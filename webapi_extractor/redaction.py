"""Redact credential material before events enter the shareable capture log."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import unquote_plus

from .bodies import parse_form_urlencoded, split_multipart, split_multipart_part
from .crypto_analyzer import value_shape


# 全部小写——匹配前会先 lower()。含简短/易误伤的同义词（pass/pin/otp）：
# 这些只做**精确匹配**，避免 substring 误伤（compass / shipping …）。
SECRET_FIELD_NAMES = {
    "password", "passwd", "pwd", "pass", "secret", "passcode", "pin", "otp",
    "captcha", "captcha_code", "captchacode", "pincode",
    "token", "access_token", "accesstoken", "refresh_token", "refreshtoken",
    "auth_token", "authtoken", "id_token", "idtoken",
    "api_key", "apikey", "client_secret", "clientsecret",
    "sms_code", "smscode", "verification_code", "verificationcode",
    "auth_code", "authcode",
}
TOKEN_FIELD_PATTERN = re.compile(r"(?:token|access[_-]?token|refresh[_-]?token|api[_-]?key|secret)", re.I)
LOGIN_PATH_PATTERN = re.compile(r"(?:^|/)(?:login|signin|sign-in|auth|session|token|oauth)(?:/|$)", re.I)

# 复合命名的凭据字段：login_password / oldPwd / secretKey / user_passwd / smsCode ……
# 只做精确匹配会全部漏掉，而它们与 password 同等敏感。
# ⚠️ 这里必须覆盖 TOKEN_FIELD_PATTERN 能命中的名字（token/secret/api_key）——
# 否则 `_is_secret_field` 会比旧的 token 分支更窄，长 token 反而漏遮（fail-open）。
# 短的 pass/pin/otp 只进精确集合，不进这里。
_SECRET_MARKERS = (
    "password", "passwd", "pwd", "secret", "passcode", "pincode",
    "token", "apikey", "api_key", "api-key",
    "client_secret", "clientsecret",
    "verification_code", "verificationcode", "sms_code", "smscode",
    "auth_code", "authcode", "captcha",
)


def _is_secret_field(name: Any) -> bool:
    """字段名是否像凭据。**只看名字**，与值长短无关（D2：短口令同样是凭据）。"""
    low = str(name).lower()
    if low in SECRET_FIELD_NAMES:
        return True
    return any(marker in low for marker in _SECRET_MARKERS)


# 「凭据名」的宽松形态，用于**结构化解析失败**的正文（XML / JS 对象字面量 /
# 宽松 JSON / multipart 字段里再嵌一层 JSON……）。
# 这类正文没有可信的字段边界，所以这里按**子串**匹配，比 _is_secret_field 更宽：
# 解析不了的时候，多判一个字段像凭据只是少写一条体，漏判一个就是明文密码落盘。
_SECRET_NAME_RE = (
    r"(?:[A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|passcode|token"
    r"|api[_-]?key|sms[_-]?code|verification[_-]?code|auth[_-]?code|captcha)"
    r"[A-Za-z0-9_.\-]*"
    r"|(?<![A-Za-z0-9_])(?:pin|otp|pass)(?![A-Za-z0-9_]))"
)
_SECRET_NAME_SEARCH_RE = re.compile(_SECRET_NAME_RE, re.I)
# 已遮蔽的形态：名字与 *** 之间只有分隔语法（引号 / 冒号 / 等号 / 空白 / 换行）。
_MASKED_SECRET_RE = re.compile(r"(?:" + _SECRET_NAME_RE + r")[^A-Za-z0-9]{0,24}?\*{3}", re.I)


def mentions_unmasked_secret(text: str) -> bool:
    """正文里是否还留着**没被遮蔽**的凭据名（写盘前的最后一道闸）。

    做法：先把「凭据名 … ***」这种已遮蔽的形态整段摘掉，再看剩下的是否还提到
    凭据名。这样就不必理解正文语法——XML、JS 字面量、multipart 里嵌的 JSON、
    甚至我们没见过的编码，都落进同一套判定。

    误伤是**有意的**：正文里只要还剩一个没遮住的凭据名（哪怕只是散文里的一句
    "reset your password"），就整条体都不写盘。少一条请求体只影响参数推断，
    写下去一条明文口令是不可逆的。
    """
    return bool(_SECRET_NAME_SEARCH_RE.search(_MASKED_SECRET_RE.sub(" ", text)))


# 请求头里的凭据：X-Auth-Token / X-Api-Key / X-Access-Token / Api-Key / X-Client-Secret …
# 与 Authorization/Cookie 一样，值必须整段遮蔽（D4：此前它们原样进 capture）。
_SENSITIVE_HEADER_PATTERN = re.compile(r"token|api[-_]?key|secret", re.I)


def _is_sensitive_header(lowered_name: str) -> bool:
    return bool(_SENSITIVE_HEADER_PATTERN.search(lowered_name))


def is_auth_candidate(url: str, post_data: str | None = None) -> bool:
    if LOGIN_PATH_PATTERN.search(url):
        return True
    if not post_data:
        return False
    try:
        value = json.loads(post_data)
    except (TypeError, json.JSONDecodeError):
        return any(name in post_data.lower() for name in SECRET_FIELD_NAMES)
    return isinstance(value, dict) and any(str(key).lower() in SECRET_FIELD_NAMES for key in value)


def _redact_json(value: Any, path: str = "$") -> tuple[Any, list[str], dict[str, dict]]:
    """Redact secrets while preserving SHAPE METADATA (B-3).

    Returns (redacted_value, token_paths, shape_meta). The value is still fully
    masked ("***"), but shape_meta records ``{"len": N, "shape": "base64|hex|plain"}``
    per redacted path — downstream crypto detection can tell a 344-char base64
    RSA ciphertext from a short plaintext password without seeing either.
    """
    paths: list[str] = []
    shape_meta: dict[str, dict] = {}
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if _is_secret_field(key):
                # 名字像凭据即遮蔽，**不再要求 len >= 16**（D2：短口令/短 token 同样是凭据）。
                # 值长度只影响形态元数据，不参与「是否遮蔽」的判定。
                redacted[key] = "***"
                if TOKEN_FIELD_PATTERN.search(str(key)):
                    paths.append(child_path)
                if isinstance(item, str):
                    shape_meta[child_path] = {"len": len(item), "shape": value_shape(item)}
            else:
                redacted[key], child_paths, child_meta = _redact_json(item, child_path)
                paths.extend(child_paths)
                shape_meta.update(child_meta)
        return redacted, paths, shape_meta
    if isinstance(value, list):
        redacted_items = []
        for index, item in enumerate(value):
            redacted_item, child_paths, child_meta = _redact_json(item, f"{path}[{index}]")
            redacted_items.append(redacted_item)
            paths.extend(child_paths)
            shape_meta.update(child_meta)
        return redacted_items, paths, shape_meta
    return value, paths, shape_meta


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in headers.items():
        lowered = name.lower()
        if lowered == "authorization":
            # 带 scheme（``Bearer <tok>`` / ``Basic <tok>``）时保留 scheme，
            # 值全遮——analyzer 靠 scheme 生成正确的鉴权代码，scheme 本身不是凭据。
            # 无空格时整串就是**裸 token**（D3：此前它被当成 scheme 原样保留），全遮。
            if not value:
                result[name] = "Bearer ***"
            elif " " in value.strip():
                result[name] = f"{value.strip().split(' ', 1)[0]} ***"
            else:
                result[name] = "***"
        elif lowered in {"cookie", "set-cookie"}:
            names = [part.split("=", 1)[0].strip() for part in value.split(";") if part.strip()]
            result[name] = "; ".join(f"{cookie}=***" for cookie in names)
        elif _is_sensitive_header(lowered):
            result[name] = "***"          # D4：X-Auth-Token / X-Api-Key 等此前完全未脱敏
        else:
            result[name] = value
    return result


def _redact_form(payload: str) -> tuple[str, list[str], dict[str, dict]] | None:
    """表单编码体的脱敏，语义与 _redact_json 一致（值遮蔽 + 保留形态元数据）。

    **结构性键名一律保留**（analyzer #23 靠它们生成工具参数），只把凭据的**值**遮掉。
    只要请求体确实是表单编码，就逐字段判「是不是凭据」——
    不再有「整串原样返回」的路径，也不再要求值长度（D1/D2）。

    不是表单编码时返回 ``None``（**不再**原样交出正文）：由 :func:`redact_payload`
    继续尝试 multipart，最后交给「写盘前终检」裁决。
    """
    pairs = parse_form_urlencoded(payload)
    if pairs is None:
        return None
    out: list[str] = []
    token_paths: list[str] = []
    shape_meta: dict[str, dict] = {}
    for name, raw_value in pairs:
        field = unquote_plus(name)
        value = unquote_plus(raw_value)
        if _is_secret_field(field):
            # 名字像凭据 → 值必遮（含无值控制项/空值：键名要保留，值不能留）。
            path = f"$.{field}"
            if TOKEN_FIELD_PATTERN.search(field):
                token_paths.append(path)
            if value:
                shape_meta[path] = {"len": len(value), "shape": value_shape(value)}
            out.append(f"{name}=***")
        else:
            out.append(f"{name}={raw_value}")
    return "&".join(out), token_paths, shape_meta


def _redact_multipart(payload: str) -> tuple[str, list[str], dict[str, dict]] | None:
    """multipart/form-data 的脱敏：按字段名就地替换值，其余字节**原样**拼回。

    只把「字段名像凭据」的那一段的值换成 ``***``；边界、头部、段顺序、
    未命名段（前导 / 结束分隔符）全都不动，所以保真度与原文一致，
    analyzer 照样能看出表单结构。

    不是 multipart 返回 ``None``。段结构看不懂却**名字像凭据**时整条返回 ``None``：
    宁可让调用方丢弃整条体，也不赌那一段里没有密码。
    """
    split = split_multipart(payload)
    if split is None:
        return None
    boundary, parts = split
    out: list[str] = []
    token_paths: list[str] = []
    shape_meta: dict[str, dict] = {}
    for name, chunk in parts:
        if name is None or not _is_secret_field(name):
            out.append(chunk)
            continue
        part = split_multipart_part(chunk)
        if part is None:
            return None                     # 名字像凭据却拆不开 → 交给终检丢弃整条体
        head, value = part
        core, newline = _split_trailing_newline(value)
        path = f"$.{name}"
        if TOKEN_FIELD_PATTERN.search(name):
            token_paths.append(path)
        if core:
            shape_meta[path] = {"len": len(core), "shape": value_shape(core)}
        out.append(f"{head}***{newline}")   # 值后的换行属于分隔语法，留在原位
    return boundary.join(out), token_paths, shape_meta


def _split_trailing_newline(value: str) -> tuple[str, str]:
    """把值末尾的 ``\\r\\n`` / ``\\n`` 摘出来——它属于边界语法，不属于值。"""
    for newline in ("\r\n", "\n"):
        if value.endswith(newline):
            return value[: -len(newline)], newline
    return value, ""


def redact_payload(payload: str | None) -> tuple[str | None, list[str], dict[str, dict]]:
    """Returns (redacted_payload, token_paths, shape_meta). shape_meta 见 _redact_json。

    依次尝试 JSON、multipart、``application/x-www-form-urlencoded`` 三种体，
    命中哪种就按哪种脱敏（值遮蔽 + 保留形态元数据，供密文判定复用）。

    **三种都不命中时不再原样放行**：先留着交给 :func:`mentions_unmasked_secret`
    终检——正文里只要还提到凭据名就返回 ``None``（调用方据此不写体、只记大小），
    否则才原样保留。修复前这里有一条 fail-open 路径：任何「看着像 JSON 但不是
    严格 JSON」或「不是表单编码」的正文都原样返回，于是
    ``{'username':'bob','password':'hunter2'}``、multipart、XML 登录体里的
    明文口令被完整写进 capture.jsonl（用户实测复现）。
    """
    if payload is None:
        return None, [], {}
    if not isinstance(payload, str):
        # 非文本体（CDP 不会这样给）：无从脱敏，也不该按原文判定，原样交回。
        return payload, [], {}
    result = _redact_json_body(payload)
    if result is None:
        result = _redact_multipart(payload)
    if result is None:
        result = _redact_form(payload)
    if result is None:
        result = (payload, [], {})           # 认不出来：先原样，交给下面的终检
    redacted, token_paths, shape_meta = result
    if mentions_unmasked_secret(redacted):
        return None, [], {}                  # 终检不过 → 整条体不落盘
    return redacted, token_paths, shape_meta


def _redact_json_body(payload: str) -> tuple[str, list[str], dict[str, dict]] | None:
    """严格 JSON 体的脱敏；不是 JSON 返回 ``None``。

    比旧实现宽容两点，都是**为了多遮一点**：
    * 容忍开头的 BOM（``\\ufeff``）——带 BOM 的体此前直接掉进 fail-open 路径；
    * ``strict=False``——字符串里的裸换行/制表符此前会让解析失败，同样掉进那条路径。
    """
    try:
        parsed = json.loads(payload.lstrip("\ufeff"), strict=False)
    except (TypeError, ValueError):
        return None
    redacted, token_paths, shape_meta = _redact_json(parsed)
    return json.dumps(redacted, ensure_ascii=False, separators=(",", ":")), token_paths, shape_meta