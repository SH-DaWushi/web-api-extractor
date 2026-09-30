"""Redact credential material before events enter the shareable capture log."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import unquote_plus

from .bodies import parse_form_urlencoded
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


def _redact_form(payload: str) -> tuple[str, list[str], dict[str, dict]]:
    """表单编码体的脱敏，语义与 _redact_json 一致（值遮蔽 + 保留形态元数据）。

    **结构性键名一律保留**（analyzer #23 靠它们生成工具参数），只把凭据的**值**遮掉。
    只要请求体确实是表单编码，就逐字段判「是不是凭据」——
    不再有「整串原样返回」的路径，也不再要求值长度（D1/D2）。
    """
    pairs = parse_form_urlencoded(payload)
    if pairs is None:
        # 只对**确实不是**表单编码的正文（JSON/HTML/XML/纯文本/空）走到这里——
        # 它们由上层（JSON 路径）或「原样保留」语义处理。
        return payload, [], {}
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


def redact_payload(payload: str | None) -> tuple[str | None, list[str], dict[str, dict]]:
    """Returns (redacted_payload, token_paths, shape_meta). shape_meta 见 _redact_json。

    支持 JSON 与 ``application/x-www-form-urlencoded`` 两种体；
    两者都遮蔽敏感值并保留形态元数据（len/shape），供密文判定复用。
    """
    if payload is None:
        return None, [], {}
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        return _redact_form(payload)
    redacted, token_paths, shape_meta = _redact_json(parsed)
    return json.dumps(redacted, ensure_ascii=False, separators=(",", ":")), token_paths, shape_meta