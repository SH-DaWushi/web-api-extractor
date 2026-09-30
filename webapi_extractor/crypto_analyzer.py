"""Conservative detection of encrypted login payloads and JS crypto hints."""

from __future__ import annotations

import base64
import binascii
import json
import re
from pathlib import Path
from typing import Any

from .bodies import body_fields


CRYPTO_HINTS = re.compile(r"CryptoJS|JSEncrypt|sm2|sm4|encrypt|RSA|AES", re.I)
# B-2: URL 查询参数里的加密信号——不是密文，但明确指出「密码需加密传输」。
ENCRYPTION_QUERY_KEYS = ("encrypt", "sign", "signature", "enc_type", "encrypt_type")
# JS 源码里的 PEM 公钥（换行可能是真实换行或字面 \n 转义）。
PEM_RE = re.compile(
    r"-----BEGIN PUBLIC KEY-----(?:\\n|\s)*(?P<body>[A-Za-z0-9+/=\\n\s]+?)(?:\\n|\s)*-----END PUBLIC KEY-----")

# D3: 密文/形态判定的下限与字符集。RSA-2048 密文 base64 后约 344 字符，
# MD5/SHA 之类的十六进制摘要 >= 32 字符，均落在此下限之上。
_MIN_CIPHERTEXT_LEN = 32
_HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")
_B64_ALPHABET = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")


def _is_low_entropy(value: str) -> bool:
    """退化输入：字符种类极少，或整串是极短周期的重复。

    用于剔除 ``"a" * 130``、``"ABAB…"`` 这类「长度像密文、内容毫无信息」的串，
    它们此前会被误判成密文。
    """
    if len(set(value)) <= 2:
        return True
    for period in (1, 2, 3, 4):
        if len(value) % period == 0 and value == value[:period] * (len(value) // period):
            return True
    return False


def _is_hex_shape(value: str) -> bool:
    """严格十六进制：全 ``[0-9a-fA-F]``、偶长度、且不短于下限。"""
    return (
        len(value) >= _MIN_CIPHERTEXT_LEN
        and len(value) % 2 == 0
        and _HEX_ONLY.fullmatch(value) is not None
    )


def _decode_base64(value: str) -> bytes | None:
    """仅在「确实像 base64」时才解码，否则返回 None。

    要求：长度达标、字符集合规、可解码（容忍缺失填充与 URL-safe 字母表）、
    解出的字节数 >= 16。
    """
    if len(value) < _MIN_CIPHERTEXT_LEN or _B64_ALPHABET.fullmatch(value) is None:
        return None
    padded = value + "=" * (-len(value) % 4)
    normalized = padded.replace("-", "+").replace("_", "/")
    try:
        decoded = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError):
        return None
    return decoded if len(decoded) >= 16 else None


def _is_base64_ciphertext(value: str, decoded: bytes) -> bool:
    """判别一段「能解码的 base64」是否真像密文，而非退化串/普通单词。"""
    if _is_low_entropy(value) or _is_low_entropy(decoded.decode("latin-1")):
        return False
    # 去掉填充后全是小写字母 → 更像英文单词/标识符；随机密文的 base64 几乎
    # 必然含大写字母、数字或 +//。
    if value.rstrip("=").islower():
        return False
    return True


def _looks_ciphertext(value: str) -> bool:
    if value is None or len(value) < _MIN_CIPHERTEXT_LEN:
        return False
    if _is_low_entropy(value):
        return False
    if _is_hex_shape(value):
        return True
    decoded = _decode_base64(value)
    return decoded is not None and _is_base64_ciphertext(value, decoded)


def value_shape(value: str) -> str:
    """B-3 配套：值的形态分类，供脱敏边车与密文判定共用。

    顺序（D3 修复）：先判**严格**十六进制，再判「像密文的 base64」，否则 plain。
    修复前先判 base64 字符集，导致 ``"password123"`` 这类纯 ASCII 也被报成
    base64、hex 分支几乎不可达；现在只有真正像密文的值才返回 base64/hex。
    """
    if _is_hex_shape(value):
        return "hex"
    decoded = _decode_base64(value)
    if decoded is not None and _is_base64_ciphertext(value, decoded):
        return "base64"
    return "plain"


def normalize_pem(raw: str) -> str:
    """把 JS 源码里的 PEM 还原成标准格式（源码换行可能是真实换行或字面 \\n）。"""
    body = raw.replace("\\n", "").replace("\r", "").replace("\n", "").strip()
    body = re.sub(r"[^A-Za-z0-9+/=]", "", body)
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----"


def find_public_key(session_dir: Path | None) -> str | None:
    """在抓包的前端脚本里搜索 PEM 公钥块。"""
    scripts_dir = Path(session_dir) / "scripts" if session_dir else None
    if not scripts_dir or not scripts_dir.is_dir():
        return None
    for js in sorted(scripts_dir.glob("*")):
        try:
            text = js.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = PEM_RE.search(text)
        if m:
            return normalize_pem(m.group("body"))
    return None


def detect_password_encryption(session_dir: Path | None, login: dict[str, Any]) -> dict[str, Any] | None:
    """B-2：判断登录接口是否有前端加密。

    判据（按可靠性）：登录接口带 `encrypt` 类查询参数（版本号）→
    从前端 JS 提取 PEM 公钥（当前识别 RSA-OAEP/SHA-256 策略）。
    """
    query = login.get("query_params") or {}
    version = query.get("encrypt")
    # auth_login 的 query_params 与 endpoint 条目同形（`{名: [值…]}`），而老 registry
    # 里是标量；两种都要认（这里不 import analyzer——它反过来 import 本模块）。
    if isinstance(version, (list, tuple)):
        version = version[0] if version else None
    if not version:
        return None
    public_key = find_public_key(session_dir)
    return {"scheme": "rsa-oaep-sha256", "version": str(version), "public_key": public_key}


def _load_capture_requests(capture_path: Path) -> dict[str, list[dict[str, Any]]]:
    """一次读入 capture.jsonl，按 ``requestId`` 索引 ``type == "request"`` 的事件。

    S3：原实现把「读整个文件 + 逐行 json.loads」放在**遍历 auth 候选的内层循环**
    里，于是文件被读的次数据等于候选数 N。redaction 会把 ``/api/auth/*``、
    ``/api/session/*`` 这类宽泛 URL 也算作候选（``is_auth_candidate``），
    因此一个 5,000 请求 / 5 MB 的抓包会被读约 5,000 次（~25 GB I/O），表现为
    ``analyze_traffic`` 疑似卡死。现在只读一次，匹配语义不变：
    仍是 ``requestId == 候选的 request_id`` 且 ``type == "request"``，
    同名事件保持**文件内顺序**（与旧的逐行扫描一致）。
    """
    index: dict[str, list[dict[str, Any]]] = {}
    try:
        text = capture_path.read_text(encoding="utf-8")
    except OSError:
        return index
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or event.get("type") != "request":
            continue
        request_id = event.get("requestId")
        try:
            index.setdefault(request_id, []).append(event)
        except TypeError:
            # requestId 缺省为 None 也能当键；不可哈希的畸形值时跳过。
            continue
    return index


def detect_crypto(session_dir: Path, analysis: dict[str, Any]) -> dict[str, Any]:
    findings = []
    # S3：capture.jsonl 只读一次并建索引，所有候选复用同一份（不再是 O(N) 次读盘）。
    capture_requests = _load_capture_requests(Path(session_dir) / "capture.jsonl")
    for candidate in analysis.get("auth_metadata", {}).get("auth_candidates", []):
        request_id = candidate.get("request_id")
        try:
            events = capture_requests.get(request_id, [])
        except TypeError:      # 候选里的 request_id 不可哈希（畸形输入）
            continue
        for event in events:
            body = event.get("postData")
            # B-3 边车：优先用脱敏时保留的形态元数据（len/shape）判定密文。
            shape_meta = event.get("redaction_meta") or {}
            for path, meta in shape_meta.items():
                if isinstance(meta, dict) and meta.get("shape") in ("base64", "hex") and meta.get("len", 0) >= 128:
                    findings.append({"endpoint": event.get("url"), "redacted_field": path,
                                     "shape": meta.get("shape"), "len": meta.get("len"), "ciphertext": True})
            # Issue #21: 逐字段判形态，JSON 与表单编码都覆盖（此前表单编码整体漏检）。
            fields = body_fields(body)
            encrypted_fields = [name for name, value in fields.items() if _looks_ciphertext(value)]
            if encrypted_fields:
                findings.append({"endpoint": event.get("url"), "encrypted_fields": encrypted_fields,
                                 "content_type": "form" if "=" in (body or "") and not (body or "").lstrip().startswith("{") else "json",
                                 "ciphertext": True})
    # B-2：URL 查询参数加密信号（如 encrypt=2）。
    query_signal = []
    for ep in analysis.get("endpoints", []):
        for key in (ep.get("query_params") or {}):
            if key.lower() in ENCRYPTION_QUERY_KEYS:
                query_signal.append({"endpoint": f"{ep['method']} {ep['host']}{ep['path']}", "param": key})
                break
    scripts = list((session_dir / "scripts").glob("*.js")) if (session_dir / "scripts").exists() else []
    hints = [str(path.relative_to(session_dir)) for path in scripts if CRYPTO_HINTS.search(path.read_text(encoding="utf-8", errors="ignore"))]
    found = bool(findings or query_signal)
    return {"found": found,
            "strategy": "L1_native" if (findings or query_signal) and hints else "L0_manual" if found else "none",
            "crypto_findings": findings, "query_encryption_signals": query_signal,
            "script_hints": hints, "scripts_unavailable": bool(found and not scripts)}