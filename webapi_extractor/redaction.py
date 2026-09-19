"""Redact credential material before events enter the shareable capture log."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import unquote_plus

from .bodies import parse_form_urlencoded
from .crypto_analyzer import value_shape


SECRET_FIELD_NAMES = {"password", "passwd", "pwd", "secret", "captcha_code"}
TOKEN_FIELD_PATTERN = re.compile(r"(?:token|access[_-]?token|refresh[_-]?token|api[_-]?key|secret)", re.I)
LOGIN_PATH_PATTERN = re.compile(r"(?:^|/)(?:login|signin|sign-in|auth|session|token|oauth)(?:/|$)", re.I)

# 复合命名的凭据字段：user_password / login_password / oldPwd / secretKey ……
# 只做精确匹配会全部漏掉，而它们与 password 同等敏感。
_SECRET_MARKERS = ("password", "passwd", "pwd", "secret", "passcode")


def _is_secret_field(name: Any) -> bool:
    low = str(name).lower()
    return low in SECRET_FIELD_NAMES or any(marker in low for marker in _SECRET_MARKERS)


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
                redacted[key] = "***"
                if isinstance(item, str):
                    shape_meta[child_path] = {"len": len(item), "shape": value_shape(item)}
            elif TOKEN_FIELD_PATTERN.search(str(key)) and isinstance(item, str) and len(item) >= 16:
                redacted[key] = "***"
                paths.append(child_path)
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
            scheme = value.split(" ", 1)[0] if value else "Bearer"
            result[name] = f"{scheme} ***"
        elif lowered in {"cookie", "set-cookie"}:
            names = [part.split("=", 1)[0].strip() for part in value.split(";") if part.strip()]
            result[name] = "; ".join(f"{cookie}=***" for cookie in names)
        else:
            result[name] = value
    return result


def _redact_form(payload: str) -> tuple[str, list[str], dict[str, dict]]:
    """表单编码体的脱敏，语义与 _redact_json 一致（值遮蔽 + 保留形态元数据）。

    修复前这里直接原样返回，导致**表单提交的明文密码被完整写进 capture.jsonl**
    （见 issue #22）。
    """
    pairs = parse_form_urlencoded(payload)
    if pairs is None:
        return payload, [], {}
    out: list[str] = []
    token_paths: list[str] = []
    shape_meta: dict[str, dict] = {}
    for name, raw_value in pairs:
        field = unquote_plus(name)
        value = unquote_plus(raw_value)
        secret = _is_secret_field(field)
        token = bool(TOKEN_FIELD_PATTERN.search(field)) and len(value) >= 16
        if value and (secret or token):
            path = f"$.{field}"
            shape_meta[path] = {"len": len(value), "shape": value_shape(value)}
            if token:
                token_paths.append(path)
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