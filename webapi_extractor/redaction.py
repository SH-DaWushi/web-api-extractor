"""Redact credential material before events enter the shareable capture log."""

from __future__ import annotations

import json
import re
from typing import Any


SECRET_FIELD_NAMES = {"password", "passwd", "pwd", "secret", "captcha_code"}
TOKEN_FIELD_PATTERN = re.compile(r"(?:token|access[_-]?token|refresh[_-]?token|api[_-]?key|secret)", re.I)
LOGIN_PATH_PATTERN = re.compile(r"(?:^|/)(?:login|signin|sign-in|auth|session|token|oauth)(?:/|$)", re.I)


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


def _redact_json(value: Any, path: str = "$") -> tuple[Any, list[str]]:
    paths: list[str] = []
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if str(key).lower() in SECRET_FIELD_NAMES:
                redacted[key] = "***"
            elif TOKEN_FIELD_PATTERN.search(str(key)) and isinstance(item, str) and len(item) >= 16:
                redacted[key] = "***"
                paths.append(child_path)
            else:
                redacted[key], child_paths = _redact_json(item, child_path)
                paths.extend(child_paths)
        return redacted, paths
    if isinstance(value, list):
        redacted_items = []
        for index, item in enumerate(value):
            redacted_item, child_paths = _redact_json(item, f"{path}[{index}]")
            redacted_items.append(redacted_item)
            paths.extend(child_paths)
        return redacted_items, paths
    return value, paths


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


def redact_payload(payload: str | None) -> tuple[str | None, list[str]]:
    if payload is None:
        return None, []
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        return payload, []
    redacted, token_paths = _redact_json(parsed)
    return json.dumps(redacted, ensure_ascii=False, separators=(",", ":")), token_paths