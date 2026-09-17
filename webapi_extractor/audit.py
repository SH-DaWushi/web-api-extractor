"""Append-only audit logging with conservative parameter redaction."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SENSITIVE_NAMES = {"password", "passwd", "pwd", "secret", "token", "authorization", "cookie"}


def redact(value: Any, key: str | None = None) -> Any:
    if key and key.lower() in SENSITIVE_NAMES:
        return "***"
    if isinstance(value, dict):
        return {name: redact(item, name) for name, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path

    def record(self, tool: str, params: dict[str, Any], result: Any = None) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "params": redact(params),
            "result_summary": redact(result) if result is not None else None,
        }
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False) + "\n")