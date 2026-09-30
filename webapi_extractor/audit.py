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
        # 最近一次写失败的原因（None = 最近一次成功）。给诊断用，不参与返回。
        self.last_error: str | None = None

    def record(self, tool: str, params: dict[str, Any], result: Any = None) -> None:
        """追加一条审计事件。**审计失败绝不能掩盖工具本身的成败。**

        调用方（`server.py` 的 `@audited`）是在工具**已经成功返回之后**才调这里；
        以前写失败（`audit.log` 不可写、磁盘满、`json.dumps` 撞上不可序列化的
        返回值……）会直接把异常抛回装饰器，把一次成功的操作变成
        `{"success": false, "error": "PermissionError: ..."}` —— 真实结果整条丢失。

        现在：失败不抛，改为（1）记进 `last_error`，（2）**就地**写进调用方传进来的
        结果字典 —— 装饰器返回的是同一个 dict，所以「结果没丢」且「失败可见」。
        成功路径不添加任何键，返回结构保持原样。
        """
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            event = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "tool": tool,
                "params": redact(params),
                "result_summary": redact(result) if result is not None else None,
            }
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception as exc:                      # noqa: BLE001 — 见 docstring
            self.last_error = f"{type(exc).__name__}: {exc}"
            self._report(result, self.last_error)

    @staticmethod
    def _report(result: Any, error: str) -> None:
        """把审计失败挂到结果上；结果不是 dict（或为 None）时无处可挂，只能沉默。"""
        if not isinstance(result, dict):
            return
        result.setdefault("audit_log", "not_written")
        result.setdefault("audit_log_error", error)