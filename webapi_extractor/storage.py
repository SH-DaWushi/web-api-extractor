"""Persistent session metadata and orphan recovery."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ACTIVE_STATES = {"capturing", "paused", "stopping"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SessionStore:
    def __init__(self, sessions_dir: Path) -> None:
        self.sessions_dir = sessions_dir
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

    def session_path(self, session_id: str) -> Path:
        return self.sessions_dir / session_id

    def metadata_path(self, session_id: str) -> Path:
        return self.session_path(session_id) / "session.json"

    def write_metadata(self, session_id: str, metadata: dict[str, Any]) -> None:
        target = self.metadata_path(session_id)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix="session-", suffix=".tmp", dir=target.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(metadata, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def read_metadata(self, session_id: str) -> dict[str, Any] | None:
        path = self.metadata_path(session_id)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _captured_bytes(self, session_id: str) -> int:
        """本会话已落盘的抓包体积（字节）。"""
        path = self.session_path(session_id) / "capture.jsonl"
        try:
            return path.stat().st_size
        except OSError:
            return 0

    def recover_orphans(self) -> list[str]:
        """回收服务重启时遗留的活动会话。

        这些会话的浏览器确实已经死了（无法继续抓包），但其 capture.jsonl
        是**逐条落盘的**——数据还在、且可直接分析。因此：

          * 状态置为 stopped（不能再抓），但打上 recovered=true 与
            captured_bytes，让上层知道"这不是白干，数据可以继续分析"；
          * 完全没有数据的会话不标 recovered，避免误导。

        返回被回收的 session_id 列表。
        """
        recovered: list[str] = []
        for directory in self.sessions_dir.iterdir():
            if not directory.is_dir():
                continue
            session_id = directory.name
            metadata = self.read_metadata(session_id)
            if not metadata or metadata.get("status") not in ACTIVE_STATES:
                continue

            stats = self._captured_bytes(session_id)
            metadata["status"] = "stopped"
            metadata["stop_reason"] = "server_restarted"
            metadata["captured_bytes"] = stats
            if stats > 0:
                metadata["recovered"] = True
                metadata["recovered_hint"] = (
                    f"服务重启导致抓包中断，但已落盘 {stats / 1024:.1f} KB 数据，"
                    "可直接对该会话调用 analyze_traffic 继续分析。"
                )
            metadata.setdefault("status_history", []).append(
                {"status": "stopped", "ts": utc_now(), "reason": "server_restarted"}
            )
            self.write_metadata(session_id, metadata)
            recovered.append(session_id)
        return recovered

    def list_sessions(self) -> list[dict[str, Any]]:
        sessions: list[dict[str, Any]] = []
        for directory in sorted(self.sessions_dir.iterdir()):
            if directory.is_dir():
                metadata = self.read_metadata(directory.name)
                if metadata:
                    sessions.append(metadata)
        return sessions