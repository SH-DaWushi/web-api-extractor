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

    def recover_orphans(self) -> list[str]:
        recovered: list[str] = []
        for directory in self.sessions_dir.iterdir():
            if not directory.is_dir():
                continue
            session_id = directory.name
            metadata = self.read_metadata(session_id)
            if not metadata or metadata.get("status") not in ACTIVE_STATES:
                continue
            metadata["status"] = "stopped"
            metadata["stop_reason"] = "server_restarted"
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