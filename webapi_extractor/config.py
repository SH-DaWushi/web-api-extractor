"""Runtime configuration for the extractor."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_root: Path
    response_body_limit: int = 256 * 1024
    idle_timeout_seconds: int = 5 * 60
    max_sessions: int = 3

    @classmethod
    def from_environment(cls) -> "Settings":
        root = Path(os.environ.get("WEB_API_EXTRACTOR_DATA", "~/.webapiextractor")).expanduser()
        response_limit = int(os.environ.get("WEB_API_EXTRACTOR_RESPONSE_LIMIT", 256 * 1024))
        idle_timeout = int(os.environ.get("WEB_API_EXTRACTOR_IDLE_TIMEOUT", 5 * 60))
        max_sessions = int(os.environ.get("WEB_API_EXTRACTOR_MAX_SESSIONS", 3))
        if response_limit <= 0 or idle_timeout <= 0 or max_sessions <= 0:
            raise ValueError("Extractor limits must be positive")
        return cls(root, response_limit, idle_timeout, max_sessions)

    @property
    def sessions_dir(self) -> Path:
        return self.data_root / "sessions"

    @property
    def auth_states_dir(self) -> Path:
        return self.data_root / "auth_states"

    @property
    def audit_path(self) -> Path:
        return self.data_root / "audit.log"

    def ensure_directories(self) -> None:
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.auth_states_dir.mkdir(parents=True, exist_ok=True)
        readme = self.auth_states_dir / "README.txt"
        if not readme.exists():
            readme.write_text(
                "This directory contains credentials. Do not commit, sync, or screenshot it.\n",
                encoding="utf-8",
            )
        gitignore = self.auth_states_dir / ".gitignore"
        if not gitignore.exists():
            gitignore.write_text("*\n!.gitignore\n!README.txt\n", encoding="utf-8")