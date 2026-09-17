import json

import pytest

from webapi_extractor.audit import AuditLog
from webapi_extractor.analyzer import normalize_paths
from webapi_extractor.config import Settings
from webapi_extractor.redaction import redact_headers, redact_payload
from webapi_extractor.storage import SessionStore


def test_settings_create_private_data_layout(tmp_path):
    settings = Settings(tmp_path)
    settings.ensure_directories()

    assert settings.sessions_dir.is_dir()
    assert settings.auth_states_dir.is_dir()
    assert (settings.auth_states_dir / ".gitignore").read_text() == "*\n!.gitignore\n!README.txt\n"


def test_audit_redacts_credentials(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    log.record("http_login", {"username": "alice", "password": "plain-text"})

    event = json.loads((tmp_path / "audit.log").read_text())
    assert event["params"]["password"] == "***"
    assert "plain-text" not in (tmp_path / "audit.log").read_text()


def test_orphan_sessions_are_recovered_atomically(tmp_path):
    store = SessionStore(tmp_path / "sessions")
    store.write_metadata("orphan", {"session_id": "orphan", "status": "capturing"})

    assert store.recover_orphans() == ["orphan"]
    metadata = store.read_metadata("orphan")
    assert metadata["status"] == "stopped"
    assert metadata["stop_reason"] == "server_restarted"


@pytest.mark.asyncio
async def test_probe_without_browser_dependency_returns_safe_fallback(monkeypatch):
    from webapi_extractor import probe

    monkeypatch.setitem(__import__("sys").modules, "playwright", None)
    result = await probe.probe_login("https://example.com")
    assert result["auth_mode"] == "none"


def test_redaction_preserves_schema_without_secrets():
    payload, paths = redact_payload('{"username":"alice","password":"plain","data":{"access_token":"secret-token-value"}}')
    assert '"password":"***"' in payload
    assert '"access_token":"***"' in payload
    assert paths == ["$.data.access_token"]
    assert "plain" not in payload
    assert redact_headers({"Authorization": "Bearer real-token", "Cookie": "sid=real"}) == {
        "Authorization": "Bearer ***",
        "Cookie": "sid=***",
    }


def test_path_normalization_does_not_turn_latest_into_id():
    normalized = normalize_paths(["/api/orders/123", "/api/orders/456", "/api/orders/latest"])
    assert [(item.path, item.sample_indexes) for item in normalized] == [
        ("/api/orders/{id}", (0, 1)),
        ("/api/orders/latest", (2,)),
    ]