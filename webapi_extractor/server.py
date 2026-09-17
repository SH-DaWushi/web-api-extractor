"""FastMCP entry point and the M1 session lifecycle surface."""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Awaitable, Callable

from fastmcp import FastMCP

from .analyzer import analyze_capture
from .audit import AuditLog
from .auth import LoginManager, http_login as perform_http_login
from .capture import CaptureSession
from .config import Settings
from .crypto_analyzer import detect_crypto
from .generator import generate
from .probe import probe_login as run_probe_login
from .storage import SessionStore, utc_now


settings = Settings.from_environment()
settings.ensure_directories()
store = SessionStore(settings.sessions_dir)
audit = AuditLog(settings.audit_path)
store.recover_orphans()
mcp = FastMCP("Web API Extractor")
login_manager = LoginManager(settings.auth_states_dir)
capture_sessions: dict[str, CaptureSession] = {}


async def _start_capture(capture: CaptureSession) -> None:
    try:
        await capture.start()
    except Exception as exc:
        capture.status = "failed"
        capture.stop_reason = "startup_failed"
        metadata = capture.metadata()
        metadata["error"] = f"{type(exc).__name__}: {exc}"
        store.write_metadata(capture.session_id, metadata)


def audited(function: Callable[..., Awaitable[dict[str, Any]]]) -> Callable[..., Awaitable[dict[str, Any]]]:
    @wraps(function)
    async def wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
        params = {**dict(zip(function.__code__.co_varnames, args)), **kwargs}
        try:
            result = await function(*args, **kwargs)
        except Exception as exc:
            result = {"success": False, "error": f"{type(exc).__name__}: {exc}"}
        audit.record(function.__name__, params, result)
        return result

    return wrapper


def new_session_id(url: str) -> str:
    host = url.split("//", 1)[-1].split("/", 1)[0].replace(":", "_") or "unknown"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{timestamp}_{host}_{secrets.token_hex(2)}"


@mcp.tool()
@audited
async def probe_login(url: str) -> dict[str, Any]:
    return await run_probe_login(url)


@mcp.tool()
@audited
async def http_login(
    url: str,
    username: str,
    password: str,
    login_endpoint: str | None = None,
) -> dict[str, Any]:
    return await perform_http_login(url, username, password, settings.auth_states_dir, login_endpoint)


@mcp.tool()
@audited
async def open_browser_login(url: str, timeout_seconds: int = 300) -> dict[str, Any]:
    return await login_manager.open(url, timeout_seconds)


@mcp.tool()
@audited
async def get_login_status(login_session_id: str) -> dict[str, Any]:
    return login_manager.status(login_session_id)


@mcp.tool()
@audited
async def start_capture(
    url: str,
    auth_state_path: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    active = [item for item in store.list_sessions() if item.get("status") in {"capturing", "paused", "stopping"}]
    if len(active) >= settings.max_sessions:
        return {"success": False, "error": "session_limit_reached", "active_sessions": active}
    session_id = session_id or new_session_id(url)
    if session_id in capture_sessions:
        return {"success": False, "error": "session_already_exists", "session_id": session_id}
    capture = CaptureSession(session_id, url, store, settings.response_body_limit, settings.idle_timeout_seconds, auth_state_path)
    capture_sessions[session_id] = capture
    initial_status = "authenticating" if auth_state_path is None else "capturing"
    metadata = {
        "session_id": session_id,
        "url": url,
        "auth_state_path": auth_state_path,
        "status": initial_status,
        "created_at": utc_now(),
        "status_history": [{"status": initial_status, "ts": utc_now()}],
        "endpoint_count": 0,
    }
    store.write_metadata(session_id, metadata)
    import asyncio
    asyncio.create_task(_start_capture(capture))
    return {
        "session_id": session_id,
        "status": initial_status,
        "message": "浏览器已打开，请先登录——登录成功后无需任何操作，直接开始正常使用网站即可，完成后再返回告诉我。" if initial_status == "authenticating" else "请正常操作网站，完成后回来告诉我或调用 stop_capture() 完成收集。",
    }


@mcp.tool()
@audited
async def get_capture_status(session_id: str) -> dict[str, Any]:
    if session_id in capture_sessions:
        return capture_sessions[session_id].metadata()
    metadata = store.read_metadata(session_id)
    if metadata is None:
        return {"success": False, "error": "session_not_found", "session_id": session_id}
    return metadata


@mcp.tool()
@audited
async def stop_capture(session_id: str) -> dict[str, Any]:
    if session_id in capture_sessions:
        return await capture_sessions[session_id].stop("agent_requested")
    metadata = store.read_metadata(session_id)
    if metadata is None:
        return {"success": False, "error": "session_not_found", "session_id": session_id}
    if metadata.get("status") in {"stopped", "failed"}:
        return metadata
    metadata["status"] = "stopped"
    metadata["stop_reason"] = "agent_requested"
    metadata.setdefault("status_history", []).append({"status": "stopped", "ts": utc_now()})
    store.write_metadata(session_id, metadata)
    return metadata


@mcp.tool()
@audited
async def resume_capture(session_id: str) -> dict[str, Any]:
    if session_id in capture_sessions:
        await capture_sessions[session_id].resume()
        return capture_sessions[session_id].metadata()
    metadata = store.read_metadata(session_id)
    if metadata is None:
        return {"success": False, "error": "session_not_found", "session_id": session_id}
    if metadata.get("status") != "paused":
        return {"success": False, "error": "session_not_paused", "status": metadata.get("status")}
    metadata["status"] = "capturing"
    metadata.setdefault("status_history", []).append({"status": "capturing", "ts": utc_now()})
    store.write_metadata(session_id, metadata)
    return metadata


@mcp.tool()
@audited
async def list_sessions() -> dict[str, Any]:
    return {"sessions": store.list_sessions()}


@mcp.tool()
@audited
async def analyze_traffic(session_id: str) -> dict[str, Any]:
    metadata = store.read_metadata(session_id)
    if metadata is None:
        return {"success": False, "error": "session_not_found", "session_id": session_id}
    result = analyze_capture(store.session_path(session_id))
    result["session_id"] = session_id
    result["crypto_findings"] = detect_crypto(store.session_path(session_id), result)
    return result


@mcp.tool()
@audited
async def update_endpoint(
    session_id: str,
    endpoint_id: str,
    description: str | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    analysis_path = store.session_path(session_id) / "analysis.json"
    if not analysis_path.exists():
        return {"success": False, "error": "analysis_not_found", "session_id": session_id}
    import json
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    for endpoint in analysis.get("endpoints", []):
        if endpoint.get("endpoint_id") == endpoint_id:
            if description is not None:
                endpoint["description"] = description
            if notes is not None:
                endpoint["notes"] = notes
            analysis_path.write_text(json.dumps(analysis, ensure_ascii=False, indent=2), encoding="utf-8")
            return endpoint
    return {"success": False, "error": "endpoint_not_found", "endpoint_id": endpoint_id}


@mcp.tool()
@audited
async def generate_mcp_server(
    session_id: str,
    output_dir: str,
    endpoint_ids: list[str] | None = None,
    language: str = "python",
    framework: str = "fastmcp",
) -> dict[str, Any]:
    if language != "python" or framework != "fastmcp":
        return {"success": False, "error": "暂未支持，仅支持 python + fastmcp"}
    try:
        return generate(store.session_path(session_id), Path(output_dir), endpoint_ids)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"success": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
@audited
async def extract_crypto_logic(session_id: str) -> dict[str, Any]:
    analysis_path = store.session_path(session_id) / "analysis.json"
    if not analysis_path.exists():
        return {"found": False, "strategy": "none", "session_id": session_id, "details": "run analyze_traffic first"}
    import json
    result = detect_crypto(store.session_path(session_id), json.loads(analysis_path.read_text(encoding="utf-8")))
    result["session_id"] = session_id
    return result


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()