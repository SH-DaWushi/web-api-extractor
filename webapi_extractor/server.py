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
from .generator import generate, regenerate
from .probe import probe_login as run_probe_login
from .project import (
    diff_hosts,
    diff_registry,
    export_user_package,
    load_registry,
    merge_registry,
    session_to_registry_entries,
)
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
    crypto = detect_crypto(store.session_path(session_id), result)
    # Return a compact summary — the full result (schemas etc.) stays in analysis.json.
    host_counts: dict[str, int] = {}
    digest: list[dict[str, Any]] = []
    for endpoint in result.get("endpoints", []):
        host_counts[endpoint["host"]] = host_counts.get(endpoint["host"], 0) + 1
        digest.append({
            "endpoint_id": endpoint["endpoint_id"], "method": endpoint["method"],
            "host": endpoint["host"], "path": endpoint["path"],
            "auth_required": endpoint.get("auth_required"),
            "sample_count": endpoint.get("sample_count"),
            "description": endpoint.get("description"),
        })
    return {
        "session_id": session_id,
        "stats": result.get("stats"),
        "base_url": result.get("base_url"),
        "host_counts": host_counts,
        "auth_schemes": (result.get("auth_metadata", {}) or {}).get("auth_schemes", {}),
        "endpoints": digest,
        "crypto_found": bool(crypto.get("found")),
        "full_result_path": str(store.session_path(session_id) / "analysis.json"),
    }


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


@mcp.tool()
@audited
async def confirm_login(login_session_id: str) -> dict[str, Any]:
    """Layer-3 login confirmation: the agent asks the user out-of-band and confirms."""
    return login_manager.confirm(login_session_id)


@mcp.tool()
@audited
async def confirm_login_ready(session_id: str) -> dict[str, Any]:
    """Manually flip a capture session from authenticating to capturing (agent-side)."""
    capture = capture_sessions.get(session_id)
    if capture is None:
        return {"success": False, "error": "capture_session_not_found", "session_id": session_id}
    if capture.status != "authenticating":
        return {"success": False, "error": "not_authenticating", "status": capture.status}
    await capture._enter_capturing()
    store.write_metadata(session_id, capture.metadata())
    return {"success": True, "session_id": session_id, "status": capture.status}


# --------------------------------------------------------------------------- #
# 项目（registry）管理工具 —— 仅 IT 管理态；用户态子 MCP 不包含这些能力
# --------------------------------------------------------------------------- #
@mcp.tool()
@audited
async def diff_capture(project_dir: str, session_id: str) -> dict[str, Any]:
    """只读：对比一次新抓包与项目 registry 的差异（新增/参数变化/未见/鉴权漂移）。"""
    try:
        registry = load_registry(project_dir)
    except FileNotFoundError as exc:
        return {"success": False, "error": str(exc)}
    analysis_path = store.session_path(session_id) / "analysis.json"
    if not analysis_path.exists():
        return {"success": False, "error": "analysis_not_found",
                "message": "先对该 session 调用 analyze_traffic。"}
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    entries, hosts = session_to_registry_entries(analysis, session_id)
    report = diff_registry(registry, entries)
    report["auth_changes"] = diff_hosts(registry.get("hosts", {}), hosts)
    report["success"] = True
    report["project_dir"] = project_dir
    report["registry_version"] = registry.get("registry_version")
    return report


@mcp.tool()
@audited
async def merge_capture(
    project_dir: str,
    session_id: str,
    endpoint_keys: list[str] | None = None,
    allow_auth_change: bool = False,
) -> dict[str, Any]:
    """确认后把抓包合并进 registry（version+1）。鉴权 scheme 变化须显式 allow_auth_change=true。

    endpoint_keys 形如 ["GET|node.example.com|/pets"]；不传则合并全部。
    """
    analysis_path = store.session_path(session_id) / "analysis.json"
    if not analysis_path.exists():
        return {"success": False, "error": "analysis_not_found",
                "message": "先对该 session 调用 analyze_traffic。"}
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    entries, hosts = session_to_registry_entries(analysis, session_id)
    keys = None
    if endpoint_keys is not None:
        keys = [tuple(k.split("|", 2)) for k in endpoint_keys]
    return merge_registry(project_dir, entries, hosts, session_id, keys, allow_auth_change)


@mcp.tool()
@audited
async def regenerate_server(project_dir: str) -> dict[str, Any]:
    """从 registry 重出 server.py 等文件（旧文件自动留 .bak）。locked 项目拒绝。"""
    return regenerate(project_dir)


@mcp.tool()
@audited
async def export_project(project_dir: str, output_dir: str) -> dict[str, Any]:
    """导出用户态分发包：仅运行与诊断能力，不含任何 registry 写入/再生成代码。"""
    try:
        load_registry(project_dir)
    except FileNotFoundError as exc:
        return {"success": False, "error": str(exc)}
    return export_user_package(project_dir, output_dir)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()