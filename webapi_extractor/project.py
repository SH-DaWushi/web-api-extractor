# -*- coding: utf-8 -*-
"""Registry-driven project model for iterative sub-MCP maintenance.

A "project" is the unit the extractor generates and keeps evolving:

    <project_dir>/
    ├─ project.json      # site name, registry_version, locked flag
    ├─ registry.json     # single source of truth: hosts + endpoints + provenance
    ├─ server.py         # rendered FROM the registry; regenerate at any time
    ├─ requirements.txt / .env.example / README.md / smoke_test.py
    └─ captures/         # provenance notes (which sessions fed which versions)

Role separation:
  * IT/admin side (this extractor) may diff/merge/regenerate/export.
  * User side (the distributed sub-MCP) physically contains NO write capability:
    its server.py never imports or includes any registry-writing code.
"""
from __future__ import annotations

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------- #
# project.json / registry.json I/O
# --------------------------------------------------------------------------- #
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def project_path(project_dir: str | Path) -> Path:
    return Path(project_dir)


def load_project(project_dir: str | Path) -> dict[str, Any]:
    path = project_path(project_dir) / "project.json"
    if not path.exists():
        raise FileNotFoundError(f"not a project directory (missing project.json): {project_dir}")
    return json.loads(path.read_text(encoding="utf-8"))


def load_registry(project_dir: str | Path) -> dict[str, Any]:
    path = project_path(project_dir) / "registry.json"
    if not path.exists():
        raise FileNotFoundError(f"missing registry.json in: {project_dir}")
    return json.loads(path.read_text(encoding="utf-8"))


def save_registry(project_dir: str | Path, registry: dict[str, Any]) -> None:
    path = project_path(project_dir) / "registry.json"
    path.write_text(json.dumps(registry, ensure_ascii=False, indent=2), encoding="utf-8")


def init_project(project_dir: str | Path, site_name: str) -> dict[str, Any]:
    directory = project_path(project_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "captures").mkdir(exist_ok=True)
    project = {"site_name": site_name, "registry_version": 0, "locked": False,
               "created_at": _now(), "tool": "webapi_extractor"}
    (directory / "project.json").write_text(json.dumps(project, ensure_ascii=False, indent=2), encoding="utf-8")
    registry = {"site_name": site_name, "registry_version": 0, "updated_at": _now(),
                "hosts": {}, "endpoints": [], "auth_login": None}
    save_registry(directory, registry)
    return project


def set_auth_login(project_dir: str | Path, auth_login: dict[str, Any] | None) -> None:
    """记录账号密码登录接口定义（curate 阶段识别，生成 login/auth_status 工具用）。"""
    registry = load_registry(project_dir)
    registry["auth_login"] = auth_login
    save_registry(project_dir, registry)


# --------------------------------------------------------------------------- #
# session analysis → registry entries
# --------------------------------------------------------------------------- #
def _tool_name(endpoint: dict[str, Any], used: set[str]) -> str:
    # 上游（curate 阶段）可显式指定 tool_name；语义化命名优先于从路径机械推导。
    explicit = re.sub(r"[^0-9a-zA-Z_]+", "_", str(endpoint.get("tool_name") or "")).strip("_")
    if explicit[:1].isdigit():
        explicit = "_" + explicit
    parts = [p for p in endpoint.get("path", "").split("/") if p and not p.startswith("{")]
    resource = "_".join(re.sub(r"[^a-zA-Z0-9]+", "_", p).strip("_") for p in parts) or "endpoint"
    verb = {"GET": "get", "POST": "create", "PUT": "update", "PATCH": "update", "DELETE": "delete"}.get(
        endpoint.get("method", "GET"), "call")
    name = explicit or f"{verb}_{resource}"
    if not explicit and "{" in endpoint.get("path", ""):
        name += "_by_id"
    candidate, index = name, 2
    while candidate in used:
        candidate = f"{name}_{index}"
        index += 1
    used.add(candidate)
    return candidate


def session_to_registry_entries(analysis: dict[str, Any], session_id: str, include_noise: bool = False) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Convert an analyze_capture() result into registry endpoint entries + host auth info.

    include_noise=False（默认）跳过标记为噪音的端点；显式传 True 保留全部。

    Issue #15：默认同时跳过 `not_independently_callable` 的端点
    （OData 绑定函数依赖父请求上下文参数，独立成工具必失败）。
    传 include_noise=True 可保留（用于人工复核）。
    """
    used: set[str] = set()
    entries: list[dict[str, Any]] = []
    for endpoint in analysis.get("endpoints", []):
        if endpoint.get("noise") and not include_noise:
            continue
        if endpoint.get("not_independently_callable") and not include_noise:
            continue
        path = endpoint.get("path", "")
        path_params = [seg.strip("{}") for seg in path.split("/") if seg.startswith("{")]
        entries.append({
            "tool_name": _tool_name(endpoint, used),
            "method": endpoint.get("method", "GET"),
            "host": endpoint.get("host", ""),
            "path": path,
            "path_params": path_params,
            "query_params": endpoint.get("query_params", {}) or {},
            "sample_count": int(endpoint.get("sample_count", 1)),
            "request_schema": endpoint.get("request_schema"),
            "response_schema": endpoint.get("response_schema"),
            "auth_required": bool(endpoint.get("auth_required")),
            "description": endpoint.get("description"),
            "notes": endpoint.get("notes"),
            "noise": bool(endpoint.get("noise")),
            # Issue #15: 透传可独立生成性标记，供生成阶段注入默认分页上限
            "not_independently_callable": bool(endpoint.get("not_independently_callable")),
            "not_callable_reason": endpoint.get("not_callable_reason"),
            "pagination_suggested": endpoint.get("pagination_suggested"),
            "required_query_param": endpoint.get("required_query_param"),
            "status": "active",
            "unseen_since": None,
            "source_sessions": [session_id],
            "sample_url": endpoint.get("url"),
        })
    hosts = (analysis.get("auth_metadata", {}) or {}).get("auth_schemes", {}) or {}
    return entries, hosts


# --------------------------------------------------------------------------- #
# diff / merge
# --------------------------------------------------------------------------- #
def _match_key(entry: dict[str, Any]) -> tuple[str, str, str]:
    return (entry.get("method", ""), entry.get("host", ""), entry.get("path", ""))


def diff_registry(registry: dict[str, Any], entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare fresh capture entries against the registry. Read-only."""
    existing = {_match_key(e): e for e in registry.get("endpoints", []) if e.get("status") != "deprecated"}
    fresh = {_match_key(e): e for e in entries}
    new = [e for key, e in fresh.items() if key not in existing]
    changed: list[dict[str, Any]] = []
    for key, e in fresh.items():
        old = existing.get(key)
        if not old:
            continue
        old_qp = {k: v for k, v in (old.get("query_params") or {}).items()}
        new_qp = {k: v for k, v in (e.get("query_params") or {}).items()}
        if set(old_qp) != set(new_qp):
            changed.append({"tool_name": old["tool_name"], "change": "query_params",
                            "registry": sorted(old_qp), "capture": sorted(new_qp)})
    # Auth-scheme drift is a hard stop: never silently merge.
    auth_changes: list[dict[str, Any]] = []
    # (host scheme comparison is done by caller with hosts info)
    unseen = [{"tool_name": e["tool_name"], "method": e["method"], "host": e["host"], "path": e["path"]}
              for key, e in existing.items() if key not in fresh]
    return {"new_endpoints": new, "changed_endpoints": changed, "unseen_endpoints": unseen,
            "counts": {"new": len(new), "changed": len(changed), "unseen": len(unseen)}}


def diff_hosts(registry_hosts: dict[str, Any], capture_hosts: dict[str, Any]) -> list[dict[str, Any]]:
    changes = []
    for host, info in capture_hosts.items():
        old_scheme = (registry_hosts.get(host) or {}).get("scheme")
        if old_scheme and info.get("scheme") and old_scheme != info["scheme"]:
            changes.append({"host": host, "registry_scheme": old_scheme, "capture_scheme": info["scheme"]})
    return changes


def merge_registry(
    project_dir: str | Path,
    entries: list[dict[str, Any]],
    hosts: dict[str, Any],
    session_id: str,
    endpoint_keys: list[tuple[str, str, str]] | None = None,
    allow_auth_change: bool = False,
) -> dict[str, Any]:
    """Merge confirmed capture entries into the registry. Bumps registry_version.

    Safety rules:
      * locked project → refuse;
      * Authorization scheme drift → refuse unless allow_auth_change=True;
      * merge is additive: existing entries are never deleted, only marked
        unseen_since if absent from this capture; parameter changes update the
        entry but never remove old defaults (backward compatible).
    """
    directory = project_path(project_dir)
    project = load_project(directory)
    if project.get("locked"):
        return {"success": False, "error": "project_locked",
                "message": "project.json 标记为 locked，拒绝合并。解锁需人工修改 project.json。"}
    registry = load_registry(directory)

    # Hard stop on auth scheme drift.
    scheme_drift = diff_hosts(registry.get("hosts", {}), hosts)
    if scheme_drift and not allow_auth_change:
        return {"success": False, "error": "auth_scheme_changed", "auth_changes": scheme_drift,
                "message": "检测到鉴权 scheme 变化，需显式传 allow_auth_change=true 才能合并。"}

    existing = {_match_key(e): e for e in registry.get("endpoints", [])}
    version = int(registry.get("registry_version", 0)) + 1
    selected = set(endpoint_keys) if endpoint_keys else None

    added, updated, unseen_now = 0, 0, 0
    fresh_keys = {_match_key(e) for e in entries}
    for key, entry in existing.items():
        if key not in fresh_keys and entry.get("unseen_since") is None and entry.get("status") == "active":
            entry["unseen_since"] = version
            unseen_now += 1
    for key, entry in ((k, e) for k, e in {_match_key(e): e for e in entries}.items()):
        if selected is not None and key not in selected:
            continue
        old = existing.get(key)
        if old is None:
            old = dict(entry)
            old["source_sessions"] = [session_id]
            registry["endpoints"].append(old)
            added += 1
        else:
            # Additive update: new query params are added; old defaults preserved.
            merged_qp = dict(old.get("query_params") or {})
            for k, v in (entry.get("query_params") or {}).items():
                if k not in merged_qp:
                    merged_qp[k] = v
            old["query_params"] = merged_qp
            if entry.get("description"):
                old["description"] = entry["description"]
            if entry.get("request_schema"):
                old["request_schema"] = entry["request_schema"]
            if entry.get("response_schema"):
                old["response_schema"] = entry["response_schema"]
            old["unseen_since"] = None
            if session_id not in old.get("source_sessions", []):
                old.setdefault("source_sessions", []).append(session_id)
            updated += 1

    # Merge host auth info (additive).
    registry_hosts = registry.setdefault("hosts", {})
    for host, info in hosts.items():
        registry_hosts.setdefault(host, {}).update(info)

    registry["registry_version"] = version
    registry["updated_at"] = _now()
    project["registry_version"] = version
    (directory / "project.json").write_text(json.dumps(project, ensure_ascii=False, indent=2), encoding="utf-8")
    save_registry(directory, registry)
    # Provenance note.
    note = {"session_id": session_id, "merged_at": _now(), "version": version,
            "added": added, "updated": updated, "marked_unseen": unseen_now}
    (directory / "captures" / f"{session_id}.json").write_text(
        json.dumps(note, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"success": True, "registry_version": version, "added": added, "updated": updated,
            "marked_unseen": unseen_now, "total_endpoints": len(registry["endpoints"])}


# --------------------------------------------------------------------------- #
# export (user-mode package: physically no write capability)
# --------------------------------------------------------------------------- #
USER_PACKAGE_FILES = ["server.py", "requirements.txt", ".env.example", "README.md",
                      "smoke_test.py", "registry.json", "project.json"]


def export_user_package(project_dir: str | Path, output_dir: str | Path) -> dict[str, Any]:
    """Copy the user-facing subset of a project. The user package keeps
    registry.json/project.json only as read-only metadata (for tool_catalog);
    it contains no code able to modify them."""
    src = project_path(project_dir)
    dst = Path(output_dir)
    dst.mkdir(parents=True, exist_ok=True)
    copied = []
    for name in USER_PACKAGE_FILES:
        source = src / name
        if source.exists():
            shutil.copy2(source, dst / name)
            copied.append(name)
    return {"success": True, "output_dir": str(dst), "files": copied,
            "note": "用户态分发包：仅含运行与诊断能力，不含任何 registry 写入/再生成代码。"}
