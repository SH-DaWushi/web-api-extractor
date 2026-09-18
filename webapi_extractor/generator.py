# -*- coding: utf-8 -*-
"""Render a registry-driven, multi-host, typed-parameter FastMCP sub-server.

Design goals (vs. the legacy single-base_url generator):
  * multi-host routing — each endpoint keeps its own host;
  * typed function signatures inferred from captured query/path parameter samples;
  * auth emitted per the *observed* scheme (Basic / Bearer / cookie), not hardcoded;
  * mutating tools require an explicit ``confirm=True`` and are audited;
  * user-mode diagnostics only (tool_catalog / error_log_tail) — the generated
    server contains NO registry-write or regeneration capability.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .project import init_project, load_registry, merge_registry, session_to_registry_entries


def _env_prefix(site_name: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", site_name.upper()).strip("_") or "SITE"


def _host_key(host: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", host.upper()).strip("_")


def _py_ident(name: str) -> str:
    ident = re.sub(r"[^0-9a-zA-Z_]+", "_", str(name)).strip("_") or "param"
    if ident[0].isdigit():
        ident = f"p_{ident}"
    return ident


def _infer_type(values: list) -> str:
    vals = [str(v) for v in values]
    if vals and all(re.fullmatch(r"-?\d+", v) for v in vals):
        return "int"
    return "str"


# --------------------------------------------------------------------------- #
# auth block (plain code text; literals injected via json.dumps)
# --------------------------------------------------------------------------- #
def _render_auth_block(prefix: str, hosts: dict) -> str:
    hosts_literal = json.dumps({h: f"https://{h}" for h in hosts}, indent=4, ensure_ascii=False)
    # repr() — NOT json.dumps — so None/null renders as a valid Python literal.
    scheme_literal = repr({h: (i or {}).get("scheme") for h, i in hosts.items()})
    cookie_literal = repr({h: ((i or {}).get("cookie_names") or [None])[0] for h, i in hosts.items()})
    return (
        "\nHOSTS = " + hosts_literal +
        "\nAUTH_SCHEME = " + scheme_literal +
        "\nCOOKIE_NAME = " + cookie_literal + """

def _HK(host: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", host.upper()).strip("_")


def _auth_headers(host: str) -> dict:
    \"\"\"Auth per the scheme actually observed during capture (not hardcoded).\"\"\"
    scheme = AUTH_SCHEME.get(host)
    if scheme == "Basic":
        # Basic base64(token:password). The password part is a per-site constant
        # that usually lives in the frontend JS (search captured scripts for
        # `btoa(` or `auth:{`) — fill it in .env as __PREFIX___BASIC_PASSWORD_<HOST>.
        password = os.environ.get("__PREFIX___BASIC_PASSWORD_" + _HK(host), "")
        raw = (TOKEN + ":" + password).encode("utf-8")
        return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}
    if scheme == "Bearer":
        return {"Authorization": "Bearer " + TOKEN} if TOKEN else {}
    cookie = COOKIE_NAME.get(host)
    if cookie and TOKEN:
        return {"Cookie": cookie + "=" + TOKEN}
    return {}
""".replace("__PREFIX__", prefix))


# --------------------------------------------------------------------------- #
# per-tool rendering
# --------------------------------------------------------------------------- #
def _render_tool(entry: dict, prefix: str) -> str:
    method = entry.get("method", "GET")
    host = entry["host"]
    path = entry["path"]
    mutating = method not in ("GET", "HEAD")
    marker = "[MUTATING] " if mutating else ""
    desc = (entry.get("description") or f"{method} {path}").replace('"', "'")

    # ---- signature -------------------------------------------------------- #
    params: list = []
    seen: set = set()
    for p in entry.get("path_params") or []:
        ident = _py_ident(p)
        if ident not in seen:
            params.append(f"{ident}: str")
            seen.add(ident)
    sample_count = max(int(entry.get("sample_count", 1)), 1)
    for key, values in (entry.get("query_params") or {}).items():
        ident = _py_ident(key)
        if ident in seen:
            continue
        seen.add(ident)
        py_type = _infer_type(values)
        always_present = len(values) >= sample_count
        if always_present and values:
            default = str(values[0]) if py_type == "int" else repr(str(values[0]))
            params.append(f"{ident}: {py_type} = {default}")
        else:
            params.append(f"{ident}: {py_type} | None = None")
    has_body = bool(entry.get("request_schema")) and mutating
    if has_body:
        params.append("payload: dict | None = None")
    if mutating:
        params.append("confirm: bool = False")
    signature = ", ".join(params) if params else "payload: dict | None = None"

    # ---- call ------------------------------------------------------------- #
    if "{" in path:
        call_path = 'f"' + path + '"'
    else:
        call_path = '"' + path + '"'
    call_args = [f'"{host}"', f'"{method}"', call_path]
    query_items = [f'"{_py_ident(k)}": {_py_ident(k)}' for k in (entry.get("query_params") or {})]
    if query_items:
        call_args.append("params={" + ", ".join(query_items) + "}")
    if has_body:
        call_args.append("json_body=payload or {}")
    call = "await _request(" + ", ".join(call_args) + ")"

    # ---- body ------------------------------------------------------------- #
    body_lines = []
    if mutating:
        body_lines.append("    if not confirm:")
        body_lines.append('        return {"need_confirm": True, "message": '
                          f'"写操作：再次调用并传 confirm=true 才会执行 {method} {path}。"}}')
        body_lines.append(f'    _audit({entry["tool_name"]!r}, {{"host": {host!r}, "path": {path!r}}})')
    body_lines.append("    return " + call)

    return (f'@mcp.tool()\n'
            f'async def {entry["tool_name"]}({signature}) -> Any:\n'
            f'    """{marker}{desc}"""\n' + "\n".join(body_lines) + "\n")


# --------------------------------------------------------------------------- #
# server template (placeholders via .replace, no str.format brace escaping)
# --------------------------------------------------------------------------- #
_SERVER_TEMPLATE = '''# -*- coding: utf-8 -*-
"""__SITE__ MCP Server — generated by web-api-extractor from registry v__VERSION__.

User-mode package: business tools + read-only diagnostics only.
This server contains NO capability to modify or regenerate itself.
"""
from __future__ import annotations

import base64
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import httpx
from fastmcp import FastMCP

_HERE = Path(__file__).resolve().parent


def _load_dotenv() -> None:
    env_file = _HERE / ".env"
    if not env_file.exists():
        return
    try:
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())
    except OSError:
        pass


_load_dotenv()

TOKEN = os.environ.get("__PREFIX___TOKEN", "").strip()
TIMEOUT = float(os.environ.get("__PREFIX___TIMEOUT", "30"))
AUDIT_PATH = _HERE / "audit.log"
ERROR_LOG = _HERE / "error.log"

mcp = FastMCP("__SITE__")
__AUTH_BLOCK__

def _clean(params):
    return {k: v for k, v in (params or {}).items() if v is not None}


def _log_error(msg: str) -> None:
    try:
        with ERROR_LOG.open("a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\\n")
    except OSError:
        pass


def _audit(action: str, detail: dict) -> None:
    try:
        with AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": int(time.time()), "action": action, **detail},
                               ensure_ascii=False) + "\\n")
    except OSError:
        pass


async def _request(host: str, method: str, path: str, *, params: dict | None = None,
                   json_body: dict | None = None) -> Any:
    headers = {"Accept": "application/json, text/plain, */*"}
    headers.update(_auth_headers(host))
    try:
        async with httpx.AsyncClient(base_url=HOSTS[host], timeout=TIMEOUT) as client:
            resp = await client.request(method, path, params=_clean(params),
                                        json=json_body, headers=headers)
    except httpx.HTTPError as exc:
        _log_error(f"{method} {host}{path} network: {type(exc).__name__}: {exc}")
        raise RuntimeError(f"network error: {type(exc).__name__}: {exc}") from exc
    if resp.status_code in (401, 403):
        _log_error(f"{method} {host}{path} auth: HTTP {resp.status_code}")
        raise RuntimeError(
            f"HTTP {resp.status_code}：鉴权失败。请检查 .env 中的 __PREFIX___TOKEN"
            + (" 与 __PREFIX___BASIC_PASSWORD_* 口令配置。" if any(s == "Basic" for s in AUTH_SCHEME.values()) else " 配置。"))
    if resp.status_code >= 400:
        _log_error(f"{method} {host}{path} HTTP {resp.status_code}")
    resp.raise_for_status()
    if not resp.content:
        return {"status": resp.status_code}
    try:
        return resp.json()
    except json.JSONDecodeError:
        return {"raw": resp.text[:4000]}


__TOOLS__

# --------------------------------------------------------------------------- #
# 用户态诊断工具（只读：可排障，不可修改工具集）
# --------------------------------------------------------------------------- #
@mcp.tool()
async def tool_catalog() -> dict:
    """自描述：本服务的工具清单与 registry 版本。反馈问题时请附上 registry_version。"""
    registry_path = _HERE / "registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8")) if registry_path.exists() else {}
    return {
        "site": __SITE_JSON__,
        "registry_version": registry.get("registry_version"),
        "updated_at": registry.get("updated_at"),
        "tools": [
            {"name": t.get("tool_name"), "method": t.get("method"), "host": t.get("host"),
             "path": t.get("path"), "mutating": t.get("method") not in ("GET", "HEAD"),
             "description": t.get("description")}
            for t in registry.get("endpoints", []) if t.get("status") != "deprecated"
        ],
    }


@mcp.tool()
async def error_log_tail(lines: int = 20) -> dict:
    """只读诊断：最近 N 条错误日志。"""
    if not ERROR_LOG.exists():
        return {"lines": []}
    content = ERROR_LOG.read_text(encoding="utf-8").splitlines()
    return {"lines": content[-max(1, min(lines, 200)):]}


if __name__ == "__main__":
    mcp.run()
'''


def render_server(registry: dict) -> dict:
    """Render all project files from a registry. Returns {filename: content}."""
    site_name = registry.get("site_name", "site")
    prefix = _env_prefix(site_name)
    version = registry.get("registry_version", 0)
    hosts = registry.get("hosts", {}) or {}
    endpoints = [e for e in registry.get("endpoints", []) if e.get("status") != "deprecated"]

    server = (_SERVER_TEMPLATE
              .replace("__SITE_JSON__", json.dumps(site_name, ensure_ascii=False))
              .replace("__SITE__", site_name)
              .replace("__VERSION__", str(version))
              .replace("__PREFIX__", prefix)
              .replace("__AUTH_BLOCK__", _render_auth_block(prefix, hosts))
              .replace("__TOOLS__", "\n\n".join(_render_tool(e, prefix) for e in endpoints) or "pass"))

    files = {"server.py": server}
    files["requirements.txt"] = "fastmcp>=2,<5\nhttpx>=0.27\n"
    env_lines = [f"# {site_name} MCP 配置。复制为 .env 后填写。",
                 f"# 登录 token（多数站点取自浏览器 localStorage/cookie，获取方法见 README）。",
                 f"{prefix}_TOKEN=",
                 f"# 请求超时（秒）",
                 f"{prefix}_TIMEOUT=30"]
    for h, info in sorted(hosts.items()):
        if (info or {}).get("scheme") == "Basic":
            env_lines.append(f"# Basic 口令（password 部分），来源见 README「鉴权说明」。")
            env_lines.append(f"{prefix}_BASIC_PASSWORD_{_host_key(h)}=")
    files[".env.example"] = "\n".join(env_lines) + "\n"
    files[".gitignore"] = ".env\naudit.log\nerror.log\n__pycache__/\n*.bak\n"

    # README
    lines = [f"# {site_name} MCP Server", "",
             f"由 web-api-extractor 从 **registry v{version}** 生成；共 {len(endpoints)} 个业务工具。",
             ""]
    if any(e.get("method") not in ("GET", "HEAD") for e in endpoints):
        lines += ["写操作工具标注 `[MUTATING]`，调用必须显式传 `confirm=true`，执行会记录到 audit.log。", ""]
    lines += ["## 鉴权说明", "", "按抓包实测的 scheme 生成：", ""]
    for h, info in sorted(hosts.items()):
        lines.append(f"- `{h}`：{(info or {}).get('scheme') or '无（公开接口）'}")
    lines += ["", f"- token 统一配置在 `.env` 的 `{prefix}_TOKEN`。"]
    if any((i or {}).get("scheme") == "Basic" for i in hosts.values()):
        lines += [f"- Basic 站点还需在 `.env` 填 `{prefix}_BASIC_PASSWORD_<HOST>`（base64 拼法中的 password 部分）。"
                  "它通常是前端 JS 里的固定字符串：在抓包会话的 scripts/ 目录搜 `btoa(` 或 `auth:{`，"
                  "例如 example 是 `api/REDACTED-BASIC-PASSWORD`。", ""]
    lines += ["## 工具清单", "", "| 工具 | 方法 | Host | 路径 | 说明 |", "|---|---|---|---|---|"]
    for e in endpoints:
        m = "**[MUTATING]** " if e.get("method") not in ("GET", "HEAD") else ""
        lines.append(f"| `{e['tool_name']}` | {e['method']} | {e['host']} | `{e['path']}` | {m}{e.get('description') or ''} |")
    lines += ["", "## 诊断工具（只读）", "",
              "- `tool_catalog`：工具清单 + registry_version（反馈问题请附上）",
              "- `error_log_tail`：最近错误日志", ""]
    files["README.md"] = "\n".join(lines) + "\n"

    get_endpoint = next((e for e in endpoints if e.get("method") == "GET"), None)
    smoke_host = json.dumps(get_endpoint["host"]) if get_endpoint else "None"
    smoke_path_tmpl = get_endpoint["path"] if get_endpoint else ""
    smoke_qp = json.dumps({k: (v or [""])[0] for k, v in (get_endpoint.get("query_params") or {}).items()},
                          ensure_ascii=False) if get_endpoint else "{}"
    files["smoke_test.py"] = (
        '# -*- coding: utf-8 -*-\n'
        f'"""{site_name} MCP 冒烟自检：调用第一个 GET 工具验证连通与鉴权。"""\n'
        'import asyncio\n'
        'import sys\n'
        'from pathlib import Path\n\n'
        'sys.path.insert(0, str(Path(__file__).resolve().parent))\n'
        'import server\n\n\n'
        'async def main() -> None:\n'
        f'    host = {smoke_host}\n'
        '    if not host:\n'
        '        print("no GET endpoint captured; skipping live smoke")\n'
        '        return\n'
        f'    path = {smoke_path_tmpl!r}\n'
        '    for seg in path.split("/"):\n'
        '        if seg.startswith("{"):\n'
        '            path = path.replace(seg, "1")\n'
        f'    params = {smoke_qp}\n'
        '    result = await server._request(host, "GET", path, params=params or None)\n'
        '    print("smoke OK:", str(result)[:300])\n\n\n'
        'asyncio.run(main())\n')
    return files


def write_files(project_dir, files: dict) -> None:
    directory = Path(project_dir)
    directory.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        target = directory / name
        if target.exists():  # keep a .bak of the previous render
            (directory / f"{name}.bak").write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
        target.write_text(content, encoding="utf-8")


def regenerate(project_dir) -> dict:
    """Re-render server.py etc. from the project's registry (admin-side action)."""
    from .project import load_project

    project = load_project(project_dir)
    if project.get("locked"):
        return {"success": False, "error": "project_locked",
                "message": "project.json 标记为 locked，拒绝再生成。解锁需人工修改 project.json。"}
    registry = load_registry(project_dir)
    files = render_server(registry)
    files.pop("registry.json", None)  # registry is owned by merge, not render
    write_files(project_dir, files)
    return {"success": True, "output_dir": str(project_dir), "files": sorted(files),
            "registry_version": registry.get("registry_version"),
            "endpoint_count": len([e for e in registry.get("endpoints", [])
                                   if e.get("status") != "deprecated"])}


# --------------------------------------------------------------------------- #
# Legacy single-shot generation (generate_mcp_server compatibility)
# --------------------------------------------------------------------------- #
def generate(session_dir: Path, output_dir: Path, endpoint_ids: list | None = None) -> dict:
    """One-shot: analysis.json → fresh project → rendered files."""
    analysis = json.loads((Path(session_dir) / "analysis.json").read_text(encoding="utf-8"))
    session_id = Path(session_dir).name
    entries, hosts = session_to_registry_entries(analysis, session_id)
    if endpoint_ids is not None:
        by_id = {f"ep_{i + 1:03d}": e for i, e in enumerate(entries)}
        missing = [i for i in endpoint_ids if i not in by_id]
        if missing:
            raise ValueError(f"Unknown endpoint_ids: {', '.join(sorted(missing))}")
        entries = [by_id[i] for i in endpoint_ids]
    site_name = re.sub(r"[^a-z0-9-]+", "", session_id.split("_", 2)[-1].split(".")[0].lower()) or "site"
    init_project(output_dir, site_name)
    result = merge_registry(output_dir, entries, hosts, session_id)
    if not result.get("success"):
        return result
    registry = load_registry(output_dir)
    files = render_server(registry)
    write_files(output_dir, files)
    return {"output_dir": str(output_dir), "files": sorted(files),
            "endpoint_count": len(registry["endpoints"]),
            "registry_version": registry["registry_version"],
            "requires_auth_setup": any(e.get("auth_required") for e in registry["endpoints"])}
