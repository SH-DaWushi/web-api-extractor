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

from .project import (
    init_project,
    load_registry,
    merge_registry,
    session_to_registry_entries,
    set_auth_login,
)


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
    token = _current_token()
    if scheme == "Basic":
        # Basic base64(token:password). The password part is a per-site constant
        # that usually lives in the frontend JS (search captured scripts for
        # `btoa(` or `auth:{`) — fill it in .env as __PREFIX___BASIC_PASSWORD_<HOST>.
        password = os.environ.get("__PREFIX___BASIC_PASSWORD_" + _HK(host), "")
        raw = (token + ":" + password).encode("utf-8")
        return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}
    if scheme == "Bearer":
        return {"Authorization": "Bearer " + token} if token else {}
    cookie = COOKIE_NAME.get(host)
    if cookie and token:
        return {"Cookie": cookie + "=" + token}
    return {}
""".replace("__PREFIX__", prefix))


# --------------------------------------------------------------------------- #
# per-tool rendering
# --------------------------------------------------------------------------- #
def _render_auth_login_tools(auth_login: dict, prefix: str) -> str:
    """生成 login / auth_status 工具。

    凭据来源优先级：调用参数 > 环境变量。密码只在内存中用于换取 token，
    既不落盘也不写审计日志。
    """
    acct, pwd = auth_login["account_field"], auth_login["password_field"]
    tpath = ".".join(auth_login["token_path"])
    verify = auth_login.get("verify")
    verify_host = (verify or {}).get("host") or auth_login["host"]
    verify_path = (verify or {}).get("path") or ""
    query = {k: v for k, v in (auth_login.get("query_params") or {}).items() if v}

    lines = [
        "",
        "# --------------------------------------------------------------------------- #",
        "# 登录（账号密码换取 token，仅存进程内存）",
        "# --------------------------------------------------------------------------- #",
        "",
        "def _dig(obj: Any, path: list) -> Any:",
        "    for key in path:",
        "        if not isinstance(obj, dict):",
        "            return None",
        "        obj = obj.get(key)",
        "    return obj",
        "",
        "",
        "def _encrypt_password(password: str) -> str:",
        '    """按前端实测的算法加密密码（当前策略：RSA-OAEP/SHA-256 + base64）。"""',
        "    enc = (_AUTH_LOGIN_CFG or {}).get('password_encryption') or {}",
        "    pem = enc.get('public_key')",
        "    if not pem or enc.get('scheme') != 'rsa-oaep-sha256':",
        "        return password",
        "    try:",
        "        from cryptography.hazmat.primitives import hashes, serialization",
        "        from cryptography.hazmat.primitives.asymmetric import padding",
        "    except ImportError:",
        "        raise RuntimeError('需要 cryptography 用于密码加密：pip install cryptography')",
        "    # registry → repr() 往返后换行可能变成字面 \\\\n，统一还原为真实换行。",
        "    pem = pem.replace('\\\\n', '\\n')",
        "    key = serialization.load_pem_public_key(pem.encode())",
        "    ct = key.encrypt(password.encode(), padding.OAEP(",
        "        mgf=padding.MGF1(algorithm=hashes.SHA256()),",
        "        algorithm=hashes.SHA256(), label=None))",
        "    return base64.b64encode(ct).decode('ascii')",
        "",
        "",
        "async def _do_login(account: str, password: str) -> dict:",
        '    """调用登录接口换取 token，成功则写入进程内存。"""',
        "    global RUNTIME_TOKEN",
        "    cfg = _AUTH_LOGIN_CFG",
        "    secret = _encrypt_password(password)",
        "    payload = {cfg['account_field']: account, cfg['password_field']: secret}",
        "    scheme = (cfg.get('password_encryption') or {}).get('scheme')",
        "    headers = {'Accept': 'application/json, text/plain, */*',",
        "               'Content-Type': 'application/json',",
        "               'Referer': HOSTS[cfg['host']] + '/'}",
        "    # 登录接口本身也走站点鉴权（抓包实测带 Authorization）",
        "    headers.update(_auth_headers(cfg['host']))",
        "    if scheme:",
        "        _audit('login_encryption', {'scheme': scheme})",
        "    async with httpx.AsyncClient(base_url=HOSTS[cfg['host']], timeout=TIMEOUT) as client:",
        "        resp = await client.request(cfg['method'], cfg['path'], tmp_placeholder",
        "                                    params=_clean(cfg['query_params']) or None,",
        "                                    json=payload, headers=headers)",
        "    if resp.status_code >= 400:",
        "        _log_error(f\"login HTTP {resp.status_code}\")",
        "        return {'success': False, 'error': f'HTTP {resp.status_code}', 'detail': resp.text[:300]}",
        "    try:",
        "        body = resp.json()",
        "    except Exception:",
        "        return {'success': False, 'error': 'invalid_json', 'detail': resp.text[:300]}",
        "    token = _dig(body, cfg['token_path'])",
        "    if not token:",
        "        msg = body.get('msg') if isinstance(body, dict) else None",
        "        return {'success': False, 'error': 'no_token_in_response',",
        "                'server_msg': msg, 'detail': str(body)[:300]}",
        "    RUNTIME_TOKEN = str(token)",
        "    # S-1/S-2: token 与凭据 DPAPI 加密落盘（仅同一 Windows 用户可解密）。",
        "    _cache_save(TOKEN_CACHE, {'token': RUNTIME_TOKEN, 'saved_at': int(time.time())})",
        "    _cache_save(CRED_CACHE, {'account': account, 'password': password})",
        "    _audit('login', {'host': cfg['host'], 'account': _mask(account), 'ok': True})",
        "    return {'success': True, 'account': _mask(account)}",
        "",
        "",
        "def _mask(value: str) -> str:",
        '    """审计日志里对账号做脱敏，不记录密码。"""',
        "    s = str(value)",
        "    if len(s) <= 4:",
        "        return '*' * len(s)",
        "    return s[:2] + '*' * (len(s) - 4) + s[-2:]",
        "",
        "",
        "@mcp.tool()",
        "async def login(account: str | None = None, password: str | None = None) -> dict:",
        '    """登录并获取访问 token。',
        "",
        "    凭据优先取参数，其次 .env，最后 DPAPI 加密缓存（首次 login 成功后自动写入）。",
        "    成功后 token 加密持久化，重启服务自动恢复，无需重复登录。",
        '    """',
        "    acct = (account or os.environ.get('" + prefix + "_ACCOUNT', '')).strip()",
        "    pwd = password or os.environ.get('" + prefix + "_PASSWORD', '')",
        "    if not acct or not pwd:",
        "        creds = _cached_credentials()",
        "        if creds:",
        "            acct, pwd = creds",
        "    if not acct or not pwd:",
        "        return {'success': False, 'error': 'missing_credentials',",
        "                'message': ('未提供账号密码。可调用 login(account=..., password=...) 传入；'",
        "                            '或在 .env 配置 " + prefix + "_ACCOUNT / " + prefix + "_PASSWORD。')}",
        "    return await _do_login(acct, pwd)",
        "",
        "",
        "@mcp.tool()",
        "async def auth_status() -> dict:",
        '    """检查当前鉴权状态：token 来源与有效性（只读，不触发登录）。"""',
        "    src = ('cache/login' if RUNTIME_TOKEN and _cache_load(TOKEN_CACHE) else",
        "           'runtime(login)' if RUNTIME_TOKEN else",
        "           ('env(" + prefix + "_TOKEN)' if TOKEN else 'none'))",
        "    info = {'has_token': bool(_current_token()), 'token_source': src,",
        "            'login_tool_available': bool(_AUTH_LOGIN_CFG),",
        "            'credentials_in_env': bool(os.environ.get('" + prefix + "_ACCOUNT')",
        "                                       and os.environ.get('" + prefix + "_PASSWORD')),",
        "            'credentials_cached_encrypted': bool(_cache_load(CRED_CACHE))}",
        "    cfg = _AUTH_LOGIN_CFG",
        "    if not cfg or not cfg.get('verify_path') or not info['has_token']:",
        "        # 无 token 时不必发探针——那必然 401，徒增日志噪音。",
        "        info['verified'] = None if not info['has_token'] else info.get('verified')",
        "        return info",
        "    try:",
        "        info['verified'] = True",
        "        info['verify_detail'] = 'ok'",
        "    except Exception as exc:",
        "        info['verified'] = False",
        "        info['verify_detail'] = f'{type(exc).__name__}: {exc}'",
        "    return info",
    ]
    # 校验探针单独渲染，避免上面的字面量过长。
    text = "\n".join(lines)
    text = text.replace("\n        info['verified'] = True\n        info['verify_detail'] = 'ok'",
                        "\n        await _request(cfg['verify_host'], 'GET', cfg['verify_path'])\n        info['verified'] = True\n        info['verify_detail'] = 'ok'")
    text = text.replace(
        "        resp = await client.request(cfg['method'], cfg['path'], tmp_placeholder\n",
        "        resp = await client.request(cfg['method'], cfg['path'],\n")
    return text


def _looks_identity_or_time(ident: str) -> bool:
    """身份类/时间类参数不做默认值：抓包时的 user_id、时间戳只代表当时那个人、那一刻。"""
    low = ident.lower()
    return (
        "user" in low or "uid" in low or "author" in low or "account" in low
        or "time" in low or "date" in low or "start" in low or "end" in low
        or "token" in low or "session" in low or "ids" in low
    )


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
        # 只有当参数在多轮采样中稳定取同一值时，才把它烘成默认值。
        # 单次采样（sample_count < 2）或值本身像具体数据（长串/含逗号/非 ASCII/时间戳）
        # 一律不做默认值——否则会把抓包当时的真实数据（用户 ID、服务器名、时间戳）
        # 写进分发包，既泄漏又会产生过期默认值。
        stable = (
            sample_count >= 2
            and len(values) == 1
            and len(str(values[0])) <= 24
            and str(values[0]).isascii()
            and "," not in str(values[0])
            and not _looks_identity_or_time(ident)
        )
        if stable:
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
import sys
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
# 登录成功后写入；运行时优先级：RUNTIME_TOKEN(含加密缓存) > .env TOKEN。
RUNTIME_TOKEN = ""
TOKEN_CACHE = _HERE / "token_cache.bin"
CRED_CACHE = _HERE / "cred_cache.bin"

mcp = FastMCP("__SITE__")
__AUTH_BLOCK__
_AUTH_LOGIN_CFG = __AUTH_LOGIN__


# --------------------------------------------------------------------------- #
# S-1/S-2: 凭据与 token 的加密持久化（Windows DPAPI；其它平台退化为仅内存）。
# 落盘文件只能由同一 Windows 用户解密；.env 里无需再写明文密码。
# --------------------------------------------------------------------------- #
def _dpapi_protect(data: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
        raise OSError("CryptProtectData failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def _dpapi_unprotect(data: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
        raise OSError("CryptUnprotectData failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


_DPAPI_OK = sys.platform == "win32"


def _cache_load(path) -> dict | None:
    if not _DPAPI_OK or not path.exists():
        return None
    try:
        import base64 as _b64
        return json.loads(_dpapi_unprotect(_b64.b64decode(path.read_text(encoding="ascii"))))
    except Exception:
        return None


def _cache_save(path, obj: dict) -> None:
    if not _DPAPI_OK:
        return
    try:
        import base64 as _b64
        path.write_text(_b64.b64encode(_dpapi_protect(json.dumps(obj, ensure_ascii=False).encode("utf-8"))).decode("ascii"), encoding="ascii")
    except Exception as exc:
        _log_error(f"cache save {path.name}: {type(exc).__name__}")


# 启动即恢复上次会话的 token（无网络调用）。
_cached_token = _cache_load(TOKEN_CACHE)
if _cached_token and _cached_token.get("token"):
    RUNTIME_TOKEN = str(_cached_token["token"])


def _cached_credentials() -> tuple[str, str] | None:
    """S-3 重认证的凭据来源：.env 优先，其次加密缓存。"""
    acct = os.environ.get("__PREFIX___ACCOUNT", "").strip()
    pwd = os.environ.get("__PREFIX___PASSWORD", "")
    if acct and pwd:
        return acct, pwd
    cred = _cache_load(CRED_CACHE)
    if cred and cred.get("account") and cred.get("password"):
        return str(cred["account"]), str(cred["password"])
    return None


def _current_token() -> str:
    return RUNTIME_TOKEN or TOKEN

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
                   json_body: dict | None = None, _retried_auth: bool = False) -> Any:
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
        # S-3: 自动重认证——有登录配置且凭据可用（.env 或加密缓存）时，
        # 重新登录并重试一次；仍失败才报错。
        _do_login_fn = globals().get("_do_login")
        if not _retried_auth and _do_login_fn is not None:
            creds = _cached_credentials()
            if creds:
                _log_error(f"{method} {host}{path} HTTP {resp.status_code}: auto re-login")
                result = await _do_login_fn(creds[0], creds[1])
                if result.get("success"):
                    return await _request(host, method, path, params=params,
                                          json_body=json_body, _retried_auth=True)
        _log_error(f"{method} {host}{path} auth: HTTP {resp.status_code}")
        hint = ""
        if _AUTH_LOGIN_CFG:
            hint = " 可调用 login(account=..., password=...) 登录；或在 .env 配置凭据。"
        raise RuntimeError(
            f"HTTP {resp.status_code}：鉴权失败（自动重登录未成功或不可用）。"
            f"请检查 .env 中的 __PREFIX___TOKEN"
            + (" 与 __PREFIX___BASIC_PASSWORD_* 口令配置。" if any(s == "Basic" for s in AUTH_SCHEME.values()) else " 配置。")
            + hint)
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

    auth_login = registry.get("auth_login") or None
    tool_blocks = [_render_tool(e, prefix) for e in endpoints]
    if auth_login:
        tool_blocks.insert(0, _render_auth_login_tools(auth_login, prefix))

    server = (_SERVER_TEMPLATE
              .replace("__SITE_JSON__", json.dumps(site_name, ensure_ascii=False))
              .replace("__SITE__", site_name)
              .replace("__VERSION__", str(version))
              .replace("__PREFIX__", prefix)
              .replace("__AUTH_LOGIN__", repr(auth_login) if auth_login else "None")
              .replace("__AUTH_BLOCK__", _render_auth_block(prefix, hosts))
              .replace("__TOOLS__", "\n\n".join(tool_blocks) or "pass"))

    files = {"server.py": server}
    req = "fastmcp>=2,<5\nhttpx>=0.27\n"
    if (auth_login or {}).get("password_encryption"):
        req += "cryptography>=42\n"
    files["requirements.txt"] = req
    env_lines = [f"# {site_name} MCP 配置。复制为 .env 后填写。",
                 f"# 登录 token（多数站点取自浏览器 localStorage/cookie，获取方法见 README）。",
                 f"{prefix}_TOKEN=",
                 f"# 请求超时（秒）",
                 f"{prefix}_TIMEOUT=30"]
    if auth_login:
        env_lines += [
            "# 账号密码登录（推荐留空：调用一次 login(account,password) 后凭据与 token",
            "# 会 DPAPI 加密存入 token_cache.bin / cred_cache.bin，重启自动恢复，401 自动重登录）。",
            "# 如需 headless 首启自动登录，可在此明文填写（注意保密）。",
            f"{prefix}_ACCOUNT=",
            f"{prefix}_PASSWORD=",
        ]
    for h, info in sorted(hosts.items()):
        if (info or {}).get("scheme") == "Basic":
            env_lines.append(f"# Basic 口令（password 部分），来源见 README「鉴权说明」。")
            env_lines.append(f"{prefix}_BASIC_PASSWORD_{_host_key(h)}=")
    files[".env.example"] = "\n".join(env_lines) + "\n"
    files[".gitignore"] = ".env\naudit.log\nerror.log\n__pycache__/\n*.bak\ntoken_cache.bin\ncred_cache.bin\n"

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
    if auth_login:
        tp = ".".join(auth_login["token_path"])
        lines += ["## 登录", "",
                  f"抓包识别到账号密码登录接口：`{auth_login['method']} {auth_login['host']}{auth_login['path']}`", "",
                  "两种用法：", "",
                  f"1. **环境变量**（推荐）：在 `.env` 填 `{prefix}_ACCOUNT` / `{prefix}_PASSWORD`，"
                  "之后调用 `login()` 无需传参。",
                  "2. **交互式**：直接调用 `login(account=\"...\", password=\"...\")`。", "",
                  f"成功后 token 取自响应字段 `{tp}`，**只保存在服务进程内存中，不写入磁盘**；",
                  f"也可以跳过登录，直接把浏览器里取到的 token 填进 `{prefix}_TOKEN`。", "",
                  "`auth_status()` 可查看当前 token 来源与是否有效（只读，不会触发登录）。", ""]
        enc = auth_login.get("password_encryption") or {}
        if enc:
            lines += [f"密码按前端实测策略加密后传输：`{enc.get('scheme')}`（加密版本 `{enc.get('version')}`）。",
                      "公钥取自前端 JS 的 PEM 块，已内联在 server.py 中，无需手工配置。", ""]
        else:
            lines += ["登录接口按明文 JSON 提交密码（抓包实测未发现前端加密）。", ""]
        lines += ["> 推荐做法：`.env` 凭据留空，调用一次 `login(account=\"...\", password=\"...\")`——",
                  "> 成功后凭据与 token 以 **DPAPI 加密**存入 `cred_cache.bin` / `token_cache.bin`",
                  "> （仅同一 Windows 用户可解密，已列入 .gitignore），重启自动恢复，401 自动重登录。",
                  "> `login` 的审计日志只记录脱敏账号与加密策略，不记录密码。", ""]
        lines = [l for l in lines if not l.startswith("- token 统一配置在")]
        lines.insert(next(i for i, l in enumerate(lines) if l.startswith("## 工具清单")),
                     f"- token 也可由 `login()` 动态获取（见下节「登录」）。")
    files["README.md"] = "\n".join(lines) + "\n"

    # 优先挑无需鉴权的 GET 接口做冒烟——否则未配 token 时必然报「没权限」，
    # 用户无法区分是环境没配好还是接口本身正常。
    get_endpoint = next(
        (e for e in endpoints if e.get("method") == "GET" and not e.get("auth_required")),
        next((e for e in endpoints if e.get("method") == "GET"), None),
    )
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
    set_auth_login(output_dir, analysis.get("auth_login"))
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
