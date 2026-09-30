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
import keyword
import re
from pathlib import Path
from typing import Any

from .analyzer import (as_value_list, credential_cookie_candidates,
                       is_switch_risk_param, value_is_response_derived)
from .project import (
    backup_existing_project,
    existing_project_summary,
    init_project,
    load_registry,
    merge_registry,
    overwrite_notice,
    session_to_registry_entries,
    set_auth_login,
)


def _env_prefix(site_name: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", site_name.upper()).strip("_") or "SITE"


# 生成物里 playwright 的**钉死版本** —— 必须与 Playwright 的浏览器内核修订号对齐：
# playwright 1.63.0 ⇄ chromium-1243（`%LOCALAPPDATA%\ms-playwright\chromium-1243`）。
# 写死版本号而不是范围，是因为内核是**按 playwright 版本**缓存的：放开为 `>=` 后，
# 用户机器上装到新版本会带来新的修订号 → 需要重新下载整个浏览器（技能侧已缓存的那份
# 用不上）。本机实测：技能侧缓存的 chromium-1243 与 1.63.0 逐字对上 → 零下载。
_PLAYWRIGHT_PIN = "1.63.0"


def _interactive_login_required(auth_login: dict | None) -> bool:
    """这个站点是否**只能交互式登录**（判据见 ``analyzer.login_post_verdict``）。

    只在拿到 ``post_login.verdict == "interactive"`` 这个**明确结论**时才为真：
    字段缺省（老 registry / 老 analysis.json）、或结论是 ``post_ok`` 时一律返回 False，
    产物与以前逐字节相同。
    """
    post_login = (auth_login or {}).get("post_login")
    return isinstance(post_login, dict) and post_login.get("verdict") == "interactive"


# IPv4 字面量的开头（如 ``10.0.0.5``）。只认「四段点分十进制」，
# 故 ``3m.example.com`` 这类以数字起头的域名不会误判。
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}")


def _site_name_from_session_id(session_id: str) -> str:
    """从会话 id 里取出站点名（生成物的 FastMCP 名与 env 前缀都源自它）。

    会话 id 形如 ``20260929_120000_<host>_<hex4>``（见 ``server.new_session_id``），
    host 里的 ``:`` 已被换成 ``_``、``.`` 保留。**修复前**一律取 host 的「第一个点号
    之前」那一段：正常域名 ``oa.example.com`` 得到可读的 ``oa``，但 IPv4 主机
    ``10.0.0.5`` 只剩 ``10`` —— 站点名与 env 前缀都退化成 ``10``，同一网段的
    多台设备还会互相撞名（``10_ACCOUNT`` / ``10_TOKEN`` 之类）。IPv4 字面量改为
    **整段保留、点换成连字符**（``10-0-0-5`` → env 前缀 ``10_0_0_5``，
    可读且仍是合法 env 名）。非 IP 主机**保持原样**（``oa`` 仍是 ``oa``），不动既有站点。
    """
    label = session_id.split("_", 2)[-1]
    match = _IPV4_RE.match(label)
    if match:
        return re.sub(r"[^a-z0-9-]+", "", match.group(0).replace(".", "-").lower()) or "site"
    return re.sub(r"[^a-z0-9-]+", "", label.split(".")[0].lower()) or "site"


def _host_key(host: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", host.upper()).strip("_")


def _py_ident(name: str) -> str:
    """捕获到的名字 → 合法且非关键字的 Python 标识符。

    必须是合法标识符:抓包里的参数名叫 `class` / `def` / `None` 时,直接拼进
    函数签名会让整个生成物 **SyntaxError**(实测:一个这样的参数就能让工具集全废)。
    """
    ident = re.sub(r"[^0-9a-zA-Z_]+", "_", str(name)).strip("_") or "param"
    if ident[0].isdigit():
        ident = f"p_{ident}"
    if keyword.iskeyword(ident):
        ident = f"{ident}_"
    return ident


def _unique_ident(base: str, taken: set) -> str:
    """在 `taken` 之外取一个确定性的唯一标识符(不做静默丢弃)。"""
    candidate, index = base, 2
    while candidate in taken:
        candidate = f"{base}_{index}"
        index += 1
    return candidate


def _src_literal_text(text: object) -> str:
    """转义成可安全嵌入 `"..."` / `\"\"\"...\"\"\"` 的内容(不含外层引号)。

    用于 site_name 这类会被同时放进文档字符串与 `FastMCP("...")` 的值:
    反斜杠与引号不转义就能闭合字符串,换行能把注释变成代码。
    """
    return (str(text).replace("\\", "\\\\").replace('"', '\\"')
            .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t"))


def _fstring_literal(text: str) -> str:
    """f-string 里**字面量部分**的转义:引号、反斜杠、换行,以及 `{`/`}`。"""
    return (text.replace("\\", "\\\\").replace('"', '\\"')
            .replace("\n", "\\n").replace("\r", "\\r")
            .replace("{", "{{").replace("}", "}}"))


def _emit_path(path: str, ident_map: dict[str, str]) -> str:
    """把捕获到的路径发射为 Python 字符串字面量(必要时为 f-string)。

    `ident_map` 是「占位符原名 → 最终参数名」的映射(必须与函数签名一致)。
    只有**已知路径参数**的占位符才会被当作插值;其它 `{`/`}` 一律转义成普通字符。
    否则抓到的路径里一个 `{...}` 就会被当成表达式求值 —— 实测可执行任意代码。
    """
    for original, ident in ident_map.items():
        if original != ident:                      # `{class}` 这类必须同步改名
            path = path.replace("{" + original + "}", "{" + ident + "}")
    if "{" not in path:
        return json.dumps(path)

    known = set(ident_map.values())
    segments: list[tuple[bool, str]] = []
    index = 0
    while index < len(path):
        char = path[index]
        if char == "{":
            end = path.find("}", index + 1)
            if end != -1 and path[index + 1:end] in known:
                segments.append((True, path[index + 1:end]))
                index = end + 1
                continue
        segments.append((False, char))
        index += 1

    merged: list[tuple[bool, str]] = []
    for is_placeholder, text in segments:
        if merged and merged[-1][0] == is_placeholder:
            merged[-1] = (is_placeholder, merged[-1][1] + text)
        else:
            merged.append((is_placeholder, text))
    body = "".join(
        ("{" + text + "}") if is_placeholder else _fstring_literal(text)
        for is_placeholder, text in merged)
    return 'f"' + body + '"'


def _infer_type(values: list) -> str:
    vals = [str(v) for v in values]
    if vals and all(re.fullmatch(r"-?\d+", v) for v in vals):
        return "int"
    return "str"


# --------------------------------------------------------------------------- #
# auth block (plain code text; literals injected via json.dumps)
# --------------------------------------------------------------------------- #
def _host_auth_kind(info: dict) -> str | None:
    """主机级兜底鉴权方式（登录工具、以及**没记 auth_hint 的旧 registry** 在用）。

    返回 ``"Basic"`` / ``"Bearer"``（发 Authorization）、``"cookie"``（发 Cookie）
    或 ``None``（没观测到凭据）。端点级结论优先，见 `_endpoint_auth_kinds`。
    """
    info = info or {}
    scheme = info.get("scheme")
    if scheme and str(scheme).lower() != "cookie":
        return str(scheme)
    if credential_cookie_candidates(info.get("cookie_names")):
        return "cookie"
    return None


def _endpoint_auth_kinds(entry: dict, info: dict) -> list[str]:
    """**这条端点**实测到的鉴权载体（S13 端点级鉴权）。

    优先用 analyzer 逐端点记录的 ``auth_hint``（``["Bearer"]`` / ``["cookie"]`` /
    ``["Bearer", "cookie"]``）。没有记录时（旧 registry / 测试直接构造的条目）退回
    主机级方式 —— 与修复前逐字节同义，故旧项目的行为不变。

    ``"none"`` 视为「这一条什么都没观测到」＝没有证据，同样退回主机级方式：
    宁可多发一种凭据（服务端最多忽略），也不能因为「端点里没记到」就把整个站点的
    鉴权摘掉。
    """
    hints = [str(h) for h in (entry.get("auth_hint") or []) if str(h) and str(h) != "none"]
    if hints:
        return list(dict.fromkeys(hints))
    kind = _host_auth_kind(info)
    return [kind] if kind else []


def _token_using_hosts(hosts: dict, host_kinds: dict) -> set:
    """哪些域名需要 `.env` 里的 ``<PREFIX>_TOKEN``（Bearer / Basic / 混用里有非 Cookie 的）。

    抽出来是为了让**三处说法同源**：`.env.example` 给不给这一行、README 的「鉴权说明」
    提不提它、401 报错指不指它 —— 必须由同一个判据决定，否则又会出现「报错让你去配一个
    `.env.example` 里根本没有的变量」这种负优化（修复前就是这么错的）。
    """
    out: set = set()
    for h, info in (hosts or {}).items():
        kinds = host_kinds.get(h) or []
        scheme = (info or {}).get("scheme")
        if len(kinds) > 1:
            if any(k != "cookie" for k in kinds):
                out.add(h)
        elif scheme and scheme != "Cookie":
            out.add(h)
    return out


def _render_auth_block(prefix: str, hosts: dict, endpoints: list, *,
                       state_cookie_hook: str = "") -> str:
    hosts_literal = json.dumps({h: f"https://{h}" for h in hosts}, indent=4, ensure_ascii=False)
    # repr() — NOT json.dumps — so None/null renders as a valid Python literal.
    # S13：鉴权方式**按端点**记录（{host: {tool: [方式…]}}），不再整域名单值。
    # 实测同一域名下可以混用（Bearer 接口 + 只认 Cookie 的接口），按主机记一种时
    # 前者会覆盖后者 → 只认 Cookie 的接口永远收不到 Cookie，稳定 401。
    per_tool: dict[str, dict[str, list[str]]] = {}
    for entry in endpoints:
        host = entry.get("host") or ""
        tool = _py_ident(entry.get("tool_name") or "")
        kinds = _endpoint_auth_kinds(entry, (hosts or {}).get(host) or {})
        per_tool.setdefault(host, {})[tool] = kinds
    scheme_literal = repr(per_tool)
    # 主机级兜底：登录工具、冒烟脚本、以及清单里没有的工具读它。
    host_scheme_literal = repr({h: _host_auth_kind(i) for h, i in (hosts or {}).items()})
    # Issue #12: 携带**全部**观测到的 Cookie，而非只取第一个、更不是只取
    # `is_credential_cookie` 认得的那些。
    # Cookie 鉴权是集合语义——实测单独带设备标识类 Cookie 返回 401，
    # 必须整套会话 Cookie 一起发送；而 Citrix ADC 这类设备的会话 Cookie 里
    # 有四个（startupapp/is_cisco_platform/NITRO_SK/rdx_pagination_size）
    # 根本不命中凭据命名特征，按特征过滤就会漏发 → `1026 Not logged in`
    # 且服务端不指出缺谁。只剔除**已知**埋点（ai_*/_ga 等）。
    cookie_literal = repr({
        h: credential_cookie_candidates((i or {}).get("cookie_names"))
        for h, i in (hosts or {}).items()
    })
    return (
        "\nHOSTS = " + hosts_literal +
        # 每条工具实测的鉴权载体：{host: {tool_name: ["Bearer" / "Basic" / "cookie"]}}。
        # 同一域名下不同接口可以不一样 —— 凭据**按端点取用**，不做整域名一刀切。
        "\nAUTH_SCHEME = " + scheme_literal +
        # 主机级兜底（登录工具 / 清单外的工具）：没记到端点时按它发凭据。
        "\nHOST_AUTH_SCHEME = " + host_scheme_literal +
        "\nCREDENTIAL_COOKIES = " + cookie_literal + """

def _HK(host: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", host.upper()).strip("_")


def _cookie_values(host: str, names: list) -> dict:
    \"\"\"按 cookie 名收集运行时值。支持两种配置方式：

      * 整串：__PREFIX___COOKIE_<HOST>='a=1; b=2'（分号分隔，推荐）
      * 逐条：__PREFIX___COOKIE_<HOST>_<NAME>=<value>

    整串形式便于直接填入从登录态文件读到的 Cookie。
    \"\"\"
    jar: dict = {}
    blob = os.environ.get("__PREFIX___COOKIE_" + _HK(host), "")
    if blob:
        for part in blob.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                jar[k.strip()] = v.strip()
    for name in names or []:
        env_key = ("__PREFIX___COOKIE_" + _HK(host) + "_"
                   + re.sub(r"[^A-Z0-9]+", "_", str(name).upper()))
        val = os.environ.get(env_key)
        if val:
            jar[name] = val
__STATE_COOKIE_HOOK__    return jar


def _auth_headers(host: str, tool: str | None = None) -> dict:
    \"\"\"该次调用要带的鉴权头 —— 按**这条端点**实测的方式取用。

    同一域名下不同接口可以用不同的登录方式（实测：一部分接口用
    `Authorization: Bearer`，另一部分只认 Cookie）。所以这里先按 `tool`
    查端点实测记录，查不到（登录工具 / 旧记录）才退回该域名的主方式 ——
    这样「只认 Cookie 的接口」不会再被硬塞一个 Authorization 而 401。
    \"\"\"
    kinds = (AUTH_SCHEME.get(host) or {}).get(tool) if tool is not None else None
    if kinds is None:
        fallback = HOST_AUTH_SCHEME.get(host)
        kinds = [fallback] if fallback else []
    lowered = [str(k).lower() for k in kinds]
    token = _current_token()
    scheme = next((str(k) for k in kinds if str(k).lower() != "cookie"), None)
    headers: dict = {}
    if scheme == "Basic":
        # Basic base64(token:password). The password part is a per-site constant
        # that usually lives in the frontend JS (search captured scripts for
        # `btoa(` or `auth:{`) — fill it in .env as __PREFIX___BASIC_PASSWORD_<HOST>.
        password = os.environ.get("__PREFIX___BASIC_PASSWORD_" + _HK(host), "")
        raw = (token + ":" + password).encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    elif scheme == "Bearer":
        if token:
            headers["Authorization"] = "Bearer " + token
    # Cookie 鉴权：**实测要求 Cookie 时一定发**（Authorization 与 Cookie 可以同时需要，
    # 实测有接口两者都带）；同时它也是「这条端点没记到方式」时的兜底。单发一个 Cookie
    # 往往 401，故发整组。
    if not kinds or "cookie" in lowered:
        jar = _cookie_values(host, CREDENTIAL_COOKIES.get(host))
        if jar:
            headers["Cookie"] = "; ".join(k + "=" + v for k, v in jar.items())
        else:
            # 回退：单一 token（兼容只配了 __PREFIX___TOKEN 的旧场景）
            names = CREDENTIAL_COOKIES.get(host) or []
            if names and token:
                headers["Cookie"] = names[0] + "=" + token
    return headers
""".replace("__PREFIX__", prefix)
        .replace("__STATE_COOKIE_HOOK__", state_cookie_hook))


# --------------------------------------------------------------------------- #
# per-tool rendering
# --------------------------------------------------------------------------- #
def _is_redaction_mark(value: object) -> bool:
    """值是不是脱敏哨兵（``***`` / 纯 ``*`` 串）。

    哨兵是「这个取值已被隐藏」的记号，**不是数据**：它被当成参数值发给服务端时，
    登录必然失败（`tenant=***`）。判定与 `_stable_default_value` 里那条完全一致。
    """
    return isinstance(value, str) and (
        value == _REDACTION_SENTINEL or (len(value) >= 2 and set(value) == {"*"}))


def _login_query_env(prefix: str, name: str) -> str:
    """(b) 类登录 query 参数的 .env 名（沿用 `<PREFIX>_<用途>_<KEY>` 的现有风格）。

    对照既有的 `<PREFIX>_ACCOUNT` / `<PREFIX>_PASSWORD` / `<PREFIX>_COOKIE_<HOST>`。
    """
    key = re.sub(r"[^A-Z0-9]+", "_", str(name).upper()).strip("_") or "PARAM"
    return f"{prefix}_LOGIN_QUERY_{key}"


def _fetch_plan(provenance: object) -> dict[str, Any] | None:
    """从 provenance 记录里取出**可自动取用**的计划（不满足五条闸门则 None）。

    分析器只在五条时序闸门**全中**时才在记录里写 ``fetch``（唯一来源 / 公共无鉴权 GET /
    来源接口自身无参数 / 不是登录或校验端点 / 早于登录且响应是完整 JSON）。生成期没有
    抓包顺序，所以这里只读结论、不重判 —— 缺了就不取用（降级为必填）。
    """
    if not isinstance(provenance, dict):
        return None
    plan = provenance.get("fetch")
    if not isinstance(plan, dict):
        return None
    if plan.get("method") != "GET" or not plan.get("url") or not plan.get("field"):
        return None
    return plan


def _auth_login_fetch_plans(auth_login: dict) -> dict[str, dict[str, Any]]:
    """``{参数名: 取用计划}`` —— 只含**能自动取用**的登录 query 参数。"""
    provenance = auth_login.get("query_param_provenance")
    if not isinstance(provenance, dict):
        return {}
    plans: dict[str, dict[str, Any]] = {}
    for raw_name, entry in provenance.items():
        plan = _fetch_plan(entry)
        if plan:
            plans[str(raw_name)] = plan
    return plans


def _login_query_plan(auth_login: dict, prefix: str) -> dict[str, Any]:
    """登录接口 query 参数的分流：烘默认值 / 自动取用 / 运行时按链取值。

    抓包第一次登录请求的 query 里可能是 `tenant=acme` / `?signature=…` 这类**只代表
    当时那一次会话**的取值。三类出口：

      * (a) ``fetched``  —— 分析器判定「值来自前面那个**公共、无鉴权、无参数**的 GET
        响应」（五条时序闸门全中）→ **不烘快照**：发射取用代码，运行时先调来源接口、
        取出字段，再用于登录。使用者什么都不用填（见 `_render_auth_login_tools`）。
        取用的优先级最高：既然确切知道值来自别处，烘一个当时的快照就是错的。
      * (c) ``baked``    —— 走 `_stable_default_value` 的名字/取值闸门：`fixed`，或
        「无证据 + 观测取值唯一」，且名字不像身份/时间、值不像具体数据、不是哨兵 `***`
        也不是空值 → 烘成默认值。**来源确定的参数不走这一条** —— 「值是从别处来的」
        本身就是可变性知识，烘一次会话的快照很快失效；
      * (b) ``required`` —— 其余参数，抓包取值一律不烘（值会变、像真实数据/凭据、是哨兵
        `***`、是空串……）。它们**不是必填**：带默认值 `None` 的参数（不填也能进入函数体，
        否则参数绑定阶段就 `TypeError`，弹窗那条路根本走不到），运行时按
        **调用方入参 → .env → 原生弹窗询问 → 明确报错并点名缺哪个** 取值。
        401 自动重登录拿不到入参，故同时发射 .env 通道（见 `_do_login` 里的缺失报错）——
        这条链是自动重登录的唯一来源，缺一个要**响亮报错并列出缺哪个**。
        来源确定但无法安全取用时也走这里，并在 docstring 里说明为什么没能自动取用。

    空 ``query_params``（金标准良性语料）→ 三个列表都空 → 生成物逐字节不变。
    """
    evidence = auth_login.get("query_param_evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    fetch_plans = _auth_login_fetch_plans(auth_login)
    provenance = auth_login.get("query_param_provenance")
    provenance = provenance if isinstance(provenance, dict) else {}
    baked: dict[str, str] = {}
    required: list[dict[str, Any]] = []
    fetched: list[dict[str, Any]] = []
    # 生成物自身的代码固定引用 account / password 这两个名字，抓包里的同名参数让名。
    taken_idents: set[str] = {"account", "password"}
    taken_envs: set[str] = set()
    for raw_name, raw_values in (auth_login.get("query_params") or {}).items():
        name = str(raw_name)
        values = as_value_list(raw_values)
        # 一个取值都没观测到的参数（`{"x": []}`）没有任何信息可烘，也没什么可传。
        if not values:
            continue
        plan = fetch_plans.get(name)
        if plan:
            fetched.append(dict(plan, name=name))
            continue
        prov = provenance.get(name)
        # 「这个值来自前序响应」本身就是可变性知识 —— 这种参数**绝不烘快照**
        # （烘的是那一次会话的值，很快失效）；取用不了就退必填，让调用方给新的。
        suspected = value_is_response_derived(prov)
        if not suspected:
            default = _stable_default_value(name, values, evidence.get(name))
            # 只有**非空**的默认值才算烘得进去：空串在 `_cfg` 构造时会被当「空值参数」
            # 丢掉（Step 2），留着它会让这个参数从请求里凭空消失。空值一样按 (b) 处理，
            # 由调用方决定要发什么。
            if default:
                baked[name] = default
                continue
        ident = _unique_ident(_py_ident(name), taken_idents)
        taken_idents.add(ident)
        env = _unique_ident(_login_query_env(prefix, name), taken_envs)
        taken_envs.add(env)
        entry: dict[str, Any] = {"name": name, "ident": ident, "env": env, "why": None}
        if suspected:
            # 来源确定、但这次不能自动取用时，把原因一并带给调用方（docstring / README）。
            entry["why"] = str(prov.get("note") or "") or None
        required.append(entry)
    return {"baked": baked, "required": required, "fetched": fetched}


def _render_auth_login_tools(auth_login: dict, prefix: str) -> str:
    """生成 login / auth_status 工具。

    凭据来源优先级：调用参数 > 环境变量 > 加密缓存。密码用于换取 token，并随凭据一起
    加密缓存（Windows DPAPI，见文件末尾说明）；审计日志只记录脱敏账号与加密策略。

    登录接口的 query 参数分三类（见 `_login_query_plan`）：无害固定参数照旧烘默认值；
    值来自公共响应接口的**发射取用代码**（运行时先取后用，使用者什么都不用填）；其余是
    「取值来源未能确认」的参数 —— 它们**不进必填位**（带默认值 None，不填也能进入函数体，
    否则参数绑定阶段就 `TypeError`，弹窗那条路根本走不到），运行时按
    **调用方入参 → .env → 原生弹窗询问 → 明确报错并点名缺哪个** 取值；401 自动重登录
    拿不到工具入参，只能走 .env，缺失时照样大声报错而不是静默跳过。
    """
    acct, pwd = auth_login["account_field"], auth_login["password_field"]
    tpath = ".".join(auth_login["token_path"])
    # 校验接口（auth_login["verify"] = {host, path}，analyzer 生成）在 render_server
    # 里摊平成 _AUTH_LOGIN_CFG['verify_host'/'verify_path'] 后才进了生成物 —— 见那里的注释。
    plan = _login_query_plan(auth_login, prefix)
    required = plan["required"]
    fetched = plan["fetched"]
    # 「取值来源未能确认」的 query 参数：**关键字限定、但带默认值 None**。
    # 关键字限定是为了不顶掉 account/password 的位置语义（也不能排在其后 ——
    # `x=None, y: str` 直接 SyntaxError）。默认值必须是 None：**不填也要能进入函数体**，
    # 否则参数绑定阶段就 `TypeError: missing 1 required keyword-only argument`，
    # 「弹窗问账号密码（口令不进对话）」那条路在这类站点上完全走不到 —— 正是本次要修的。
    # 取用型参数**不进签名** —— 服务自己会取，给调用方多一个入参只会让人以为「必须填」。
    login_signature = ("async def login(account: str | None = None, password: str | None = None")
    if required:
        login_signature += ", *" + "".join(
            f", {item['ident']}: str | None = None" for item in required)
    login_signature += ") -> dict:"
    # 生成物里 `_do_login` 取值：入参 → .env → 报错（绝不退回抓包值）；取用型先去取。
    needs_params = bool(required or fetched)
    do_login_params = ""
    params_expr = "cfg['query_params']"
    if needs_params:
        params_expr = "params"
        do_login_params = "\n".join([
            "    params = dict(cfg.get('query_params') or {})",
            *(["    # (a) 取用型：值来自公共、无鉴权、无参数的 GET 响应 —— **不烘快照**，",
               "    # 运行时先去来源接口取。这条路径刻意**不走 `_request`**：它 401 会自动",
               "    # 重登录，而这里正在重登录链路内部，走它会递归。"] if fetched else []),
            *(["    params.update(await _fetch_login_query_values())"] if fetched else []),
            *(["    # 以下 query 参数在抓包里的取值来源未能确认，**没有**烘进代码：",
               "    # 取值优先 调用方入参 > .env > 报错。缺失时**大声**失败——401 自动重登录",
               "    # 拿不到工具入参，只能走 .env；静默跳过重登录会让调用方以为「重登录没用」。"]
              if required else []),
            *(["    _missing = []",
               "    for _name, _env in (cfg.get('login_query_params') or {}).items():",
               "        _value = (login_query or {}).get(_name)",
               "        if _value in (None, ''):",
               "            _value = os.environ.get(_env, '')",
               "        if _value in (None, ''):",
               "            _missing.append(_env)",
               "        else:",
               "            params[_name] = _value",
               "    if _missing:",
               "        _log_error('login missing required query param env: ' + ', '.join(_missing))",
               "        raise RuntimeError(",
               "            '登录接口的 query 参数取值来源未能确认（未烘入代码），必须由调用方提供；'",
               "            '401 自动重登录请在 .env 配置：' + ', '.join(_missing))"] if required else []),
            "",
        ])
    login_note = ""
    login_call = "await _do_login(acct, pwd)"
    if fetched or required:
        login_note = "\n".join([
            "",
            *[f"    `{_doc_escape(item['name'])}`：本工具会**自动获取**它 —— 先调来源接口 "
              f"`GET {_doc_escape(item['url'])}`，取响应字段 "
              f"`{_doc_escape(item.get('field_display') or '')}`，再用于登录；无需传参。"
              for item in fetched],
            *[f"    `{_doc_escape(item['ident'])}`：本参数的取值**来源未知**"
              + (f"（{_doc_escape(item['why'])}）" if item.get("why") else "")
              + "；为避免把抓包当时的取值烘进代码，不烘默认值。**不填也能调用**："
              "会依次尝试 调用入参 → .env → 本机弹窗询问；都取不到才明确报错并点名缺的是哪个。"
              f"（401 自动重登录不经过入参，请在 .env 配置 `{_doc_escape(item['env'])}`。）"
              for item in required],
        ])
    if required:
        login_call = "await _do_login(acct, pwd, login_query)"

    # (a) 取用型：来源接口地址、方法与响应字段路径**全部经 json.dumps 发射**（抓包内容
    # 只当字符串，不拼进源码）。计划为空时整段不发射 → 其它 registry 的产物逐字节不变。
    fetch_helpers: list[str] = []
    if fetched:
        fetch_literal = json.dumps(
            [{key: item[key] for key in ("name", "method", "url", "field")}
             for item in fetched], ensure_ascii=False)
        fetch_helpers = [
            "# 登录 query 参数的「取用计划」：来源是公共、无鉴权、无参数的 GET。",
            "_LOGIN_FETCH = " + fetch_literal,
            "",
            "",
            "def _dig_path(obj: Any, path: list) -> Any:",
            '    """按注册时记录的字段路径取值：字典按 key、列表按下标；取不到返回 None。"""',
            "    for key in path:",
            "        if isinstance(obj, dict):",
            "            obj = obj.get(key)",
            "        elif isinstance(obj, list) and isinstance(key, int) and 0 <= key < len(obj):",
            "            obj = obj[key]",
            "        else:",
            "            return None",
            "    return obj",
            "",
            "",
            "async def _fetch_login_query_values() -> dict:",
            '    """登录前自动取用：调来源接口取出登录 query 参数的值（先取后用）。',
            "",
            "    这些值在抓包里就是从**公共、无鉴权、无参数**的响应里取出来的（每次会话",
            "    都可能不同），所以不烘快照。刻意**不走 `_request`**：`_request` 在 401 时",
            "    会触发自动重登录，而这里正处在重登录链路内部 —— 走它会递归。",
            '    """',
            "    values = {}",
            "    for item in _LOGIN_FETCH:",
            "        try:",
            "            async with httpx.AsyncClient(timeout=TIMEOUT) as client:",
            "                resp = await client.request(item['method'], item['url'])",
            "            if resp.status_code >= 400:",
            "                raise RuntimeError('HTTP ' + str(resp.status_code))",
            "            value = _dig_path(resp.json(), item['field'])",
            "        except Exception as exc:",
            "            _log_error('login query fetch failed: ' + item['name']",
            "                       + ' from ' + item['url'])",
            "            raise RuntimeError(",
            "                '登录需要的一个参数（' + item['name'] + '）本应自动从 '",
            "                + item['url'] + ' 取到，但这次没有取到。'",
            "                '请让用户重新抓一次包，再用新的抓包重新生成这个服务。') from exc",
            "        if value in (None, ''):",
            "            _log_error('login query fetch empty: ' + item['name'])",
            "            raise RuntimeError(",
            "                '登录需要的一个参数（' + item['name'] + '）本应自动从 '",
            "                + item['url'] + ' 取到，但对方这次返回的是空值。'",
            "                '请让用户重新抓一次包，再用新的抓包重新生成这个服务。')",
            "        values[item['name']] = str(value)",
            "    return values",
            "",
            "",
        ]

    # (b') 「取值来源未能确认」的参数：工具层（有图形会话、能弹窗）的取值链 ——
    # 入参 → .env → 原生弹窗 → 明确报错。名字 / env 名 / 入参变量名全部**经 json 发射**
    # （抓包内容只当字符串）；没有这类参数时整段不发射 → 其它 registry 的产物逐字节不变。
    query_helpers: list[str] = []
    login_body_inputs: list[str] = []
    if required:
        # [参数名(wire key, repr), .env 名(repr), 该次调用的入参**变量**]。第三项是变量
        # 引用而不是字符串 —— 抓包里观测到的名字经 repr 当字符串，`ident` 是生成器自己
        # 切出来的合法标识符（`_unique_ident` 保证不与 account/password 撞名）。
        inputs_literal = "[" + ", ".join(
            f"({item['name']!r}, {item['env']!r}, {item['ident']})" for item in required) + "]"
        secrets_literal = json.dumps(
            [item["name"] for item in required if _looks_secret_name(item["name"])],
            ensure_ascii=False)
        query_helpers = [
            "# 名字像密码 / 令牌 / 密钥的参数，弹窗里用掩码输入（口令不进对话、不进日志）。",
            "_LOGIN_SECRET_PARAMS = " + secrets_literal,
            "",
            "",
            "def _ask_login_query_params(names):",
            '    """本机弹窗逐个询问缺失的登录 query 参数；弹不出窗口或用户取消 → None。',
            "",
            "    取值只留在内存里：不进对话、不进日志、不进任何返回值。名字像密码 / 令牌 /",
            "    密钥的参数用**掩码输入**（同密码框）。本函数会**阻塞**，故由 _run_native 放到",
            "    **守护**线程上执行（用户不作答也不会拖住进程退出）。",
            '    """',
            "    try:",
            "        import tkinter as tk",
            "        from tkinter import simpledialog",
            "    except Exception:",
            "        return None",
            "    try:",
            "        root = tk.Tk()",
            "        root.withdraw()",
            "        root.attributes('-topmost', True)",
            "        try:",
            "            _values = {}",
            "            for _name in names:",
            "                _secret = _name in _LOGIN_SECRET_PARAMS",
            "                _answer = simpledialog.askstring(",
            "                    '登录',",
            "                    '登录还需要「' + _name + '」' + ('（不会显示）：' if _secret else '：'),",
            "                    parent=root, show='*' if _secret else None)",
            "                if _answer is None:",
            "                    return None",
            "                _answer = _answer.strip()",
            "                if _answer:",
            "                    _values[_name] = _answer",
            "        finally:",
            "            root.destroy()",
            "    except Exception:",
            "        return None",
            "    return _values",
            "",
            "",
        ]
        # 工具层取值链。放在 `_do_login` 之前（凭证之后）：不直接报错，先弹窗问用户。
        # `_inputs` 的第三项是**入参变量本身**（不是字符串），故必须写在函数体内。
        login_body_inputs = [
            "    login_query = {}",
            "    _inputs = " + inputs_literal,
            "    _missing = []",
            "    for _name, _env, _value in _inputs:",
            "        if _value in (None, ''):",
            "            _value = os.environ.get(_env, '')",
            "        if _value in (None, ''):",
            "            _missing.append(_name)",
            "        else:",
            "            login_query[_name] = _value",
            "    if _missing:",
            "        # 不直接报错：先在本机弹窗问用户要这几个参数（口令/令牌掩码输入）。",
            "        _asked = await _run_native(lambda: _ask_login_query_params(_missing))",
            "        if _asked:",
            "            login_query.update(_asked)",
            "        _missing = [_name for _name, _env, _value in _inputs",
            "                    if _name not in login_query]",
            "    if _missing:",
            "        # 弹不出窗口 / 用户取消 / 取消后仍没填 → 明确报错并**点名**缺的是哪个参数。",
            "        _envs = [_env for _name, _env, _value in _inputs if _name in _missing]",
            "        _log_error('login missing query params: ' + ', '.join(_envs))",
            "        return {'success': False, 'error': 'missing_login_query_params',",
            "                'missing_params': list(_missing),",
            "                'message': ('登录还需要以下参数，但没能取得：' + '、'.join(_missing)",
            "                            + '。请在弹窗里填写，或在 .env 里配置 ' + '、'.join(_envs)",
            "                            + '；也可以让 Agent 重新抓一次包后重新生成这个服务。')}",
        ]

    lines = [
        "",
        "# --------------------------------------------------------------------------- #",
        "# 登录（账号密码换取 token）",
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
        "def _cache_probe(path) -> str:",
        '    """区分「文件不在」与「文件在、但解不开」（只读，绝不抛异常）。',
        "",
        "    `_cache_load` 对这两种情况都返回 None —— 读不到凭据只意味着「需要重新登录」，",
        "    但对**用户**来说出路完全不同：文件不在 = 这台机器上还没登录过；文件在却解不开",
        "    = 换了电脑 / 换了 Windows 登录用户（DPAPI 的密钥不同，密文再也解不开）。",
        "    把区别显式做出来，好让 login() / auth_status() / 401 报错给出可行动的下一步。",
        '    """',
        "    if not _DPAPI_OK or not path.exists():",
        '        return "missing"',
        "    try:",
        "        import base64 as _b64",
        '        json.loads(_dpapi_unprotect(_b64.b64decode(path.read_text(encoding="ascii"))))',
        "    except Exception:",
        '        return "unreadable"',
        '    return "ok"',
        "",
        "",
        "def _login_recovery_hint() -> str:",
        '    """凭据出问题时给**非技术用户**的一句出路（面向「完全不懂 HTTP」的人）。',
        "",
        "    两种情形、两种说法：缓存解不开 → 删掉 cred_cache.bin 再登一次；缓存正常但登录",
        "    仍失败（多半是口令被改了）→ 重新登录一次即可。**绝不**自动反复重试登录。",
        '    """',
        '    if _cache_probe(CRED_CACHE) == "unreadable":',
        '        return ("检测到本项目保存的凭据文件（" + CRED_CACHE.name + "）解不开，"',
        '                "通常是因为换了电脑或换了 Windows 登录用户。"',
        '                "删掉项目里的 " + CRED_CACHE.name + "，再调用 login() 登录一次即可。")',
        '    return "如果账号或口令已经变更，请调用 login()（无参数时会弹窗向你询问一次）重新登录。"',
        "",
        "",
        "def _ask_credentials_native():",
        '    """本机弹窗问**一次**「账号 + 掩码密码」；弹不出（无图形环境）或用户取消 → None。',
        "",
        "    生成的服务是 stdio 的 MCP 服务，**没有控制台**可读，只能弹原生窗口。用标准库",
        "    tkinter（Windows/macOS 自带）：密码框用 show='*' 掩码，口令只留在内存里——",
        "    不进对话、不进日志、不进任何返回值。本函数会**阻塞**，故由 _run_native 放到",
        "    守护线程上执行（用户不作答也不会拖住进程退出）。",
        '    """',
        "    try:",
        "        import tkinter as tk",
        "        from tkinter import simpledialog",
        "    except Exception:",
        "        return None",
        "    try:",
        "        root = tk.Tk()",
        "        root.withdraw()",
        "        root.attributes('-topmost', True)",
        "        try:",
        "            account = simpledialog.askstring('登录', '请输入账号：', parent=root)",
        "            if account is None:",
        "                return None",
        "            password = simpledialog.askstring('登录', '请输入密码（不会显示）：',",
        "                                              parent=root, show='*')",
        "            if password is None:",
        "                return None",
        "        finally:",
        "            root.destroy()",
        "    except Exception:",
        "        return None",
        "    account = (account or '').strip()",
        "    if not account or not password:",
        "        return None",
        "    return account, password",
        "",
        "",
        "async def _run_native(function):",
        '    """把阻塞的原生弹窗放到**守护**线程上执行并 await 结果。',
        "",
        "    不用 asyncio.to_thread：默认 executor 的线程不是守护线程，用户不作答时会把",
        "    进程拖住不退出。这里手工起守护线程（与技能侧 dialog.py 同一约定）。",
        '    """',
        "    import asyncio",
        "    import threading",
        "    loop = asyncio.get_running_loop()",
        "    future = loop.create_future()",
        "",
        "    def worker():",
        "        try:",
        "            result = function()",
        "        except Exception:",
        "            result = None",
        "        try:",
        "            loop.call_soon_threadsafe(",
        "                lambda: None if future.done() else future.set_result(result))",
        "        except RuntimeError:",
        "            pass  # 事件循环已关闭，没人再等这个结果",
        "",
        "    threading.Thread(target=worker, daemon=True, name='wae-login-dialog').start()",
        "    return await future",
        "",
        "",
        "def _plaintext_env_used() -> bool:",
        '    """`.env` 里是否**仍有**明文账号密码（登录成功后提示删掉，但绝不代改文件）。',
        "",
        "    静默修改用户的文件比多留一行明文更糟：这里只读、只提示，`.env` 的**读取**",
        "    通道照旧保留（旧配置仍能用，只是不再推荐）。",
        '    """',
        "    return bool(os.environ.get('" + prefix + "_ACCOUNT')",
        "                and os.environ.get('" + prefix + "_PASSWORD'))",
        "",
        "",
        "def _cache_save_checked(path, obj) -> bool:",
        '    """写加密缓存并**回读**验证：返回是否真的落盘可用。',
        "",
        "    `_cache_save` 会把写失败吞掉（缓存问题不该中断登录），所以这里不能",
        "    假设它成功。回读得到内容才算「重启能恢复」；否则写一条 error.log，",
        "    并把结果如实报给调用方 —— 否则用户会以为凭据已保存，直到下次 401 才发现。",
        '    """',
        "    _cache_save(path, obj)",
        "    ok = _cache_load(path) is not None",
        "    if not ok:",
        "        _log_error(f'credential cache not saved: {path.name}')",
        "    return ok",
        "",
        "",
        *fetch_helpers,
        *query_helpers,
        "async def _do_login(account: str, password: str"
        + (", login_query: dict | None = None" if required else "") + ") -> dict:",
        '    """调用登录接口换取 token，成功则写入进程内存。"""',
        "    global RUNTIME_TOKEN",
        "    cfg = _AUTH_LOGIN_CFG",
        *([do_login_params] if needs_params else []),
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
        # 烘入的固定参数 + 调用方/env 传入的 (b) 类参数，在这里合成一份（`params`
        # 只在上面的分支里存在；无 (b) 类参数时表达式与修复前逐字节一致）。
        "                                    params=_clean(" + params_expr + ") or None,",
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
        "    token_saved = _cache_save_checked(TOKEN_CACHE, {'token': RUNTIME_TOKEN, 'saved_at': int(time.time())})",
        "    cred_saved = _cache_save_checked(CRED_CACHE, {'account': account, 'password': password})",
        "    _audit('login', {'host': cfg['host'], 'account': _mask(account), 'ok': True})",
        "    result = {'success': True, 'account': _mask(account),",
        "              'token_cache': 'saved' if token_saved else 'not_saved',",
        "              'credential_cache': 'saved' if cred_saved else 'not_saved'}",
        "    if not (token_saved and cred_saved):",
        "        # 缓存失败必须**可见**：README 承诺「重启自动恢复」，静默吞掉会让",
        "        # 调用方以为重启后仍是登录态，直到下一次 401 才发现凭据从未保存。",
        "        result['message'] = ('登录成功，但凭据/token 未能写入加密缓存：仅本次进程内有效，'",
        "                             '重启后需重新 login（原因见 error.log）。')",
        "    return result",
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
        login_signature,
        '    """登录并获取访问 token。',
        "",
        "    **无参数调用 `login()` 时，会在你这台电脑上弹出一个输入窗口，问你一次账号与**",
        "    **密码**（密码是掩码输入）—— 敲一次即可，不需要任何配置文件。也可以在调用时",
        "    直接传入 `account=... / password=...`。",
        "    **给 Agent**：弹窗会打断用户，请**先征得用户同意**再调用无参 `login()`；",
        "    用户同意后调用它，再把结果如实告诉用户。",
        *(["    （若登录接口另有 query 参数且取不到值，`login()` 还会弹窗问一次那几个参数 ——",
           "    同样先征得用户同意；用户取消时会返回 `missing_login_query_params` 并点名缺哪个。）"]
          if required else []),
        "    凭据优先级：入参 > .env（旧配置的兼容通道，仍可读）> DPAPI 加密缓存。",
        "    口令只用于换取 token 并加密落盘，**绝不会**出现在返回内容、对话或日志里。",
        "    成功后 token 加密持久化，重启服务自动恢复，无需重复登录。",
        "    若这台机器弹不出窗口（没有图形环境）或用户取消，会返回 `missing_credentials`：",
        "    那时请在对话里把账号密码告诉 Agent，由它带参调用 `login(account=..., password=...)`。",
        *([login_note] if (fetched or required) else []),
        '    """',
        "    acct = (account or os.environ.get('" + prefix + "_ACCOUNT', '')).strip()",
        "    pwd = password or os.environ.get('" + prefix + "_PASSWORD', '')",
        "    if not acct or not pwd:",
        "        creds = _cached_credentials()",
        "        if creds:",
        "            acct, pwd = creds",
        "    if (not acct or not pwd) and account is None and password is None:",
        "        # 「一次输入」：无参且无可用缓存时，在本机弹窗问一次（口令掩码输入、不进对话）。",
        "        asked = await _run_native(_ask_credentials_native)",
        "        if asked:",
        "            acct, pwd = asked",
        "    if not acct or not pwd:",
        "        _state = _cache_probe(CRED_CACHE)",
        "        _fallback = ('请在对话里把账号与密码告诉 Agent，由它调用 login(account=..., '",
        "                     'password=...) 传入。')",
        "        if _state == 'unreadable':",
        "            _message = ('本项目保存的凭据文件（' + CRED_CACHE.name + '）解不开——通常是因为'",
        "                        '换了电脑或换了 Windows 登录用户。请删掉项目里的 ' + CRED_CACHE.name",
        "                        + '，再调用 login() 登录一次即可（' + _fallback + '）')",
        "        else:",
        "            _message = '未提供账号密码，且本机弹不出输入窗口。' + _fallback",
        "        return {'success': False, 'error': 'missing_credentials',",
        "                'credentials_cache_state': _state, 'message': _message}",
        *login_body_inputs,
        "    result = " + login_call,
        "    if result.get('success') and _plaintext_env_used():",
        "        # Step 4a：`.env` 明文的读取通道保留（逃生门），但这里做**一次性、非阻塞**的",
        "        # 提示 —— 只提示、绝不代改用户的 .env（静默改别人的文件更糟）。",
        "        _notice = " + json.dumps(
            "检测到项目里的 .env 仍写着明文账号密码（已改用加密缓存保存）；"
            f"为避免明文留在磁盘上，可以把 .env 里的 {prefix}_ACCOUNT / "
            f"{prefix}_PASSWORD 两行删掉。", ensure_ascii=False),
        "        result['plaintext_env_notice'] = _notice",
        "        result['message'] = (result.get('message', '') + ' ' + _notice).strip()",
        "    return result",
        "",
        "",
        "@mcp.tool()",
        "async def auth_status() -> dict:",
        '    """检查当前鉴权状态：token 来源与有效性（只读，不触发登录）。"""',
        "    src = ('cache/login' if RUNTIME_TOKEN and _cache_load(TOKEN_CACHE) else",
        "           'runtime(login)' if RUNTIME_TOKEN else",
        "           ('env(" + prefix + "_TOKEN)' if TOKEN else 'none'))",
        "    cred_state = _cache_probe(CRED_CACHE)",
        "    info = {'has_token': bool(_current_token()), 'token_source': src,",
        "            'login_tool_available': bool(_AUTH_LOGIN_CFG),",
        "            'credentials_in_env': bool(os.environ.get('" + prefix + "_ACCOUNT')",
        "                                       and os.environ.get('" + prefix + "_PASSWORD')),",
        "            'credentials_cached_encrypted': cred_state == 'ok',",
        "            'credentials_cache_state': cred_state,",
        "            'token_cache_state': _cache_probe(TOKEN_CACHE)}",
        "    if cred_state == 'unreadable':",
        "        # 如实回答「保存的凭据解不开」，并直接给出可行动的下一步（换电脑/换用户后必然如此）。",
        "        info['credentials_cache_hint'] = _login_recovery_hint()",
        "    cfg = _AUTH_LOGIN_CFG",
        "    verify_host = (cfg or {}).get('verify_host')",
        "    verify_path = (cfg or {}).get('verify_path')",
        "    if not info['has_token']:",
        "        # 无 token 时不必发探针——那必然 401，徒增日志噪音；也不能谎称「已验证」。",
        "        info['verified'] = None",
        "        info['verify_detail'] = '未登录：当前进程没有可用 token，未做校验探针。'",
        "        return info",
        "    if not (verify_host and verify_path):",
        "        # 抓包没记录校验接口时必须**如实**回答：「本次没能力验证」而不是「已验证」。",
        "        info['verified'] = None",
        "        info['verify_detail'] = '本次抓包没有记录可用于校验的接口，无法验证 token 是否仍有效。'",
        "        return info",
        "    try:",
        "        await _request(verify_host, 'GET', verify_path)",
        "        info['verified'] = True",
        "        info['verify_detail'] = 'ok'",
        "    except Exception as exc:",
        "        info['verified'] = False",
        "        info['verify_detail'] = f'{type(exc).__name__}: {exc}'",
        "    return info",
    ]
    text = "\n".join(lines)
    text = text.replace(
        "        resp = await client.request(cfg['method'], cfg['path'], tmp_placeholder\n",
        "        resp = await client.request(cfg['method'], cfg['path'],\n")
    return text


# --------------------------------------------------------------------------- #
# 只能交互式登录的站点：发射**交互式登录**（真实浏览器窗口 + 用户确认）
#
# 判据是 `auth_login["post_login"]["verdict"] == "interactive"`（见 analyzer 的两层
# 判据）。被这么判的站点上，账号密码 + 401 自动重登录这套代码**必然失败**：抓包与实测
# 都表明登录需要人工参与（验证码 / 短信 / 二次验证 / 无法复现的前端加密口令）。
# 此前的产物照旧发射 `login()`，于是「假装有 401 自动重登录」——用户以为配好凭据就能
# 自动续期，实际每次过期都得回技能侧重来。现在改为**自带**交互式登录：
#
#   * 拉起**真实浏览器窗口**（stdio 的 MCP 没有控制台，只能弹原生窗口）；
#   * 验证码 / 短信 / SSO 全部由**用户本人**完成；
#   * 服务只**轮询 + 报告旁证**，完成一律由用户确认（`confirm_login()`），
#     **绝不自动判定** —— 技能侧在 auth.py 记过这次事故：自动放行会在用户还在输密码
#     时就把会话判成完成并关掉浏览器；
#   * playwright 写进 `requirements.txt`（**钉死版本**，内核按版本缓存）并在 MCP
#     初始化时**尽力自动安装**，用户不需要自己 pip install。
# --------------------------------------------------------------------------- #
def _render_interactive_login_tools(auth_login: dict, prefix: str) -> str:
    """发射交互式登录的三个工具（登录 / 查状态 / 用户确认）与配套助手。

    ``auth_login`` 只用来取登录页所在的 host（浏览器要打开的那个地址）。host 来自抓包
    （不可信）→ 经 ``json.dumps`` 当**字符串字面量**发射；代码里只用它做 `HOSTS` 的键
    去查（``HOSTS.get(_LOGIN_HOST)``），绝不把它拼进源码结构里。
    """
    login_host = json.dumps(str(auth_login.get("host") or ""), ensure_ascii=False)
    return _INTERACTIVE_LOGIN_BLOCK.replace("__LOGIN_HOST__", login_host).replace(
        "__PREFIX__", prefix).replace("__PIN__", _PLAYWRIGHT_PIN)


_INTERACTIVE_LOGIN_BLOCK = '''# --------------------------------------------------------------------------- #
# 交互式登录（这个站点**无法**用构造请求登录）
#
# 抓包 + 实测的结论：登录需要人工参与（验证码 / 短信 / 二次验证 / SSO / 无法复现的
# 前端加密口令）。因此这里**没有** `login()` / `_do_login()`，也**不会**假装能 401
# 自动重登录 —— 那套代码在这种站点上必然失败，只会让人以为「配好凭据就能自动续期」。
#
# 完成一律由**用户确认**：服务只轮询并报告旁证（`auth_evidence`），绝不自动放行。
# --------------------------------------------------------------------------- #
import asyncio

_PLAYWRIGHT_PIN = "__PIN__"          # 与浏览器内核修订号绑定（chromium-1243）
_AUTH_STATE = _HERE / "auth_state.json"
# 登录页地址取自 HOSTS（host 来自抓包，经 json 字面量发射，只当**键**用，不拼进代码结构）。
_LOGIN_HOST = __LOGIN_HOST__
_LOGIN_URL = str(HOSTS.get(_LOGIN_HOST) or "") + "/"
_INTERACTIVE: dict = {"session_id": 0, "status": "idle", "detail": "",
                      "auth_evidence": False}


def _install_playwright() -> bool:
    """确保 playwright 可导入；缺了就**尽力**装一次（版本已钉死）。

    在 MCP 初始化时调用一次：用户拿到的应该是一个直接能用的服务，不该还需要自己去
    `pip install`。失败只写 error.log 并返回 False —— 绝不因此让服务起不来（业务工具
    照旧可用，只是登录窗口打不开）。
    """
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        pass
    try:
        import subprocess
        subprocess.run([sys.executable, "-m", "pip", "install",
                        "--disable-pip-version-check", "-q",
                        "playwright==" + _PLAYWRIGHT_PIN],
                       timeout=600, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as exc:
        _log_error("playwright install failed: " + type(exc).__name__)
    try:
        import playwright  # noqa: F401
        return True
    except Exception as exc:
        _log_error("playwright unavailable: " + type(exc).__name__)
        return False


def _install_chromium() -> bool:
    """浏览器内核缺失时补装一次（内核与 playwright 版本绑定）。"""
    try:
        import subprocess
        subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"],
                       timeout=900, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception as exc:
        _log_error("chromium install failed: " + type(exc).__name__)
        return False


def _prepare_playwright_in_background() -> None:
    """模块导入（= MCP 初始化）时在**守护线程**里预装一回，不阻塞启动握手。"""
    import threading
    threading.Thread(target=_install_playwright, daemon=True,
                     name="wae-playwright").start()


def _load_auth_state() -> dict:
    try:
        data = json.loads(_AUTH_STATE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _cookies_from_auth_state(host: str) -> dict:
    """登录态文件里属于该 host 的 Cookie（{名: 值}）—— 交互式登录的产物。

    域名按**后缀**匹配（`.example.com` 覆盖 `crm.example.com`），与浏览器行为一致。
    Cookie 值因此不必手工粘进 .env。
    """
    target = str(host or "").split(":")[0].lower()
    jar: dict = {}
    cookies = _load_auth_state().get("cookies")
    if not isinstance(cookies, list):
        return jar
    for cookie in cookies:
        if not isinstance(cookie, dict):
            continue
        name, value = cookie.get("name"), cookie.get("value")
        domain = str(cookie.get("domain") or "").lstrip(".").lower()
        if not name or value is None or not domain:
            continue
        if target == domain or target.endswith("." + domain):
            jar[str(name)] = str(value)
    return jar


def _login_evidence(cookies: list, baseline: dict) -> bool:
    """旁证：登录后**新增或值变化**的凭据类 Cookie（相对刚打开登录页时的基线）。

    只用来提示「看起来已经登录了，请确认」，**不驱动任何状态流转** —— 登录页自己就会
    下发 JSESSIONID 这类会话 Cookie，只看「有没有」必然误判。
    """
    for cookie in cookies or []:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get("name") or "").lower()
        key = (cookie.get("name"), cookie.get("domain"), cookie.get("path"))
        if any(mark in name for mark in ("token", "session", "sid", "auth")):
            if baseline.get(key) != cookie.get("value"):
                return True
    return False


async def _interactive_worker(session_id: int) -> None:
    """拉起浏览器窗口等用户登录；**只观察，不判定**（完成由 confirm_login 落定）。"""
    _INTERACTIVE.update(status="waiting", detail="", auth_evidence=False)
    try:
        from playwright.async_api import async_playwright
    except Exception as exc:
        if not _install_playwright():
            _INTERACTIVE.update(status="unavailable",
                                detail="playwright 没能装好（详见 error.log）")
            return
        try:
            from playwright.async_api import async_playwright
        except Exception as exc:      # noqa: BLE001
            _INTERACTIVE.update(status="unavailable",
                                detail="playwright 导入失败：" + type(exc).__name__)
            return
    try:
        async with async_playwright() as pw:
            try:
                browser = await pw.chromium.launch(headless=False)
            except Exception as exc:
                _log_error("chromium launch failed: " + type(exc).__name__)
                if not _install_chromium():
                    _INTERACTIVE.update(status="unavailable",
                                        detail="浏览器内核不可用，且自动安装失败")
                    return
                browser = await pw.chromium.launch(headless=False)
            _INTERACTIVE["browser"] = browser
            try:
                # 自签名证书的内网站点是常态：不放开校验，登录页根本打不开。
                context = await browser.new_context(ignore_https_errors=True, no_viewport=True)
                page = await context.new_page()
                await page.goto(_LOGIN_URL, wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_timeout(2000)
                baseline = {(c.get("name"), c.get("domain"), c.get("path")): c.get("value")
                            for c in await context.cookies()}
                while _INTERACTIVE.get("session_id") == session_id \\
                        and _INTERACTIVE.get("status") == "waiting":
                    try:
                        if page.is_closed():
                            _INTERACTIVE.update(
                                status="browser_closed",
                                detail="浏览器窗口被关掉了，请重新调用 login_interactive()")
                            return
                        _INTERACTIVE["auth_evidence"] = _login_evidence(
                            await context.cookies(), baseline)
                    except Exception:
                        pass
                    await asyncio.sleep(1)
                if _INTERACTIVE.get("status") == "confirmed":
                    await context.storage_state(path=str(_AUTH_STATE))
                    _INTERACTIVE["status"] = "saved"
                    _audit("interactive_login", {"host": _LOGIN_HOST, "saved": True})
            finally:
                await browser.close()
    except Exception as exc:
        _INTERACTIVE.update(status="failed",
                            detail=type(exc).__name__ + ": " + str(exc)[:200])


@mcp.tool()
async def login_interactive() -> dict:
    """打开一个真实浏览器窗口，让你本人完成这个网站的登录。

    什么时候用：这个站点的登录带验证码 / 短信 / 二次验证（或前端加密口令无法复现），
    服务**无法**用账号密码自动登录，也**不会**自动续期。

    怎么用（给 Agent）：调用后**立即返回**。请把下面的话原样转告用户：
    「已经为你打开了登录窗口，请在弹出的浏览器里完成登录（验证码 / 短信验证都由你本人
    完成）。登录好了告诉我一声。」用户答复已登录后，再调用 `confirm_login()` 保存登录态。
    **不要**自行判定登录是否完成 —— 本服务只给旁证（`get_login_status()`），
    保存与否由用户确认。
    """
    if _INTERACTIVE.get("status") == "waiting":
        return {"success": True, "status": "waiting",
                "message": "登录窗口还开着。请用户先在那个窗口里完成登录，"
                           "登录好了再调用 confirm_login()。"}
    _INTERACTIVE["session_id"] = int(_INTERACTIVE.get("session_id") or 0) + 1
    session_id = _INTERACTIVE["session_id"]
    _INTERACTIVE.update(status="starting", detail="")
    asyncio.create_task(_interactive_worker(session_id))
    return {"success": True, "status": "starting",
            "message": "已打开登录窗口。请让用户在**浏览器窗口**里完成登录"
                       "（验证码 / 短信 / 二次验证都由用户本人完成）；登录完成后先问用户"
                       "一句「登录好了吗」，得到肯定答复再调用 confirm_login() 保存。"}


@mcp.tool()
async def get_login_status() -> dict:
    """查看交互式登录的状态（只读，不触发任何登录动作）。

    `auth_evidence` 只是旁证（登录后新增的凭据类 Cookie）。它变成 True **不代表**登录
    完成 —— 完成一律由用户在对话里确认后调用 confirm_login() 落定。
    """
    return {"status": _INTERACTIVE.get("status"),
            "detail": _INTERACTIVE.get("detail", ""),
            "auth_evidence": bool(_INTERACTIVE.get("auth_evidence")),
            "auth_state_saved": _AUTH_STATE.exists()}


@mcp.tool()
async def confirm_login() -> dict:
    """用户在对话里确认「已经登录好了」之后调用 —— 保存登录态（auth_state.json）。

    调用本工具**等于**替用户确认登录完成，所以必须先问过用户、拿到肯定答复。
    保存之后，本服务的工具会自动带上这份登录态；若返回的 status 不是 saved，
    请把 message 原样转告用户。
    """
    if _INTERACTIVE.get("status") == "waiting":
        _INTERACTIVE["status"] = "confirmed"
        return {"success": True, "status": "saving",
                "message": "正在保存登录态，稍后可用 get_login_status() 看 "
                           "status=saved（已保存）。"}
    if _AUTH_STATE.exists():
        return {"success": True, "status": "saved", "auth_state": str(_AUTH_STATE),
                "message": "登录态已保存，现在可以直接调用业务工具了。"}
    return {"success": False, "status": _INTERACTIVE.get("status"),
            "message": "现在没有等待确认的登录窗口。请先调用 login_interactive()，"
                       "在弹出的窗口里完成登录，再调用 confirm_login()。"}


_prepare_playwright_in_background()'''


# 401 报错里那句「下一步该做什么」的两种取值（模板里的 `__LOGIN_HINT__`）。
# 「账号密码登录」那句与修复前**逐字相同** —— 非交互式产物因此只有 `.env` 指路那句
# 因本次修复而变化（见 `_auth_failure_env_hint`）。
_POST_LOGIN_401_HINT = " 可调用 login(account=..., password=...) 登录；或在 .env 配置凭据。"
_INTERACTIVE_401_HINT = (
    " 这个站点的登录要人工完成（验证码 / 二次验证），**不会自动重登录**："
    "请让 Agent 调用 login_interactive()，在弹出的浏览器窗口里自己登录一次，"
    "登录好后让 Agent 调用 confirm_login() 保存。")


def _auth_failure_env_hint(prefix: str, cookie_hosts: dict, token_hosts: set,
                           basic_hosts: list) -> str:
    """401 报错里那句「请检查 .env 中的 X」—— 必须与 `.env.example` **同一份事实**。

    修复前这里硬写 ``<PREFIX>_TOKEN``，而纯 Cookie 站点的 `.env.example` 里根本没有
    这一行（它给的是 `<PREFIX>_COOKIE_<HOST>`）：用户被指去配一个不存在的变量，
    照做还是 401，且不知道该改什么。现在按项目**实际提供**的配置项指路。
    """
    parts: list[str] = []
    if cookie_hosts:
        names = "、".join(f"{prefix}_COOKIE_{_host_key(h)}" for h in sorted(cookie_hosts))
        parts.append(names + "（Cookie 整串，分号分隔）")
    if token_hosts or not cookie_hosts:
        parts.append(f"{prefix}_TOKEN")
    if basic_hosts:
        names = "、".join(f"{prefix}_BASIC_PASSWORD_{_host_key(h)}"
                         for h in sorted(basic_hosts))
        parts.append(names + "（Basic 口令）")
    return "请检查 .env 中的 " + "；".join(parts) + " 配置。"


# 两层判据的信号码 → 给**用户**看的人话（README 里「本次判定用到的证据」那一句）。
_LOGIN_SIGNAL_TEXT = {
    "captcha_field": "登录请求里带验证码字段",
    "mfa_field": "登录请求里带二次验证字段",
    "signed_params": "登录请求里带签名 / 时间戳类参数",
    "encrypted_password": "口令由前端加密，且抓不到可复现的公钥",
}


def _interactive_login_readme(auth_login: dict, prefix: str) -> list[str]:
    """交互式登录的站点：README 里那一节「登录」。

    写给**完全不懂 HTTP 的人**：只讲「你要做的唯一一件事」（在弹出的窗口里登录一次、
    然后让 Agent 确认），以及「过期了怎么办」（再授权一次，别指望自动续期）。
    判据本身（实测结果 / 静态信号）也如实列出来 —— 用户有权知道为什么不能自动登录。
    """
    post_login = auth_login.get("post_login") or {}
    measured = post_login.get("measured") or {}
    evidence: list[str] = []
    if isinstance(measured, dict) and measured:
        evidence.append("实测直接发登录请求没有成功（原因码：" + str(measured.get("reason") or "?") + "）")
    for signal in (post_login.get("signals") or []):
        evidence.append(_LOGIN_SIGNAL_TEXT.get(str(signal), str(signal)))
    return [
        "## 登录（需要你本人完成一次）", "",
        "这个站点**没有办法用账号密码自动登录** —— "
        + ("；".join(evidence) + "。" if evidence else
           "登录过程需要人工参与（验证码 / 短信 / 二次验证 / 单点登录）。"),
        "",
        "**你要做的只有一件事**：让 Agent 调用 `login_interactive()`。",
        "它会在你的电脑上打开一个**真实的浏览器窗口**，你在里面像平时一样登录就行"
        "（验证码 / 短信验证 / 二次验证 / 单点登录都由你本人完成 —— 本服务不破解、"
        "也不绕过任何验证）。",
        "登录好了**告诉 Agent 一声**，它再调用 `confirm_login()` 把登录态保存下来。", "",
        "> 服务**不会**自动判定你登录完了，也不会自动关掉那个窗口 —— 保存只由"
        " `confirm_login()` 触发。`get_login_status()` 里的 `auth_evidence` 只是旁证"
        "（登录后新增的凭据类 Cookie），它变成 `true` **不代表**登录已完成。",
        "> 登录窗口打不开时会自动补装浏览器组件（`playwright` 已写进 `requirements.txt`，"
        "版本钉死以便复用本机已有的浏览器缓存）；仍打不开请把 `error.log` 的最后几行给 Agent。",
        "",
        "登录态保存在本项目目录下的 `auth_state.json`（**请勿提交、同步或分享**），"
        "之后所有工具都会自动带上它。", "",
        "### 登录态过期了怎么办", "",
        "**重新授权一次即可**：再让 Agent 调用一次 `login_interactive()`，在窗口里登录一次，"
        "然后 `confirm_login()`。",
        "这类站点**没有 401 自动重登录** —— 构造请求过不了验证码 / 二次验证，"
        "自动重登录只会白白失败，还会让你以为是自己把凭据配错了。",
        "不必重建项目、不必重新抓包（已经生成的工具不会因为过期而消失）。", "",
        "> 另一种等价做法：把浏览器里的 Cookie 整串粘进 `.env` 的 "
        f"`{prefix}_COOKIE_<HOST>`（见 `.env.example` 里的说明）。", "",
    ]


# 身份类/时间类**词**集合：按标识符切词后整词比对。
# 只做子串匹配是不够的——`id`、`tenant`、`email`、`phone`、`recipient` 都不含
# 下面那些子串，于是它们的真实值会被烘成默认值（实测：`id: int = 88231`、
# `recipient: str = 'bob@corp.com'`、`phone: str = '13800138000'`）。
_IDENTITY_WORDS = frozenset({
    "id", "ids", "uid", "uuid", "guid", "key", "no", "num", "code",
    "user", "username", "account", "acct", "member", "author", "owner",
    "email", "mail", "mobile", "phone", "tel", "contact", "recipient",
    "tenant", "org", "employee", "staff", "customer", "client",
})
_TIME_WORDS = frozenset({
    "time", "date", "datetime", "timestamp", "start", "end", "begin", "until",
    "since", "created", "updated", "modified", "expires", "expiry", "deadline",
})

# 值本身像「具体数据」的形态。名称过关不代表值安全：
# `sectionId` 也许无害，但 `bob@corp.com` 无论挂在哪个键下都是 PII。
# 脱敏哨兵：analyzer 读到的请求体**已经脱敏**（见 redaction.py），敏感字段的
# 取样值就是字面 `***`。它长得「短、ASCII、无逗号」，会通过下面全部形态检查，
# 于是被烘成 `password: str = '***'` —— 生成的工具把哨兵当密码发给服务端。
_REDACTION_SENTINEL = "***"

_VALUE_PATTERNS = (
    re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$"),                  # 邮箱
    re.compile(r"^\+?\d[\d\s()-]{6,}$"),                        # 电话号
    re.compile(r"^\d{5,}$"),                                    # 5 位以上纯数字（ID/编号）
    re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
               r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),            # UUID
    re.compile(r"^(?:[0-9a-fA-F]{2}){16,}$"),                   # 长十六进制串
    re.compile(r"^[A-Za-z0-9+/_=-]{24,}$"),                     # 长 token / base64
)


def _words(ident: str) -> set:
    """把标识符切成小写词：`menuIds`→{menu,ids}，`user_id`→{user,id}。"""
    spaced = re.sub(r"[^0-9a-zA-Z]+", " ", str(ident))
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", spaced)
    spaced = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", spaced)
    return {w.lower() for w in spaced.split() if w}


def _looks_like_real_data(value: str) -> bool:
    """值是否像「抓包当时那个人的具体数据」。"""
    text = str(value)
    return any(pattern.match(text) for pattern in _VALUE_PATTERNS)


def _looks_identity_or_time(ident: str) -> bool:
    """身份类/时间类参数不做默认值：抓包时的 user_id、时间戳只代表当时那个人、那一刻。"""
    low = ident.lower()
    if _words(ident) & (_IDENTITY_WORDS | _TIME_WORDS):
        return True
    # 保留原有的子串判据（如 `authorid`、`ids` 这类不切词的写法）
    return (
        "user" in low or "uid" in low or "author" in low or "account" in low
        or "time" in low or "date" in low or "start" in low or "end" in low
        or "token" in low or "session" in low or "ids" in low
    )


# 名字像**口令/凭据**的参数词：弹窗输入时要掩码（同密码框的约定：口令不进对话、不进日志）。
_SECRET_WORDS = frozenset({
    "password", "passwd", "pwd", "pass", "secret", "token", "key", "apikey",
    "signature", "sign", "credential", "credentials", "auth", "otp", "pin",
})


def _looks_secret_name(name: str) -> bool:
    """参数名像不像口令/令牌/密钥 —— 决定弹窗里要不要用掩码输入（`show='*'`）。"""
    return bool(_words(name) & _SECRET_WORDS)


def _safe_default_query(param_name: str, values: list) -> str | None:
    """为「查询即内容」的参数生成安全默认值。

    原则：**保留查询结构，剥离身份数据，强制带上分页上限**。

    不能直接烘抓包里的原值——那是当时那个用户的查询（含具体 objectid、
    时间戳等），既泄漏又很快过期。也不能给空值——空值等于无界查询
    （实测 >90s 超时）。

    **认不出语义的参数返回 None**：宁可变可选，也不要塞一个无关的值。

    对 FetchXML：取样本里的根实体名与字段列表，重建一个
    `count=50 page=1` 的安全查询，并丢掉所有 condition（过滤条件）。
    """
    name_low = (param_name or "").lower()

    if name_low == "fetchxml" and values:
        sample = str(values[0])
        entity = re.search(r'<entity\s+name="([^"]+)"', sample)
        if entity:
            ent = entity.group(1)
            # 必须先剥掉 <link-entity>...</link-entity> 段再取 attribute——
            # 关联实体的字段不属于主实体，混入会报
            # "entity doesn't contain attribute with Name = 'xxx'"（实测 400）。
            main = re.sub(r"<link-entity\b.*?</link-entity>", "", sample, flags=re.S | re.I)
            attrs = re.findall(r'<attribute\s+name="([^"]+)"', main)[:12]
            # 无字段时用 all-attributes，避免生成非法 FetchXML
            body = ("".join(f'<attribute name="{a}"/>' for a in attrs)
                    if attrs else "<all-attributes/>")
            # 注意：不带 <filter>，即不做任何数据过滤（不泄漏抓包时的筛选条件）
            order = attrs[0] if attrs else "createdon"
            return (f'<fetch version="1.0" output-format="xml-platform" mapping="logical" '
                    f'page="1" count="50" no-lock="true"><entity name="{ent}">{body}'
                    f'<order attribute="{order}" descending="true"/>'
                    f'</entity></fetch>')

    # 其它「查询即内容」的参数：只对**能确定语义**的少数名字给合成默认值。
    # 认不出来就返回 None，让调用方退回普通门槛（参数变成可选），
    # 而不是塞一个与该参数无关的值 —— 实测 `filter` 曾被填成 `count=50`，
    # 设备收到 `filter=count=50` 直接回 599。
    if name_low in ("query", "sql", "odataquery"):
        return "page=1&count=50"
    return None


def _observed_values_are_unique(values: list) -> bool:
    """该参数在抓包里只观测到一个**不同**取值吗？

    `query_params`（以及表单那边的 `request_body_params`）本身就是「不同取值」的列表
    （见 `analyzer`），所以长度 ≤ 1 即「唯一」。手写 registry 里可能有重复，故用 set。
    """
    return len({str(value) for value in values}) <= 1


def _measured_behaviour_switch(evidence: dict | None) -> bool:
    """**实测**过「换个取值，响应结构真的不同」吗（`behaviour_switch is True`）？

    这是三态布尔里唯一算数的那一态：`True` = 对照抓包实测过；`False` = 实测过、结构相同；
    `None` = 找不到对照、没结论（见 `analyzer.detect_behaviour_switch`）。
    """
    evidence = evidence if isinstance(evidence, dict) else {}
    return evidence.get("behaviour_switch") is True


def _switch_blocks_default(name: str, values: list | None,
                           evidence: dict | None = None) -> bool:
    """该参数的**取值会不会切换响应形态** —— 会的话，抓包快照值**一个都不许烘**。

    两档判据，命中其一即拦（这一层只回答「烘不烘」，「必填还是可选」见 `_param_is_required`）：

      * **实测档**：`behaviour_switch is True`（对照抓包真的观测到结构变了）→ 拦；
      * **名字/取值档**：`analyzer.is_switch_risk_param`（名字 `count` / `pagesize` /
        `bulkbindings` / `filter` / `page` / `sort` … 或取值 `yes` / `no` / `true` /
        `false` / `on` / `off`）→ 拦。

    为什么必须拦：NITRO 这类设备管理 API 里 `count=yes` **只返回 `__count`**、不返回对象
    列表。烘 `count='yes'` 会让生成的工具**静默**给出一条错误的业务结论 —— HTTP 200、
    JSON 正常、无任何报错，LLM 于是告诉用户「设备上没有对象」，而设备上可能有几十个。
    这是整份缺陷清单里唯一「静默给出错误业务结论」的一类，比报错坏得多。

    为什么**名字档不看有没有证据**：`count=yes` 只抓到**一个**请求时，`analyze_param_evidence`
    返回空证据（`classify_request_params` 少于 2 个不同请求就什么都不分类）——若只在
    「证据说 `switch_risk`」时才拦，恰恰漏掉最常见的那次（用户第一次抓包往往只有一个
    请求）。所以名字/取值档与证据有无无关。

    ⚠️ 局限（未决）：这条判据只说「会变」，**不说「哪个取值返回完整数据」** ——
    `behaviour_switch` 是三态布尔，`detect_behaviour_switch` 只比两个结构签名**集合**是否
    相等，逐取值 → 结构签名的映射**从不落盘**。所以生成器现在无法「烘那个返回完整数据的
    取值」，只能退到「不烘 + 文档说明」（见 `docs/reference.md` 的同名一节）。
    """
    if _measured_behaviour_switch(evidence):
        return True
    return is_switch_risk_param(name, values)


def _default_eligible(name: str, evidence: dict | None, values: list) -> bool:
    """该参数是否**有资格**烘默认值 —— 「良性就保留默认值」。

    判据只有两类，二者之一成立即可：

      * 证据明确说它是 `fixed`（每个观测到的**不同请求**都带它、且值完全一样）→ 烘。
        一个在每个请求里都取同一个值的参数，烘它就**复现了抓包时的行为**；
        让不懂 HTTP 的使用者去手填一个他自己也不知道该填什么的值，是净负分。
        （`verified` —— 行为开关是否验证过 —— **不再**是一票否决：fixed 参数按定义
        不存在「带 / 不带」的对照请求，拿不到对照就永远不烘，等于永久把参数丢给用户。）
      * **没有证据**（证据重做之前生成的老项目、手写 registry）→ 只要**观测取值唯一**
        就烘。值会变的话至少能看到两个取值；只看到一个，说明本次只见到一个。

    明确**排除**的三类 —— 前两类是我们**确切知道**它可变，第三类是我们知道**烘了会
    静默给出错误的业务结论**（见 `_switch_blocks_default`），烘一个快照必然错：

      * `variable`   —— 值会变（每个请求都有）→ 暴露为**必填**输入；
      * `occasional` —— 有的请求没带它 → 可选、无默认值（抓包时带的那个值不代表常态）；
      * 取值会**切换响应形态**的（`count` / `pagesize` / `bulkbindings` …，见
        `_switch_blocks_default`）→ 不烘。`count='yes'` 烘进签名后，调用方省略它就会拿到
        `{"__count": 0}` 并据此告诉用户「设备上没有对象」——而设备上可能有几十个。
        两档都**不烘**，但「必填还是可选」不同（见 `_param_is_required`），
        并在 docstring 里用面向非技术用户的话说清（见 `_evidence_note`）。
    """
    if _switch_blocks_default(name, values, evidence):
        return False
    evidence = evidence if isinstance(evidence, dict) else {}
    klass = evidence.get("class")
    if klass in ("variable", "occasional"):
        return False
    if klass == "fixed":
        return True
    return _observed_values_are_unique(values)


def _stable_default_value(ident: str, values: list,
                          evidence: dict | None = None) -> str | None:
    """可安全烘入的默认值（原始字符串）；不安全则不烘，返回 None。

    第一道闸门是**证据**（见 `_default_eligible`）：`fixed` 或「无证据 + 取值唯一」
    才继续往下走；但不包括**取值会切换响应形态**的参数（`count` / `pagesize` /
    `bulkbindings` …，见 `_switch_blocks_default`）—— 那类一律不烘（实测档必填、
    名字档可选无默认值，见 `_param_is_required`）。
    第二道闸门是**名字与值**：
      * 名字：不得是身份/时间类（见 `_looks_identity_or_time`）；
      * 值：不得像具体数据（邮箱/电话/长数字/UUID/长 token，见 `_looks_like_real_data`）；
      * 值：不得是脱敏哨兵 `***`（见 `_REDACTION_SENTINEL`）—— 那不是数据，是遮蔽记号；
      * 值：不得为空 —— 空值烘进去等于「这个参数凭空消失」，让服务端收到缺参请求。
    只看名字是不够的——实测 `id`/`tenant`/`email`/`recipient` 这些名字以前都放行，
    于是抓包当时那个人的邮箱、手机号、用户 ID 被烘进了分发包。
    """
    if not values or not _default_eligible(ident, evidence, values):
        return None
    text = str(values[0])
    # 脱敏哨兵绝不入默认值：它是「值已隐藏」的记号，不是真实取值。
    # 只认它精确形态与纯 `*` 串；别的「看起来像掩码」的值不猜。
    if _is_redaction_mark(text) or not text:
        return None
    if len(text) > 24 or not text.isascii() or "," in text:
        return None
    if _looks_identity_or_time(ident) or _looks_like_real_data(text):
        return None
    return text


def _param_is_required(name: str, values: list | None, evidence: dict | None) -> bool:
    """该参数在签名里是否**必填**（无默认值）。

    只有 `variable`（每个请求都带、但值会变）是必填：它不能有默认值（烘任何一个
    观测值都是错的那一个），也不能是可选的（省略它就是把「调用方想查什么」丢掉）。
    规则原文：variable —— expose it as a real input (required if present in every
    request, optional otherwise)；按定义 variable 就是「每个请求都有」。

    「取值会切换响应形态」的参数（`_switch_blocks_default`）**分两档**，必填与否据此定：

      * **实测档**（`behaviour_switch is True`）：必填。实测过「换个取值结构就不同」，
        而且抓包里的那个取值只代表当时那一次 —— 写死它就会**静默**给出错误结论
        （`count='yes'` → `{"__count": 0}`），省略它又等于让服务端按自己的默认行为回，
        同样不是调用方要的那个形态。所以既不烘、也不给「可选」。
      * **名字/取值档**（只是名字像 `page` / `sort` / `format`，没有任何实测证据）：
        **可选、无默认值**（`| None = None`）。这类名字在普通 CRUD 项目里遍地都是，
        而大多数**并不**切换响应形态 —— 一律逼成必填只会让调用方来问使用者「page 填几」，
        而他不知道。省略它时请求里**根本不会出现**这个键（`_clean` 丢掉 `None`），
        服务端用自己的默认值，正是抓包当时的常态。

    `occasional`（抓包里有的请求本来就没带它）是**唯一**的例外：一律可选、无默认值，
    即便实测档也不逼成必填 —— 事实就是「不带它也能通」。
    """
    evidence = evidence if isinstance(evidence, dict) else {}
    if evidence.get("class") == "variable":
        return True
    if evidence.get("class") == "occasional":
        return False
    return _measured_behaviour_switch(evidence)


def _param_decl(ident: str, py_type: str, values: list,
                evidence: dict | None = None) -> str:
    """产出参数声明。query 参数与表单体字段（#23）共用同一套门槛。

    顺序：先看分类（variable → 必填）；否则若能安全烘默认值（见
    `_stable_default_value`：`fixed`，或「无证据 + 取值唯一」，且名字/取值均良性）
    就烘；都不行才降级为可选、无默认值。
    """
    if _param_is_required(ident, values, evidence):
        return f"{ident}: {py_type}"
    text = _stable_default_value(ident, values, evidence)
    if text is None:
        return f"{ident}: {py_type} | None = None"
    if py_type == "int":
        # 必须**规范化**：`_infer_type` 认得 `007` / `0000` 这类带前导零的样本，而
        # Python 3 里 `x: int = 007` 直接 SyntaxError —— 一个这样的参数就能让整份
        # 生成物编不过（与参数名是关键字同一类事故）。
        try:
            default = str(int(text))
        except ValueError:                       # 理论上不可达（int 类型由 `\d+` 推出）
            return f"{ident}: {py_type} | None = None"
    else:
        default = repr(text)
    return f"{ident}: {py_type} = {default}"


def _render_file_response_helper() -> str:
    """文件/流式响应通道（Fix 1）。

    **只在 registry 里真有 `file_response` 端点时才发射**：纯 JSON 项目的产物因此
    逐字节不变（见 audit/compare_render.py 的冻结输出守卫）。`_request` 的 `raw`
    分支复用这里的 `_raw_payload`——两条路径共用同一套鉴权与 401 自动重登录，
    不另起一份网络实现（复制一份必然漂移，本仓库已吃过这个亏）。
    """
    return '''_TEXT_CONTENT_TYPES = ("text/",)
_TEXT_CONTENT_SUFFIXES = ("+json", "+xml")
_TEXT_CONTENT_EXACT = {"application/json", "application/xml", "application/csv",
                       "application/x-ndjson", "application/sql"}


def _is_text_content_type(content_type: str) -> bool:
    """响应体能不能按文本原样返回（csv/json/xml… 可以；pdf/xlsx/zip 不行）。"""
    media = (content_type or "").split(";", 1)[0].strip().lower()
    return (media in _TEXT_CONTENT_EXACT
            or media.startswith(_TEXT_CONTENT_TYPES)
            or media.endswith(_TEXT_CONTENT_SUFFIXES))


def _raw_payload(resp) -> dict:
    """文件/流式响应：**不解析 JSON**，把响应体原样交给调用方自行落盘。

    文本类响应给 ``text``（原文），二进制（pdf/xlsx/zip/octet-stream …）给
    ``base64``（原文的 base64）。连同 ``status`` / ``content_type`` /
    ``content_disposition`` 一起返回。
    **本函数不写磁盘**：写哪个文件、什么格式，由调用方决定。
    """
    content_type = resp.headers.get("content-type", "")
    payload = {"status": resp.status_code, "content_type": content_type,
               "size": len(resp.content),
               "content_disposition": resp.headers.get("content-disposition", "")}
    if _is_text_content_type(content_type):
        payload["text"] = resp.text
    else:
        payload["base64"] = base64.b64encode(resp.content).decode("ascii")
    return payload
'''


# 渲染一条工具**必须**有的字段。缺了没法编：补一个假 path 只会让工具打到
# 错误地址（比报错更坏），所以这里 fail-loud，并且报错必须点名是哪一条。
_ENDPOINT_REQUIRED_FIELDS = ("tool_name", "host", "path")


def _endpoint_label(entry: Any, index: int | None = None) -> str:
    """出错时用来点名条目的标识：索引 + `endpoint_id` 或 `tool_name`。"""
    ident = None
    if isinstance(entry, dict):
        ident = entry.get("endpoint_id") or entry.get("tool_name")
    kind = type(entry).__name__ if not isinstance(entry, dict) else "dict"
    prefix = f"#{index} " if index is not None else ""
    return f"{prefix}(id={ident!r}, {kind})"


def _missing_endpoint_fields(entry: Any) -> list[str]:
    if not isinstance(entry, dict):
        return list(_ENDPOINT_REQUIRED_FIELDS)
    return [f for f in _ENDPOINT_REQUIRED_FIELDS
            if entry.get(f) is None or entry.get(f) == ""]


def _doc_escape(text: object) -> str:
    """把任意文本安全地放进工具文档字符串的**一行**里。

    溯源/证据提示是用户（或抓包）提供的内容：引号与反斜杠不转义就能闭合文档字符串
    （与 `description` 同样的注入面），换行会破坏「一条一行」的排版。
    """
    return (str(text).replace("\\", "\\\\").replace('"', "'")
            .replace("\r", " ").replace("\n", " ").strip())


def _evidence_note(ident: str, wire: str, values: list | None,
                   evidence: dict | None) -> list[str]:
    """一个参数的「证据」说明行（只在该参数需要调用方特别注意时才产出）。

    调用方是 LLM，它只读工具的文档字符串；「这个参数会变、必须自己传」或
    「它的取值会改变返回内容」必须写在它看得见的地方 —— 否则调用方省略它就会拿到
    **不完整**的数据，还以为是全部。

    「会切换响应形态」的两档**话术不同**（这是刻意的，不是重复）：实测档要逼调用方
    显式传（省略/写死都可能给错数据）；名字档只是提示，不填时服务端用默认，
    返回值看起来不完整再换个值试。两档都必须说清「换个值，给你的东西就不一样」。
    """
    evidence = evidence or {}
    label = f"`{ident}`" + (f"（原始名 `{wire}`）" if wire != ident else "")
    klass = evidence.get("class")
    if klass == "variable":
        return [f"- {label}：抓包中每个请求都带它、但**取值会变** → 必填，"
                f"不设默认值（烘任何一个观测值都是错的那个）。"]
    if not _switch_blocks_default(wire or ident, values, evidence):
        return []
    # 面向**不懂 HTTP 的使用者**（真正读这段话的是 LLM，它再转述给使用者）：
    # 不说「行为开关 / 响应结构」这类术语，只说「换个值，给你的东西就不一样」。
    # 「没判定出哪个取值返回完整数据」时**不猜**哪个值对，只如实说明 + 给可操作
    # 的下一步 —— 猜一个值烘进去比不给默认值坏得多（那是静默的错误结论）。
    head = (f"- {label}：这个参数的**取值会改变返回内容**（同一个接口换个值，"
            f"可能从「一串列表」变成「只有计数」或只给前几条）。")
    if _param_is_required(wire or ident, values, evidence):
        # 实测档：一句话说清「写死会拿到不完整数据」+ 明确要求显式传值。
        how = ("**必填**：抓包时的那个值只代表当时那一次，写死就可能让你拿到不完整的"
               "数据，所以本次不替你写死默认值，请显式传一个值。"
               "拿回来的东西明显不完整时，换另一个取值再调一次。")
    elif klass == "occasional":
        # 抓包里有的请求本来就没带它 —— 这是事实，比任何猜测都硬。
        how = ("**可选**：抓包里有的请求本来就没带它，所以本次不设默认值；"
               "不填时服务端会用它自己的默认值。拿回来的东西明显不完整时，"
               "可以显式换一个取值再调一次。")
    else:
        # 名字/取值档：只是「像开关」，没有任何实测证据。不替调用方写死，也不逼他填。
        how = ("**可选**：不填时服务端会用它自己的默认值（本次没有替你写死）；"
               "拿回来的东西看起来不完整时，可以显式换一个取值再调一次。")
    return [head + how]


def _provenance_note(ident: str, wire: str, provenance: object) -> list[str]:
    """一个参数的溯源说明行（`origin` 来自哪里 + `impact` 影响什么）。"""
    if not provenance:
        return []
    if isinstance(provenance, dict):
        origin = provenance.get("origin")
        impact = provenance.get("impact")
    else:
        origin, impact = None, provenance
    parts = [p for p in (origin, impact) if p]
    if not parts:
        return []
    label = f"`{ident}`" + (f"（原始名 `{wire}`）" if wire != ident else "")
    return [f"- {label}：{'；'.join(_doc_escape(p) for p in parts)}"]


def _validate_endpoints(endpoints: list) -> None:
    """渲染前校验：缺字段就报**点名**的错误，而不是下游某处的裸 `KeyError`。

    以前 `_render_tool` 直接 `entry["tool_name"]` / `["host"]` / `["path"]`，
    registry 里少一个字段时 `regenerate_server` 抛的是不带任何上下文的
    `KeyError: 'host'` —— 用户看到的是「合并/再生成失败」，不知道是哪一条、
    也不知道该去 registry.json 里改什么。
    """
    for index, entry in enumerate(endpoints):
        missing = _missing_endpoint_fields(entry)
        if missing:
            raise ValueError(
                f"registry endpoint {_endpoint_label(entry, index)} 缺少必填字段："
                f"{', '.join(missing)}。渲染器不会替缺失字段编造默认值"
                f"（凭空的 host/path 会让生成的工具请求到错误地址）。"
                f"请修 registry.json 里这条条目的 {'/'.join(missing)} 后重试。"
                f"必填字段：{', '.join(_ENDPOINT_REQUIRED_FIELDS)}。")


def _render_tool(entry: dict, prefix: str) -> str:
    # 防御性兜底：正常路径已由 render_server 的 _validate_endpoints 点名校验
    # （带索引），但 _render_tool 也会被单独调用，不能退化成裸 KeyError。
    missing = _missing_endpoint_fields(entry)
    if missing:
        raise ValueError(
            f"endpoint {_endpoint_label(entry)} 缺少必填字段：{', '.join(missing)}。"
            f"渲染器不会替缺失字段编造默认值。")
    method = entry.get("method", "GET")
    host = entry["host"]
    path = entry["path"]
    mutating = method not in ("GET", "HEAD")
    # Fix 1: 业务文件下载端点没有 JSON schema，生成的工具必须**如实说明**它返回的是
    # 文件/流（响应体原文 + 内容类型），由调用方自行落盘；否则调用方会以为拿到的是
    # 解析好的数据。
    file_mode = bool(entry.get("file_response"))
    marker = ("[FILE] " if file_mode else "") + ("[MUTATING] " if mutating else "")
    # 反斜杠必须一并转义：描述以 `\` 结尾时会把文档字符串的收尾引号转义掉，
    # 后面的源码就被并进字符串里（实测可借此注入）。
    desc = ((entry.get("description") or f"{method} {path}")
            .replace("\\", "\\\\").replace('"', "'"))
    if file_mode:
        desc += ("（文件/流式响应：无 JSON schema。返回响应体原文——文本在 text、"
                 "二进制在 base64——连同 content_type / status；本工具不写磁盘，"
                 "调用方须自行落盘。）")

    # ---- signature -------------------------------------------------------- #
    # 本次重做：默认值只看「不同请求之间的比较」证据，不再看 sample_count。
    evidence = dict(entry.get("query_param_evidence") or {})
    form_evidence = dict(entry.get("request_body_param_evidence") or {})
    # Issue #15: 从 $batch 还原且无分页参数的集合端点，注入默认上限。
    # 实测同一端点：无上限 >90s 超时；$top=10 用 3.1s。
    pagination = entry.get("pagination_suggested") or {}
    inject_top = bool(pagination) and method in ("GET", "HEAD")
    has_body = bool(entry.get("request_schema")) and mutating

    # 注入参数（top / payload / confirm）的名字被生成物自身的代码固定引用，
    # 所以先把它们占住；抓包里若有同名字段，给抓到的那个让名。
    # 既不能静默丢弃（参数凭空消失），也不能直接拼出重复参数——实测后者会让
    # 整个生成物 SyntaxError（`def post_x(confirm: str = None, confirm: bool = False)`）。
    taken: set = set()
    if inject_top:
        taken.add("top")
    if has_body:
        taken.add("payload")
    if mutating:
        taken.add("confirm")

    # 必填参数必须排在带默认值的参数**前面**，否则 Python 直接 SyntaxError
    # （`def f(a: str = '1', b: str)`）。variable 参数与 fetchXml 这类
    # 「查询即内容」的参数都是必填，故分两条列表各收集、末尾拼接。
    required_params: list = []
    optional_params: list = []
    note_lines: list[str] = []
    path_idents: dict[str, str] = {}
    for p in entry.get("path_params") or []:
        # 路径参数改名的同时必须改路径串里的占位符，故把映射交给 _emit_path。
        ident = _unique_ident(_py_ident(p), taken)
        path_idents[str(p)] = ident
        taken.add(ident)
        required_params.append(f"{ident}: str")

    # Issue #15: fetchXml 这类「查询即内容」的参数必须保持必填。
    # 实测：annotations 的分页约束在 fetchXml 内（count="10" page="1"），
    # 若降级为 None，调用方省略后即退化为无界查询（>90s 超时 vs 带参数 3.1s）。
    req_q = entry.get("required_query_param") or {}
    required_query_name = req_q.get("param") if req_q else None

    query_idents: dict[str, str] = {}
    for key, values in (entry.get("query_params") or {}).items():
        ident = _unique_ident(_py_ident(key), taken)
        query_idents[key] = ident
        taken.add(ident)
        param_evidence = evidence.get(key)
        if required_query_name and key == required_query_name:
            # 必填，但给一份**带分页上限**的安全默认（不烘真实抓包值——
            # 那些含具体 objectid 等身份数据，泄漏且过期）。
            safe = _safe_default_query(key, values)
            if safe is None:
                # 认不出这个参数该配什么值：**要求调用方提供**，不给默认。
                # 两条路都不能走 —— 编一个无关的值会让服务端报错（实测 `filter=count=50`
                # → 设备 599），而退回"烘抓到的那份查询"则是把抓包当时那个用户的
                # 具体条件写进分发包（泄漏 + 很快过期，正是这条路本来要避免的）。
                required_params.append(f"{ident}: {_infer_type(values)}")
            else:
                optional_params.append(f'{ident}: str = {safe!r}')
            continue
        decl = _param_decl(ident, _infer_type(values), values, param_evidence)
        (required_params if _param_is_required(key, values, param_evidence)
         else optional_params).append(decl)

    # Issue #23: 表单编码体字段 → 具名参数（与 query 参数同一套类型推断与默认值
    # 门槛）。传统服务端渲染系统的接口全靠 POST 体传参，此前参数全丢，
    # 工具能连通但必然业务报错。
    form_params = entry.get("request_body_params") or {}
    form_idents: dict[str, str] = {}
    for key, values in form_params.items():
        ident = _unique_ident(_py_ident(key), taken)
        form_idents[key] = ident
        taken.add(ident)
        param_evidence = form_evidence.get(key)
        decl = _param_decl(ident, _infer_type(values), values, param_evidence)
        (required_params if _param_is_required(key, values, param_evidence)
         else optional_params).append(decl)

    if inject_top:
        # 用更贴近 OData 的参数名；调用方可以覆盖
        optional_params.append("top: int = 50")
        desc += "（默认 top=50 限制返回量，避免全表拉取超时）"

    if has_body:
        optional_params.append("payload: dict | None = None")
    if mutating:
        optional_params.append("confirm: bool = False")
    params = required_params + optional_params
    signature = ", ".join(params) if params else "payload: dict | None = None"

    # ---- 证据 / 溯源写进 docstring（调用方是 LLM，只读这里） ---------------- #
    if entry.get("insufficient_samples"):
        note_lines.append("- " + _doc_escape(
            entry.get("evidence_hint") or
            "该端点观测到的不同请求不足 2 个，无法比较参数是否可变；本次只对取值唯一的"
            "参数沿用抓包取值作默认值，其余不设默认值。"
            "请让用户再操作一次该功能后重新抓包分析。"))
    provenance = entry.get("param_provenance") or {}
    for key in list(query_idents) + list(form_idents):
        ident = query_idents.get(key) or form_idents[key]
        in_query = key in query_idents
        evidence_entry = evidence.get(key) if in_query else form_evidence.get(key)
        # 取值从同一处取（与上面签名渲染用的是同一份），供「会切换响应形态」判据复用。
        raw_values = ((entry.get("query_params") or {}) if in_query
                      else (entry.get("request_body_params") or {})).get(key)
        note_lines += _evidence_note(ident, key, as_value_list(raw_values),
                                     evidence_entry)
        note_lines += _provenance_note(ident, key, provenance.get(key))

    # ---- call ------------------------------------------------------------- #
    # 路径/主机/方法一律经 json.dumps 发射：抓到的内容只当**字符串**，不再拼接进
    # 源码。此前一个含 `"` 或 `{...}` 的路径就能在生成物里注入可执行代码（实测
    # 生成的 server.py 里出现了 __import__("os").system(...) 且 compile 通过）。
    call_path = _emit_path(path, path_idents)
    # 工具名同样过标识符层：`class` 这类关键字会让整个文件 SyntaxError。
    tool_name = _py_ident(entry["tool_name"])
    # S13：把**这条端点**的鉴权方式交给 `_request`，凭据按端点取用（同域名可混用）。
    # 键与 `AUTH_SCHEME[host]` 的键同一套标识符，两侧不会对不上。
    auth_tool = json.dumps(tool_name)
    call_args = [json.dumps(host), json.dumps(method), call_path]
    # wire key 用**原始**参数名：此前把 Python 标识符当线上参数名，`$filter`、
    # `a.b`、中文键会被改写成 `filter`/`a_b`/`param` 发给服务端，必然 400/404。
    query_items = [f'{json.dumps(key)}: {query_idents[key]}'
                   for key in (entry.get("query_params") or {})]
    if inject_top:
        # $top 对 OData 生效；对非 OData 服务端由 _request 侧透传，无害
        query_items.append('"$top": top')
    if query_items:
        call_args.append("params={" + ", ".join(query_items) + "}")
    if form_params:
        # Issue #23: 表单编码体（与 JSON body 互斥）；wire key 同样用原始名
        call_args.append("form_body={" + ", ".join(
            f'{json.dumps(key)}: {form_idents[key]}' for key in form_params) + "}")
    elif has_body:
        call_args.append("json_body=payload or {}")
    if file_mode:
        # Fix 1: 走 _request 的 raw 分支（同一套鉴权 / 401 自动重登录），只是不解析
        # JSON。raw 分支与 _raw_payload 只在 registry 里真有文件端点时才发射，故
        # 纯 JSON 项目的产物逐字节不变。
        call_args.append("raw=True")
    call_args.append("auth_tool=" + auth_tool)
    call = "await _request(" + ", ".join(call_args) + ")"

    # ---- body ------------------------------------------------------------- #
    body_lines = []
    if mutating:
        body_lines.append("    if not confirm:")
        message = f"写操作：再次调用并传 confirm=true 才会执行 {method} {path}。"
        body_lines.append('        return {"need_confirm": True, "message": '
                          + json.dumps(message, ensure_ascii=False) + '}')
        body_lines.append(f'    _audit({entry["tool_name"]!r}, {{"host": {host!r}, "path": {path!r}}})')
    body_lines.append("    return " + call)

    doc = marker + desc
    if mutating:
        # S33：`confirm` 拦的是「一次误触」，拦不住调用方自己重试 —— 它**不是**向人
        # 取得同意的门槛。所以必须把**实质后果**写在工具描述里（调用方是 LLM，只读
        # 这里），说清这件事会真的改数据、可能撤不回来；措辞面向不懂技术的读者。
        doc += ("\n\n    重要：这是写操作，调用它会真的修改服务器上的数据，"
                "可能无法撤销，请确认你确实要这么做。"
                "必须显式传 confirm=true 才会执行；执行会把这次调用记进项目的 audit.log。")
    if note_lines:
        doc += "\n\n    参数说明：\n" + "\n".join("    " + line for line in note_lines)
    return (f'@mcp.tool()\n'
            f'async def {tool_name}({signature}) -> Any:\n'
            f'    """{doc}"""\n' + "\n".join(body_lines) + "\n")


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

# ⚠️ 必须在导入 fastmcp **之前**清洗 NO_PROXY。FastMCP 的启动横幅会调
# check_for_newer_version()，用 trust_env=True 的 httpx 客户端打 PyPI；而宿主注入的
# NO_PROXY 里带方括号 IPv6（`[::1]`）会让 httpx 在**构造时**就抛 InvalidURL。
# 顺序反了的后果：生成的服务启动即崩、端口从未监听，而调用方只看到 ConnectError。
# 本块与 webapi_extractor/proxy_env.py 等价（生成物无法 import 技能自身的包）。
# --------------------------------------------------------------------------- #
def _sanitize_no_proxy() -> None:
    for var in ("NO_PROXY", "no_proxy"):
        raw = os.environ.get(var)
        if not raw or "[" not in raw:
            continue
        parts = []
        for part in raw.split(","):
            entry = part.strip()
            if len(entry) >= 2 and entry.startswith("[") and entry.endswith("]"):
                entry = entry[1:-1].strip()
            if entry:
                parts.append(entry)
        os.environ[var] = ",".join(parts)


_sanitize_no_proxy()


import httpx
from fastmcp import FastMCP

_HERE = Path(__file__).resolve().parent


def _unquote_env_value(raw: str) -> str:
    """剥离 dotenv 风格的引号与行内注释。

    密钥常含 base64 的 '=' 补位、'+'、'/'，运维按惯例写成

        SITE_TOKEN="abc=def"

    时，若不剥引号会把引号也带进环境变量，导致鉴权失败且错误信息不指向根因。
    """
    v = raw.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        # 成对引号：整体去掉，内部原样保留（含 # 与 =）
        return v[1:-1]
    # 无引号：按 dotenv 惯例剥离行内注释（空格 + #）
    for marker in (" #", "\t#"):
        idx = v.find(marker)
        if idx != -1:
            v = v[:idx]
    return v.strip()


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
            os.environ.setdefault(k.strip(), _unquote_env_value(v))
    except OSError:
        pass


_load_dotenv()


# --------------------------------------------------------------------------- #
# httpx 兼容性：清洗 NO_PROXY 中的方括号 IPv6 字面量（如 [::1]）。
#
# httpx 在**构造客户端**时就会解析 NO_PROXY；遇到 [::1] 直接抛
#   InvalidURL: Invalid port: ':1]'
# 客户端因此根本建不起来 —— 即使请求根本不经过代理。裸 ::1 无此问题。
# 剥掉方括号即修复，同时保留代理能力（需经代理访问目标站的环境不受影响）。
#
# 注：本文件是独立部署单元，不依赖 webapi_extractor 包，故此处内联实现
# （包内等价实现见 webapi_extractor/proxy_env.py）。

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
    return {k: v for k, v in (params or {}).items() if v is not None__CLEAN_EXTRA__}


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
                   json_body: dict | None = None, form_body: dict | None = None,
__RAW_PARAM__                   auth_tool: str | None = None,
                   _retried_auth: bool = False) -> Any:
    headers = {"Accept": "application/json, text/plain, */*"}
    # S13：凭据按**端点**取用 —— 同一域名下可以一部分接口用 Bearer、另一部分只认
    # Cookie，传 auth_tool 才能各发各的（不传则退回该域名的主方式）。
    headers.update(_auth_headers(host, auth_tool))
    # Issue #23: 表单编码体通道。传统服务端渲染系统的接口只认
    # application/x-www-form-urlencoded，发 JSON 会得到业务错误。
    # httpx 只在未显式设置时才补 Content-Type，故这里可安全指定 charset。
    if form_body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
        body_kwargs: dict = {"data": _clean(form_body)}
    else:
        body_kwargs = {"json": json_body}
    try:
        async with httpx.AsyncClient(base_url=HOSTS[host], timeout=TIMEOUT) as client:
            resp = await client.request(method, path, params=_clean(params),
                                        headers=headers, **body_kwargs)
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
__FORM_RETRY____RAW_RETRY__                                          json_body=json_body,
                                          auth_tool=auth_tool, _retried_auth=True)
        _log_error(f"{method} {host}{path} auth: HTTP {resp.status_code}")
        hint = ""
        if _AUTH_LOGIN_CFG:
            hint = __LOGIN_HINT__
__AUTH_401_EXTRA__        raise RuntimeError(
            f"HTTP {resp.status_code}：鉴权失败（自动重登录未成功或不可用）。"
            f"__AUTH_FAIL_WHERE__"
            + hint)
    if resp.status_code >= 400:
        _log_error(f"{method} {host}{path} HTTP {resp.status_code}")
    resp.raise_for_status()
    if not resp.content:
        return {"status": resp.status_code}
__RAW_BRANCH__    try:
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


def _baked_names_for(params: object, evidence: object,
                     skip: object = None) -> list[str]:
    """这批参数里，哪些会以**抓包取值**当默认值？（与渲染走同一套判据）"""
    params = params if isinstance(params, dict) else {}
    evidence = evidence if isinstance(evidence, dict) else {}
    names: list[str] = []
    for raw_name, raw_values in params.items():
        name = str(raw_name)
        if skip is not None and name == skip:
            continue
        if _stable_default_value(name, as_value_list(raw_values),
                                 evidence.get(name)) is not None:
            names.append(name)
    return names


def baked_param_defaults(endpoints: list | None, auth_login: dict | None = None) -> list[dict]:
    """列出「抓包取值被当作默认值烘进生成物」的参数 —— **只给参数名与端点，绝不带取值**。

    这份清单是给**不懂 HTTP 的使用者**看的：他要知道「分享这个 MCP 给别人之前，该去
    检查哪个参数」。把取值一并列出来等于把抓包数据塞进 LLM 上下文 —— 既制造噪音，
    又多一个泄漏面；参数名足以让他知道该检查哪一个。

      * 端点参数只列**真被烘进去**的（`required_query_param` 那条用的是合成安全查询，
        不是抓包取值，故跳过）；
      * 登录接口的 query 参数里，「取用型」（运行时去来源接口取）不算默认值，不列。
    """
    found: list[dict] = []
    for entry in endpoints or []:
        if not isinstance(entry, dict):
            continue
        skip = (entry.get("required_query_param") or {}).get("param")
        names = _baked_names_for(entry.get("query_params"),
                                 entry.get("query_param_evidence"), skip=skip)
        names += _baked_names_for(entry.get("request_body_params"),
                                  entry.get("request_body_param_evidence"))
        if not names:
            continue
        found.append({"endpoint_id": entry.get("endpoint_id"),
                      "tool": entry.get("tool_name"),
                      "path": entry.get("path"), "params": names})
    if isinstance(auth_login, dict):
        # 取用型（运行时去来源接口取）与「来源确定但取用不了」（走必填）都不是默认值。
        provenance = auth_login.get("query_param_provenance")
        provenance = provenance if isinstance(provenance, dict) else {}
        excluded = {name for name, entry in provenance.items()
                    if value_is_response_derived(entry)}
        names = [name for name in _baked_names_for(auth_login.get("query_params"),
                                                  auth_login.get("query_param_evidence"))
                 if name not in excluded]
        if names:
            found.append({"endpoint_id": None, "tool": "login",
                          "path": auth_login.get("path"), "params": names})
    return found


def baked_param_notice(defaults: list[dict]) -> str:
    """把上面的清单写成一句**给非技术用户看**的话（只列参数名，不列取值）。"""
    if not defaults:
        return ""
    ordered: list[str] = []
    for item in defaults:
        for name in item.get("params") or []:
            if name not in ordered:
                ordered.append(name)
    return ("以下参数使用了抓包时的取值作为默认值，分享这个 MCP 给他人前请检查："
            + "、".join(ordered))


def _smoke_endpoint(endpoints: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, list[str], list[str]]:
    """为冒烟脚本挑一个「最可能无副作用、最可能一次就通」的端点。

    **只读 GET 是前提**（写操作绝不进冒烟）。在此之上按下列优先级对齐（全部满足者胜出，
    同分取注册顺序里的第一个，`max` 稳定所以结果确定）：

      1. 无需鉴权 —— 未配凭据时不会 401，否则用户分不清「环境没配好」和「接口本身正常」；
      2. 无路径参数 —— 不用拿假 id（``"1"``）去猜，避免必然 404；
      3. 无「查询即内容」的必填参数 —— 省略它会退化成无界查询（实测 >90s 超时）；
      4. 不是文件/流式下载 —— 不给冒烟拉一个几十 MB 的文件；
      5. 不在「体积/频次大，建议复核」之列 —— 不挑轮询/巨型响应端点。

    返回 ``(端点, 选它的理由, 未能满足、但要在生成物里如实说明的注意事项)``。
    """
    def rank(entry: dict[str, Any]) -> tuple[int, ...]:
        return (
            0 if entry.get("auth_required") else 1,
            0 if entry.get("path_params") else 1,
            0 if entry.get("required_query_param") else 1,
            0 if entry.get("file_response") else 1,
            0 if entry.get("review_suggested") else 1,
        )

    gets = [e for e in endpoints if str(e.get("method") or "").upper() == "GET"]
    if not gets:
        return None, [], []
    best = max(gets, key=rank)
    reasons = ["只读 GET 请求，不会产生任何副作用"]
    caveats: list[str] = []
    if best.get("auth_required"):
        caveats.append("这个接口需要鉴权：请先按 README 配好凭据，"
                       "否则冒烟会返回 401（那是没配好，不代表接口本身有问题）。")
    else:
        reasons.append("无需鉴权（没配凭据也能通）")
    if best.get("path_params"):
        caveats.append("它需要路径参数，脚本里用 1 占位；若因此报错，请换成真实值再试。")
    else:
        reasons.append("不需要路径参数（不用拿假 id 去猜）")
    if best.get("required_query_param"):
        caveats.append("它有一个省略后会退化成无界查询的必填参数，脚本已填入安全默认值。")
    else:
        reasons.append("没有省略后会退化成无界查询的必填参数")
    if best.get("file_response"):
        caveats.append("它是文件/流式下载接口，冒烟会拉取响应体，可能较慢。")
    else:
        reasons.append("不是文件/流式下载（不会为冒烟拉大文件）")
    if best.get("review_suggested"):
        caveats.append("它被标记为「体积/频次大」，冒烟可能较慢。")
    else:
        reasons.append("响应体积与请求频次正常")
    return best, reasons, caveats


def render_server(registry: dict) -> dict:
    """Render all project files from a registry. Returns {filename: content}."""
    site_name = registry.get("site_name", "site")
    prefix = _env_prefix(site_name)
    version = registry.get("registry_version", 0)
    hosts = registry.get("hosts", {}) or {}
    endpoints = [e for e in registry.get("endpoints", []) if e.get("status") != "deprecated"]
    # Fix 5: 缺字段的条目在这里就点名报错，而不是等下面某处抛裸 KeyError。
    _validate_endpoints(endpoints)

    auth_login = registry.get("auth_login") or None
    # 这个站点能不能靠构造请求登录（两层判据的结论见 analyzer.login_post_verdict）。
    # 只有拿到 `interactive` 这个**明确结论**才改产物：老 registry / 老 analysis.json
    # 没有这个字段时，下面是 False，产物与以前逐字节相同。
    interactive_only = _interactive_login_required(auth_login)
    # S13：逐端点收集每个域名下**实际用到的**鉴权方式。同一域名可以混用，因此
    # 「要不要 Basic 口令 / 要不要 Cookie 整串」这类**配置项**必须按端点判断 ——
    # 只看主机级 scheme 会让「同一域名里那个 Basic 接口」拿不到口令。
    host_kinds: dict[str, list[str]] = {}
    for e in endpoints:
        h = e.get("host")
        for kind in _endpoint_auth_kinds(e, (hosts or {}).get(h) or {}):
            bucket = host_kinds.setdefault(h, [])
            if kind not in bucket:
                bucket.append(kind)
    basic_hosts = sorted({h for h, kinds in host_kinds.items() if "Basic" in kinds}
                         | {h for h, i in hosts.items() if (i or {}).get("scheme") == "Basic"})
    # Fix 1: 文件/流式响应端点（无 JSON schema，工具原样返回响应体）。
    file_endpoints = [e for e in endpoints if e.get("file_response")]
    tool_blocks = [_render_tool(e, prefix) for e in endpoints]
    if interactive_only:
        # 交互式登录的站点**不发射** `login()`/`_do_login()`：那套代码在这里必然失败
        # （验证码 / 二次验证不是构造请求能过的），发射它等于给用户一个「假装能自动
        # 重登录」的假承诺。改为发射浏览器窗口 + 用户确认的三个工具。
        tool_blocks.insert(0, _render_interactive_login_tools(auth_login, prefix))
    elif auth_login:
        tool_blocks.insert(0, _render_auth_login_tools(auth_login, prefix))
    if file_endpoints:
        # 只有真有文件端点时才发射 _raw_payload（纯 JSON 产物逐字节不变）。
        tool_blocks.insert(0, _render_file_response_helper())

    # raw 支持同样按需注入：无文件端点时三个占位符都替换成空串，_request 的源码
    # 与修复前**逐字节一致**。
    raw_param = raw_branch = raw_retry = ""
    if file_endpoints:
        raw_param = "                   raw: bool = False,\n"
        raw_branch = "    if raw:\n        return _raw_payload(resp)\n"
        raw_retry = "                                          raw=raw,\n"

    # 登录 query 参数的分流（`_login_query_plan`）：(c) 无害固定参数照旧烘进
    # `cfg['query_params']`；(a) 能自动取用的进 `cfg['login_query_fetch']`（只带
    # 「从哪取、取哪个字段」，不带任何抓包取值）；(b) 其余**绝不**进 cfg，只在
    # `cfg['login_query_params']` 留「参数名 → env 名」，取值由调用方入参或 .env 提供。
    # 交互式登录的站点**没有** `login()` 工具，也就没有 query 参数入参通道 ——
    # 登录整件事都在浏览器窗口里由用户完成，故这里按「无登录 query 参数」处理
    # （闸门关闭 → 模板里那几处占位符为空串，产物里不会凭空多出取用/必填代码）。
    login_plan = (_login_query_plan(auth_login, prefix) if auth_login and not interactive_only
                  else {"baked": {}, "required": [], "fetched": []})
    login_requires_input = bool(login_plan["required"])
    # Defect 1: analyzer 把校验接口**嵌套**存成 auth_login["verify"] = {host, path}，
    # 而 auth_status() 的探针读的是 cfg['verify_host'] / cfg['verify_path'] —— 键名对不上，
    # 探针永远进不去（verified 恒为 None）。这里在发进 server.py 前把它摊平成两个顶层键，
    # 探针才真正可用；没抓到校验接口时 verify_path 为空串，auth_status() 会如实说明。
    auth_login_literal = "None"
    if auth_login:
        _cfg = dict(auth_login)
        _verify = auth_login.get("verify") or {}
        _cfg["verify_host"] = _verify.get("host") or auth_login["host"]
        _cfg["verify_path"] = _verify.get("path") or ""
        # 纵深防御（Step 2）：脱敏哨兵 `***` 与空值**绝不能**进生成物——真发出去
        # 服务端收到的就是 `tenant=***`，登录必失败（`_clean` 只过滤 None）。
        _cfg["query_params"] = {
            name: value for name, value in login_plan["baked"].items()
            if value not in (None, "") and not _is_redaction_mark(value)}
        # 参数证据只用于渲染期分类（里面同样是 `***` 占位），运行期没人读它。
        _cfg.pop("query_param_evidence", None)
        # 「疑似来源」的**原始记录**（`analyzer.analyze_query_param_provenance` 附加）
        # 是分析侧元数据（含逐值结论、原因码、note），运行期没人读它，所以不原样烘进
        # `_AUTH_LOGIN_CFG`。**生成物要的是从它派生出来的取用计划** —— 那是上面
        # `_LOGIN_FETCH` 里的一份，只含来源 URL 与字段路径。registry.json /
        # analysis.json 照旧保留整份记录。
        _cfg.pop("query_param_provenance", None)
        # 两层判据的**结论**是分析侧元数据（运行期没人读它：判据只影响生成什么代码）。
        # 与 query_param_provenance 同理不烘进 `_AUTH_LOGIN_CFG`。
        _cfg.pop("post_login", None)
        if login_plan["required"]:
            _cfg["login_query_params"] = {item["name"]: item["env"]
                                          for item in login_plan["required"]}
        if login_plan["fetched"]:
            # 取用计划只留运行时真用得上的四个键；`field_display` 只用于文档。
            _cfg["login_query_fetch"] = [
                {key: item[key] for key in ("name", "method", "url", "field")}
                for item in login_plan["fetched"]]
        auth_login_literal = repr(_cfg)

    # `_clean` 的哨兵过滤（Step 2）以「存在 (b) 类登录 query 参数」为闸门：
    # 闸门关闭时模板逐字节不变（金标准良性语料 query_params 为空）。闸门恰好覆盖
    # 所有 registry 派生的哨兵——任何取值为 `***` 的登录参数都判不出 (c)，必然落进 (b)。
    clean_extra = (' and not (v == "***" or (isinstance(v, str) and len(v) >= 2'
                   ' and set(v) == {"*"}))') if login_requires_input else ""

    # Defect 2: 401 自动重登录后的重试必须带着 form_body —— 否则表单端点重试时
    # 退化成 json=None 且无表单 Content-Type，重登录成功后业务调用照样失败（读到的是
    # 「重登录没用」）。只在有 auth_login（即真有自动重登录路径）时注入，保持其它产物逐字节不变。
    form_retry = ""
    if auth_login:
        form_retry = "                                          form_body=form_body,\n"

    # 401 报错里「下一步该做什么」那句（模板里的 `__LOGIN_HINT__`）：
    #   * 交互式登录的站点 → 指向浏览器窗口重授权（**没有**自动重登录这回事）；
    #   * 其余项目 → 与修复前**逐字相同**的原文。没有登录通道时这句落在
    #     `if _AUTH_LOGIN_CFG:` 的死分支里，照原样保留原文，产物因此逐字节不变。
    login_hint = (_INTERACTIVE_401_HINT if interactive_only else _POST_LOGIN_401_HINT)

    # 凭据缓存解不开（换了电脑 / 换了 Windows 用户）时补一句可行动的下一步。它引用的是
    # `_render_auth_login_tools` 发射的 `_login_recovery_hint()` —— 交互式登录的产物里
    # **没有**那段代码（也没有凭据缓存），故那个分支关闭、改用上面的 login_hint。
    auth_401_extra = ""
    if auth_login and not interactive_only:
        auth_401_extra = "            hint += _login_recovery_hint()\n"

    # Cookie 鉴权：按 host 给出该站实际观测到的 Cookie 名（只剔除已知埋点；
    # `CREDENTIAL_COOKIES` 用的是同一份名单，两处不能各说各话），并说明填法。
    # 这份名单同时供 `.env.example`、README 与 401 报错指路 —— **必须是同一份**，
    # 否则报错会指向一个 .env 里根本不存在的变量（修复前就是这样）。
    cookie_hosts = {h: credential_cookie_candidates((info or {}).get("cookie_names"))
                    for h, info in (hosts or {}).items()}
    cookie_hosts = {h: n for h, n in cookie_hosts.items() if n}
    # 需要 `<PREFIX>_TOKEN` 的域名。`.env.example` / README「鉴权说明」/ 401 报错
    # 三处共用这一份结论（见 `_token_using_hosts` 的说明）。
    token_hosts = _token_using_hosts(hosts, host_kinds)

    server = (_SERVER_TEMPLATE
              .replace("__SITE_JSON__", json.dumps(site_name, ensure_ascii=False))
              .replace("__SITE__", _src_literal_text(site_name))
              .replace("__VERSION__", _src_literal_text(version))
              .replace("__PREFIX__", prefix)
              .replace("__CLEAN_EXTRA__", clean_extra)
              .replace("__AUTH_LOGIN__", auth_login_literal)
              .replace("__AUTH_BLOCK__", _render_auth_block(
                  prefix, hosts, endpoints,
                  state_cookie_hook=(
                      "    if not jar:\n"
                      "        # 交互式登录保存的登录态（auth_state.json）：用户手动登录过一次后，\n"
                      "        # Cookie 从这里来 —— 不必手工往 .env 里粘。\n"
                      "        jar.update(_cookies_from_auth_state(host))\n"
                  ) if interactive_only else ""))
              .replace("__LOGIN_HINT__", json.dumps(login_hint, ensure_ascii=False))
              .replace("__AUTH_FAIL_WHERE__",
                       _auth_failure_env_hint(prefix, cookie_hosts, token_hosts,
                                              basic_hosts))
              .replace("__RAW_PARAM__", raw_param)
              .replace("__RAW_BRANCH__", raw_branch)
              .replace("__RAW_RETRY__", raw_retry)
              .replace("__FORM_RETRY__", form_retry)
              .replace("__AUTH_401_EXTRA__", auth_401_extra)
              .replace("__TOOLS__", "\n\n".join(tool_blocks) or "pass"))

    files = {"server.py": server}
    req = "fastmcp>=2,<5\nhttpx>=0.27\n"
    if (auth_login or {}).get("password_encryption"):
        req += "cryptography>=42\n"
    if interactive_only:
        # 交互式登录要用 playwright 拉起真实浏览器窗口。**钉死版本**（不写范围）：
        # 浏览器内核按 playwright 版本缓存（1.63.0 ⇄ chromium-1243），放开为 `>=`
        # 后装到新版本会带来新修订号 → 用户机器上要重新下载整个浏览器。
        req += f"playwright=={_PLAYWRIGHT_PIN}\n"
    files["requirements.txt"] = req
    env_lines = [f"# {site_name} MCP 配置。复制为 .env 后填写。",
                 f"# 请求超时（秒）",
                 f"{prefix}_TIMEOUT=30"]
    if cookie_hosts:
        env_lines += [
            "# ── Cookie 鉴权 ──────────────────────────────────────────────",
            "# 抓到该站使用 Cookie 鉴权。填**整串**（分号分隔）最省事，",
            "# 值可在 web-api-extractor 的 auth_states/<site_key>.json 里找到"
            "（文件名 = netloc 的 `.`/`:` 换成 `_`）。",
        ]
        for h, names in sorted(cookie_hosts.items()):
            env_lines += [
                f"# {h} 需要的 Cookie: {', '.join(names)}",
                f'{prefix}_COOKIE_{_host_key(h)}="name1=value1; name2=value2"',
            ]
        env_lines += [
            "# 也可逐条填写：",
            *[f"# {prefix}_COOKIE_{_host_key(h)}_{re.sub(r'[^A-Z0-9]+', '_', n.upper())}=<value>"
              for h, names in sorted(cookie_hosts.items()) for n in names[:2]],
            "",
        ]
    # `_TOKEN` 这一行：没有 Cookie 通道时必须给；**同时有 Bearer / Basic 接口时也要给**
    # （README 的「鉴权说明」本来就写着「token 统一配置在 .env 的 <PREFIX>_TOKEN」，
    # 而 `.env.example` 此前不给这一行 → 照着 README 去配的人找不到地方填）。
    if not cookie_hosts:
        env_lines += [
            f"# 登录 token（站点未观测到 Cookie 鉴权时才需要）",
            f"{prefix}_TOKEN=",
        ]
    elif token_hosts:
        env_lines += [
            "# 登录 token（Bearer / Basic 接口需要；只认 Cookie 的接口不用）",
            f"{prefix}_TOKEN=",
        ]

    if interactive_only:
        # 交互式登录：**没有**账号密码配置项 —— 登录要在浏览器窗口里由用户本人完成，
        # 放两个 `_ACCOUNT` / `_PASSWORD` 只会让人以为「填了就能自动登录」。
        env_lines += [
            "# ── 登录 ────────────────────────────────────────────────────",
            "# 这个站点的登录**必须由人完成**（验证码 / 短信 / 二次验证），所以这里没有",
            "# 账号密码配置项。登录态保存在项目里的 auth_state.json，由 Agent 调用",
            "# login_interactive()（弹出浏览器窗口，你本人登录）→ confirm_login() 保存。",
            "# 上面的 Cookie 项仍然可用：想跳过浏览器窗口时，可把浏览器里的 Cookie 整串",
            "# 粘进来（过期后同样要重新授权一次，本服务不会自动续期）。",
        ]
    elif auth_login:
        env_lines += [
            "# 账号密码登录（**推荐**：这两项留空，交给 Agent 调用一次 login() ——",
            "# 它会在本机弹窗问你一次账号密码，口令不进对话、不写明文；成功后凭据与 token",
            "# 以 DPAPI 加密存入 cred_cache.bin / token_cache.bin，重启自动恢复，401 自动重登录）。",
            "# 下面两项是**旧配置的兼容 / 应急通道**（比如无人值守、弹不出窗口时）：填了照样能用，",
            "# 但明文写在磁盘上会泄密，登录成功后建议把这两行删掉。",
            f"{prefix}_ACCOUNT=",
            f"{prefix}_PASSWORD=",
        ]
        if login_plan["required"]:
            # 只放**占位符**，绝不写抓包真实值（那正是本次要拦的泄漏）。
            env_lines += [
                "# 登录接口以下 query 参数在抓包里的取值来源未能确认，未烘入代码。",
                "# 调用 login(...) **可以不填**：会依次尝试 入参 → 这里 → 本机弹窗询问，",
                "# 都取不到才报错并点名缺哪个。401 自动重登录不经过入参，只能从这里读，",
                "# 缺一个同样会报错并指明缺哪个变量（不会静默跳过重登录）。",
                *[f"{item['env']}=" for item in login_plan["required"]],
            ]
    # S13：按**端点**判断要不要 Basic 口令 —— 同一域名里可能只有一个接口用 Basic，
    # 只看主机级 scheme 就漏掉它，那个接口会因为口令为空而永远 401。
    for h in basic_hosts:
        env_lines.append("# Basic 口令（password 部分），来源见 README「鉴权说明」。")
        env_lines.append(f"{prefix}_BASIC_PASSWORD_{_host_key(h)}=")
    files[".env.example"] = "\n".join(env_lines) + "\n"
    files[".gitignore"] = ".env\naudit.log\nerror.log\n__pycache__/\n*.bak\ntoken_cache.bin\ncred_cache.bin\n"

    # README
    # 文档里出现的名字（工具名 / 参数名 / 路径）都来自抓包 → 统一过 `_doc_escape`，
    # 并把反引号去掉，免得文档里凭空多出代码段。
    _plain = lambda text: _doc_escape(text).replace("`", chr(39))  # noqa: E731
    lines = [f"# {site_name} MCP Server", "",
             f"由 web-api-extractor 从 **registry v{version}** 生成；共 {len(endpoints)} 个业务工具。",
             ""]
    mutating_endpoints = [e for e in endpoints
                          if e.get("method") not in ("GET", "HEAD")]
    if mutating_endpoints:
        # S33：写操作清单必须让用户**一眼看到** —— 只靠工具名旁边的 `[MUTATING]`
        # 标记，用户不点进表格就不知道哪些工具会真的改数据（可能撤不回来）。
        lines += ["## 重要：会修改服务器数据的工具", "",
                  "下面这些工具**不只是查询**：调用会真的改动服务器上的数据，"
                  "有些操作可能撤不回来。它们必须显式传 `confirm=true` 才会执行，"
                  "而且每次执行都会写进 `audit.log`"
                  "（下面工具清单里带 `[MUTATING]` 标记的就是它们）：", ""]
        for e in mutating_endpoints:
            note = _doc_escape(e.get("description") or "").replace("`", chr(39))
            lines.append(f"- `{e['tool_name']}`：{e['method']} {e['host']}{e['path']}"
                         + (f" —— {note}" if note else ""))
        lines += ["", "其余工具都只读，不会改动数据。", "",
                  "> 请只在你确实要做这件事的时候调用它们；不确定时先看 `tool_catalog` 里的说明。", ""]
    auth_required_hosts = {e.get("host") for e in endpoints if e.get("auth_required")}
    # `token_hosts` 已在渲染 `.env.example` 之前由 `_token_using_hosts` 算好（三处同源）。
    # 同一域名混用多种方式（S13）——「该域名下用到的鉴权方式不止一种」。
    mixed_hosts = sorted(h for h in hosts if len(host_kinds.get(h) or []) > 1)
    # 措辞按事实给：只有真出现混用时才讲「逐接口取用」，否则维持原话 —— 单方式的产物
    # 文案不必跟着变（内容等价，改动即噪音）。
    lines += ["## 鉴权说明", "",
              ("按抓包实测的方式**逐接口**生成（同一台服务器上不同接口可以不一样）："
               if mixed_hosts else "按抓包实测的 scheme 生成："), ""]
    for h, info in sorted(hosts.items()):
        info = info or {}
        scheme = info.get("scheme")
        kinds = host_kinds.get(h) or []
        if len(kinds) > 1:
            # 同一域名混用多种方式：不能只写其中一种，否则用户会以为另一半接口也用那种。
            # （哪些域名要 token 已由 `_token_using_hosts` 判过，此处只写说明文字。）
            desc = " / ".join("Cookie" if k == "cookie" else k for k in kinds)
        elif scheme and scheme != "Cookie":
            desc = scheme
        elif cookie_hosts.get(h):
            # 纯 Cookie 鉴权站点：scheme 为空**不等于**公开接口，
            # 接口实测仍需登录后的 Cookie。这里若按 scheme 判会误报成「公开接口」。
            desc = f"Cookie（{', '.join(cookie_hosts[h])}）"
        elif h in auth_required_hosts:
            desc = "需要鉴权（未识别出具体 scheme，请人工核对抓包）"
        else:
            desc = "无（公开接口）"
        lines.append(f"- `{h}`：{desc}")
    if token_hosts or not cookie_hosts:
        lines += ["", f"- token 统一配置在 `.env` 的 `{prefix}_TOKEN`。"]
    if cookie_hosts:
        if interactive_only:
            lines += ["", f"- Cookie 整串配置在 `.env` 的 `{prefix}_COOKIE_<HOST>`（分号分隔，可选）。"
                          "**也可以完全不配**：登录态由 `login_interactive()` 保存到项目里的"
                          " `auth_state.json`，本服务的工具会自动带上它（见下节「登录」）。"]
        else:
            lines += ["", f"- Cookie 整串配置在 `.env` 的 `{prefix}_COOKIE_<HOST>`（分号分隔，推荐）；"
                          "取值见 web-api-extractor 的 `auth_states/<site_key>.json`（netloc 的 `.`/`:` 换成 `_`）。"
                          "Cookie 过期后重跑一次 `open_browser_login` 覆盖该文件即可，"
                          "无需重建项目、无需重抓接口。"]
    if basic_hosts:
        lines += [f"- Basic 站点还需在 `.env` 填 `{prefix}_BASIC_PASSWORD_<HOST>`（base64 拼法中的 password 部分）。"
                  "它通常是前端 JS 里的固定字符串：在抓包会话的 scripts/ 目录搜 `btoa(` 或 `auth:{`，"
                  "从命中的那段里取出 base64 解码后的 password 部分即可。", ""]
    if mixed_hosts:
        # 用户不必知道这套机制，只要知道「不用你操心、每个接口会自动带对凭据」。
        # 具体是哪几种写在括号里，正文只说「按接口各带各的」—— 写死「有的用
        # Authorization、有的只认 Cookie」会在 Bearer+Basic 这类混用上说错。
        lines += ["- 这些服务器上**不同接口用了不同的登录方式**（"
                  + "、".join(f"`{h}`（{' / '.join('Cookie' if k == 'cookie' else k for k in (host_kinds.get(h) or []))}）"
                             for h in mixed_hosts)
                  + "）。本项目的工具会按每个接口实际的方式各自带上对应凭据，"
                    "你不需要手动区分，也不必额外配置。", ""]
    lines += ["## 工具清单", "", "| 工具 | 方法 | Host | 路径 | 说明 |", "|---|---|---|---|---|"]
    for e in endpoints:
        m = "**[MUTATING]** " if e.get("method") not in ("GET", "HEAD") else ""
        # Fix 1: 文件工具在清单里就能一眼认出（不点进 docstring 也知道它返回的是文件）
        f = "**[FILE]** " if e.get("file_response") else ""
        lines.append(f"| `{e['tool_name']}` | {e['method']} | {e['host']} | `{e['path']}` | {f}{m}{e.get('description') or ''} |")
    if file_endpoints:
        lines += ["## 文件 / 流式响应工具", "",
                  "以下端点的响应**不是 JSON**（CSV / PDF / XLSX / ZIP 等），工具返回响应体**原文**：",
                  "文本类在 `text`，二进制在 `base64`，并附 `content_type` / `status` / `content_disposition`。",
                  "**服务不写磁盘** —— 请把内容自行落盘（或转发给别的系统）。", ""]
        lines += [f"- `{e['tool_name']}`：{e['method']} {e['host']}{e['path']}"
                  for e in file_endpoints]
        lines += [""]
    forced_endpoints = [e for e in endpoints if e.get("forced_include")]
    if forced_endpoints:
        # Feature: 让读的人知道**为什么**一条本该被跳过的端点会出现在这里。
        lines += ["## 显式点名包含的端点", "",
                  "以下端点按筛选规则（噪音 / 不可独立调用 / 非 JSON 响应）本来**不会**生成，",
                  "是调用方在 `generate_mcp_server(include_endpoint_ids=[...])` 里显式点名包含的：", ""]
        lines += [f"- `{e['tool_name']}`：{e['method']} {e['host']}{e['path']}"
                  for e in forced_endpoints]
        lines += [""]
    lines += ["", "## 诊断工具（只读）", "",
              "- `tool_catalog`：工具清单 + registry_version（反馈问题请附上）",
              "- `error_log_tail`：最近错误日志", ""]
    if auth_login and interactive_only:
        lines += _interactive_login_readme(auth_login, prefix)
        # 「token 统一配置在 .env」这句对交互式登录的站点**不成立**（没有 login() 去换
        # token），换成同一份事实的说明 —— 与 `_LOGIN_HINT` 里那句同源。
        lines = [l for l in lines if not l.startswith("- token 统一配置在")]
        lines.insert(next(i for i, l in enumerate(lines) if l.startswith("## 工具清单")),
                     "- 登录态由 `login_interactive()` 保存到项目里的 `auth_state.json`"
                     "（见下节「登录」）。")
    elif auth_login:
        tp = ".".join(auth_login["token_path"])
        _req = login_plan["required"]
        # (b) 类参数的 README 说明：名字与 env 名都来自抓包 → 过一遍 `_doc_escape`
        # 再去掉反引号，免得文档里凭空多出代码段。
        _req_names = "、".join(f"`{_doc_escape(i['name']).replace('`', chr(39))}`" for i in _req)
        _req_envs = "、".join(f"`{i['env']}`" for i in _req)
        _req_kwargs = ", ".join(f"{i['ident']}=\"...\"" for i in _req)
        _req_usage = [] if not _req else [
            f"**登录接口还有 query 参数取值来源未能确认**：{_req_names}"
            "（抓包只观测到当时那一次会话的取值）。",
            "它们**不是必填**：不填也能调用，会依次尝试 调用入参 → `.env` → 本机弹窗询问；",
            "都取不到才明确报错，并点名缺的是哪个参数"
            "（名字像密码 / 令牌 / 密钥的，弹窗里是掩码输入，取值不进对话）。",
            f"401 自动重登录不经过工具入参，只能从 `.env` 读 {_req_envs} —— "
            "缺一个就会报错并指明缺哪个变量（不会静默跳过重登录）。"
            f"也可以带参调用 `login(account=\"...\", password=\"...\", {_req_kwargs})`。", ""]
        _fetch = login_plan["fetched"]
        _fetch_usage = [] if not _fetch else [
            "**以下登录 query 参数由服务自动获取**，你**不需要**填写：",
            *[f"- `{_plain(i['name'])}`：先调 `GET {_plain(i['url'])}`，"
              f"取响应字段 `{_plain(i.get('field_display') or '')}`"
              "（抓包时它的值就是从那里来的）。" for i in _fetch],
            "若该接口变得需要登录才能访问，登录会**明确报错**并提示重新抓包，不会静默失败。", ""]
        lines += ["## 登录", "",
                  f"抓包识别到账号密码登录接口：`{auth_login['method']} {auth_login['host']}{auth_login['path']}`", "",
                  "**什么都不用配：调用一次 `login()` 就行。**",
                  "它会在你的电脑上弹出一个窗口，问你一次账号与密码（密码是掩码输入）；敲一次即可 ——",
                  "口令不会出现在对话里，也不会明文写进磁盘"
                  + ("（这个登录接口另有 query 参数，见下）。" if (_req or _fetch) else "。"),
                  "（也可以直接带参调用 `login(account=\"...\", password=\"...\")`；",
                  "若本机弹不出窗口，就在对话里把账号密码告诉 Agent，由它带参调用。）", "",
                  "**换了电脑、或换了另一个 Windows 登录用户之后登录会失败**：加密保存的凭据",
                  "（`cred_cache.bin`）换了用户就解不开。出路只有一条 —— **删掉项目里的",
                  "`cred_cache.bin`，再调用一次 `login()` 重新登录**。",
                  "**把这份服务发给同事时，凭据不随包走**（加密文件只在本机、同一个 Windows 用户下",
                  "可解）；对方自己 `login()` 一次即可。", "",
                  *_fetch_usage,
                  *_req_usage,
                  f"成功后 token 取自响应字段 `{tp}`，并加密缓存到 `token_cache.bin`（见下），重启自动恢复；",
                  f"也可以跳过登录，直接把浏览器里取到的 token 填进 `{prefix}_TOKEN`。", "",
                  "`auth_status()` 可查看当前 token 来源、凭据缓存状态（`credentials_cache_state`：",
                  "`missing` 没登录过 / `ok` 正常 / `unreadable` 换电脑或换用户后解不开）与下一步建议"
                  "（只读，不会触发登录）。", ""]
        # Defect 1: README 不能承诺生成物做不到的校验 —— 只有抓包真的记录了校验接口时，
        # auth_status() 才会去探测；否则它如实报告「无法验证」（verified: null）。
        _verify = auth_login.get("verify") or {}
        if _verify.get("path"):
            lines += [f"校验登录态：抓包记录了校验接口 `GET {_verify.get('host') or auth_login['host']}"
                      f"{_verify['path']}`，`auth_status()` 会调用它确认 token 是否仍有效"
                      "（`verified` 为 `true`/`false`）。", ""]
        else:
            lines += ["本次抓包**没有记录可用于校验的接口**，因此 `auth_status()` 只报告 token 来源，",
                      "不会声明 token 是否有效（`verified` 恒为 `null`，`verify_detail` 会说明原因）。", ""]
        enc = auth_login.get("password_encryption") or {}
        if enc:
            lines += [f"密码按前端实测策略加密后传输：`{enc.get('scheme')}`（加密版本 `{enc.get('version')}`）。",
                      "公钥取自前端 JS 的 PEM 块，已内联在 server.py 中，无需手工配置。", ""]
        else:
            lines += ["登录接口按明文 JSON 提交密码（抓包实测未发现前端加密）。", ""]
        lines += ["> `.env` 里的 `" + prefix + "_ACCOUNT` / `" + prefix + "_PASSWORD` 是**旧配置的兼容通道**",
                  "> （仍可读，比如无人值守、弹不出窗口时），但它是**明文**；改用 `login()` 之后，",
                  "> 建议把那两行删掉。",
                  "> 凭据与 token 以 **DPAPI 加密**存入 `cred_cache.bin` / `token_cache.bin`",
                  "> （仅同一 Windows 用户可解密，已列入 .gitignore），重启自动恢复，401 自动重登录。",
                  "> `login` 的审计日志只记录脱敏账号与加密策略，不记录密码。", ""]
        lines = [l for l in lines if not l.startswith("- token 统一配置在")]
        lines.insert(next(i for i, l in enumerate(lines) if l.startswith("## 工具清单")),
                     f"- token 也可由 `login()` 动态获取（见下节「登录」）。")
    # 「哪些参数沿用了抓包取值作默认值」必须让使用者看得见 —— 且**只列参数名**：
    # 把取值一起印出来等于把抓包数据塞进文档，既噪音又多一个泄漏面。
    _baked = baked_param_defaults(endpoints, auth_login)
    if _baked:
        lines += ["", "## 默认参数取值来自抓包", "",
                  "以下参数在抓包时带了具体取值，生成的服务把它们当作**默认值**"
                  "（调用时不传就用这个值）：", ""]
        for item in _baked:
            label = item.get("tool") or item.get("endpoint_id") or item.get("path") or "?"
            names = "、".join(f"`{_plain(n)}`" for n in item["params"])
            lines.append(f"- `{_plain(label)}`：{names}")
        lines += ["",
                  "这些值是抓包那次会话的值，**不一定适用于别人**。把这份服务分享给别人之前，",
                  "请先检查上面这些参数；需要别的值时，调用工具时显式传参即可。", ""]
    files["README.md"] = "\n".join(lines) + "\n"

    get_endpoint, smoke_reasons, smoke_caveats = _smoke_endpoint(endpoints)
    if interactive_only and get_endpoint:
        # 交互式登录的项目：冒烟很可能 401（会话还没建立），而它在 README 里没有账号密码
        # 可配 —— 不给这句话，接手的人只会去翻 .env 找一个并不存在的变量。
        smoke_caveats.append(
            "这个站点的登录要人工完成（验证码 / 二次验证）：冒烟返回 401 时，先让用户调用"
            "一次 login_interactive()，在弹出的浏览器窗口里登录，再用 confirm_login() 保存，"
            "然后重跑冒烟。")
    smoke_host = json.dumps(get_endpoint["host"]) if get_endpoint else "None"
    smoke_path_tmpl = get_endpoint["path"] if get_endpoint else ""
    # S13：冒烟必须与工具**用同一套**鉴权 —— 不带 auth_tool 时 `_request` 会退回该
    # 域名的主方式，混用站点上就可能出现「冒烟通过、某个工具 401」的假绿灯。
    smoke_auth_tool = (_py_ident(get_endpoint["tool_name"]) if get_endpoint else None)
    # 冒烟参数**不烘抓包当时的真实值**：此前是把每个 query 参数的第一个样本原样
    # 写进分发包的 smoke_test.py —— 那里可能有 token、objectid、邮箱（实测
    # `{"token": "SUPERSECRET", "uid": "alice"}`），泄漏且很快过期。
    # 只保留「已经够安全、允许进工具签名」的那些（复用同一套门槛）。
    # 「查询即内容」的必填参数（required_query_param）例外：它不能省略（会退化成无界
    # 查询），也不能烘抓包取值，故与生成的工具**用同一份**安全默认值（`_safe_default_query`）
    # —— 这样冒烟脚本与默认值策略自洽（工具签名里是什么，冒烟就发什么）。
    if get_endpoint:
        smoke_evidence = dict(get_endpoint.get("query_param_evidence") or {})
        required_name = (get_endpoint.get("required_query_param") or {}).get("param")
        smoke_params: dict[str, Any] = {}
        for key, values in (get_endpoint.get("query_params") or {}).items():
            if key == required_name:
                safe = _safe_default_query(key, values)
                if safe is not None:
                    smoke_params[key] = safe
                continue
            value = _stable_default_value(key, values, smoke_evidence.get(key))
            if value is not None:
                smoke_params[key] = value
        smoke_qp = json.dumps(smoke_params, ensure_ascii=False)
    else:
        smoke_qp = "{}"
    # S25：把「为什么选它」写进生成物注释 —— 使用者/接手的人能自己判断这个选择是否合理。
    smoke_doc = (f"{site_name} MCP 冒烟自检：对一个只读 GET 接口发一次请求，"
                 "验证连通与鉴权是否配好。\n\n"
                 "    选中端点：" + (f'GET {smoke_path_tmpl}（host {get_endpoint["host"]}）'
                                  if get_endpoint else "（本次抓包没有 GET 端点，无法冒烟）") + "\n"
                 "    选择理由：" + ("；".join(smoke_reasons) if smoke_reasons else "无可用 GET 端点") + "。\n"
                 "    只做读操作，不会发送任何写请求（POST/PUT/PATCH/DELETE）。"
                 + ("\n    注意：" + " ".join(smoke_caveats) if smoke_caveats else "") + "\n    ")
    files["smoke_test.py"] = (
        '# -*- coding: utf-8 -*-\n'
        f'"""{_src_literal_text(smoke_doc)}"""\n'
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
        f'    result = await server._request(host, "GET", path, params=params or None,\n'
        f'                                   auth_tool={smoke_auth_tool!r})\n'
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
def generate(session_dir: Path, output_dir: Path, endpoint_ids: list | None = None,
             include_endpoint_ids: list | None = None) -> dict:
    """One-shot: analysis.json → fresh project → rendered files.

    ``endpoint_ids``：只生成这些衔接键对应的端点（**语义不变**：键按条目自带的
    ``endpoint_id`` 解析，未知或会被跳过的键一律 fail-loud 报
    ``Unknown endpoint_ids``，不做隐式别名）。

    Feature — ``include_endpoint_ids``：用户复核 ``not_generated`` 后「我就是要它」
    的显式出口。列在这里的键**绕过全部跳过规则**（噪音 / 不可独立调用 / 非 JSON
    响应）照常生成，条目上打 ``forced_include: True``，生成的 README 里单独列一节
    说明它们为什么在。它与 ``endpoint_ids`` 是**并集**关系（两边都点名只生成一次）。

    覆盖已有项目 — ``output_dir`` 里已经有项目（``registry.json`` / ``project.json``）时
    **不再拒绝**：先把整个目录**复制**到旁边的 ``<dir>.bak-<时间戳>``，再照常覆盖。因为
    本函数走 ``init_project``，会把已有 registry 重建成空的（端点和用户写的 description /
    notes / param_provenance 一起丢），所以备份是**必要条件**：宁可多一份备份，也不能
    静默删掉使用者的东西。备份路径出现在返回值的 ``backup_path`` 与 ``message`` 里。
    （续作仍是 ``regenerate`` 或 ``diff_registry`` → ``merge_registry``，只增不减。）
    """
    # 先读会话（这一步失败时还**没写任何东西**，也不必白复制一份备份）。
    analysis = json.loads((Path(session_dir) / "analysis.json").read_text(encoding="utf-8"))
    # 再备份：必须**先于任何写入**，否则覆盖一开始，旧项目就没了。
    # 概况同样要在覆盖前读（覆盖后读到的已经是新一轮的数字）。
    before = existing_project_summary(output_dir)
    backup_path = backup_existing_project(output_dir)
    session_id = Path(session_dir).name
    forced_ids = [str(i) for i in include_endpoint_ids] if include_endpoint_ids else None
    entries, hosts = session_to_registry_entries(
        analysis, session_id, include_endpoint_ids=forced_ids)
    if endpoint_ids is not None:
        # 用条目自带的 endpoint_id，**不要**按位置重编：entries 已经过滤掉噪音 /
        # 不可独立调用 / 非 JSON 的端点，按位置编号会让 id 指向别的端点
        # （实测：一个心跳接口就能让 ep_002 落到另一条路径上，ep_003 直接报错）。
        by_id = {e["endpoint_id"]: e for e in entries if e.get("endpoint_id")}
        missing = [i for i in endpoint_ids if i not in by_id]
        if missing:
            raise ValueError(f"Unknown endpoint_ids: {', '.join(sorted(missing))}")
        # 被显式点名的端点「照常生成」——即便调用方同时用 endpoint_ids 圈定了子集，
        # 点名包含的那些也在并集里（否则 include_endpoint_ids 会被静默忽略）。
        selected = list(endpoint_ids)
        for forced_id in forced_ids or []:
            if forced_id not in selected and forced_id in by_id:
                selected.append(forced_id)
        entries = [by_id[i] for i in selected]
    site_name = _site_name_from_session_id(session_id)
    init_project(output_dir, site_name)
    set_auth_login(output_dir, analysis.get("auth_login"))
    result = merge_registry(output_dir, entries, hosts, session_id)
    if not result.get("success"):
        return result
    registry = load_registry(output_dir)
    files = render_server(registry)
    write_files(output_dir, files)
    # R1：把「哪些参数沿用了抓包取值作默认值」如实报出去（**只给参数名 + 端点，不带取值**），
    # 让 Agent 能对使用者说清「分享前该检查什么」。
    defaults = baked_param_defaults(registry["endpoints"], registry.get("auth_login"))
    result = {"output_dir": str(output_dir), "files": sorted(files),
              "endpoint_count": len(registry["endpoints"]),
              "registry_version": registry["registry_version"],
              "requires_auth_setup": any(e.get("auth_required") for e in registry["endpoints"]),
              "param_defaults": defaults,
              # Feature: 实际被显式点名包含的衔接键（拼错的键不会静默消失在结果里）。
              "forced_include": sorted(e["endpoint_id"] for e in registry["endpoints"]
                                       if e.get("forced_include") and e.get("endpoint_id")),
              "file_response": sorted(e["tool_name"] for e in registry["endpoints"]
                                      if e.get("file_response"))}
    if defaults:
        result["param_defaults_notice"] = baked_param_notice(defaults)
    # R4：覆盖了已有项目就必须**把备份路径说出来**，否则使用者以为数据没了。
    if backup_path:
        result["backup_path"] = backup_path
        result["message"] = overwrite_notice(backup_path, before)
    return result
