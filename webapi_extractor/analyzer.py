"""Pure analysis helpers used by the capture analyzer."""

from __future__ import annotations

import re
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qsl, quote_plus, unquote_plus, urlsplit, urlunsplit

from .bodies import parse_form_urlencoded
from .crypto_analyzer import detect_password_encryption
# 头合并只有 capture.py 一份实现：redact + ExtraInfo 的大小写不敏感合并规则
# 必须与抓包侧**完全相同**，否则「落盘的头」与「分析用的头」会再次分叉
# （本仓库已经吃过两份登录判定各自跑偏的亏，见 tests/test_login_confirmation.py）。
from .capture import _merge_headers


VALUE_SHAPES = (
    re.compile(r"^\d+$"),                      # 123, 6463
    re.compile(r"^[0-9a-f]{8,}$", re.I),       # hex ids
    # Generic alphanumeric ids MUST contain a digit and be >= 6 chars — otherwise
    # plain words like "community" (9 chars, no digit) or "next2" (5 chars) match
    # and whole literal path segments get wrongly collapsed into {id}.
    re.compile(r"^(?=.*\d)[A-Za-z0-9_-]{6,}$"),
)


# --------------------------------------------------------------------------- #
# registry 落盘前的 URL / query 凭据擦除
#
# 抓包 URL 不脱敏是**有意**的（captures/analysis.json 是本地溯源，不分发）。但
# registry.json 是产品产物，又随 project.export_user_package 原样交给同事 ——
# 抓包 URL 里的任何**取值**（?token=… / ?signature=… / session id / 邮箱…）
# 都不能进 registry，更不能进分发包。两条出口：
#   * sample_url → scheme+host+path + 参数名，取值换成 ``REDACTED``；
#   * query_params / query_param_evidence.values → 身份/凭据类参数的值换成 ``***``
#     （与 redaction.py 的哨兵一致，generator 拒绝把它烘成默认值）；
# 良性的固定参数（page / size / format…）取值照旧保留 —— 生成器的默认值靠它，
# 那些值也本来就会通过 generator 的「名字不像身份、值不像真实数据」两道闸门。
# --------------------------------------------------------------------------- #
URL_QUERY_REDACTED = "REDACTED"
_REDACTION_SENTINEL = "***"

# 名字里带这些词（切词或子串）的参数，其取值一律遮蔽。
_CREDENTIAL_QUERY_WORDS = frozenset({
    "token", "auth", "authorization", "bearer", "jwt", "secret", "password",
    "passwd", "pwd", "pass", "credential", "credentials", "key", "apikey",
    "signature", "sig", "sign", "hmac", "hash", "session", "sessionid", "sid",
    "jsessionid", "phpsessid", "csrf", "xsrf", "nonce", "state", "code",
    "ticket", "cookie", "id", "ids", "uid", "uuid", "guid", "no", "num",
    "user", "username", "account", "acct", "email", "mail", "phone", "mobile",
    "tel", "recipient", "member", "customer", "client", "tenant", "org",
    "employee", "staff", "author", "owner",
})

# 取值本身像「具体数据」的形态（token / PII / 长 id）。
_CREDENTIAL_VALUE_PATTERNS = (
    re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$"),                    # 邮箱
    re.compile(r"^\+?\d[\d\s()-]{6,}$"),                          # 电话
    re.compile(r"^\d{5,}$"),                                      # 5 位以上纯数字
    re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
               r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),              # UUID
    re.compile(r"^(?:[0-9a-fA-F]{2}){16,}$"),                     # 长 hex
    re.compile(r"^[A-Za-z0-9+/_=-]{24,}$"),                       # 长 token / base64
)


def _query_name_words(name: str) -> set[str]:
    """把参数名切成小写词：`accessToken`→{access,token}，`user_id`→{user,id}。"""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(name or ""))
    return {w for w in re.split(r"[^0-9a-zA-Z]+", spaced.lower()) if w}


def query_param_is_sensitive(name: str, value: Any = None) -> bool:
    """参数名像凭据/身份，或取值像具体数据 → registry 里必须遮蔽取值。"""
    low = str(name or "").lower()
    if _query_name_words(name) & _CREDENTIAL_QUERY_WORDS:
        return True
    if any(word in low for word in ("token", "secret", "password", "passwd",
                                    "session", "signature", "apikey", "csrf",
                                    "bearer", "auth", "cookie")):
        return True
    if value is not None:
        text = str(value)
        if text and any(pattern.match(text) for pattern in _CREDENTIAL_VALUE_PATTERNS):
            return True
    return False


def _redact_url_query(raw: str) -> str:
    """`a=1&b=2` → `a=REDACTED&b=REDACTED`；裸标记留名不留值；非 k=v 整体丢弃。"""
    pairs = parse_qsl(raw, keep_blank_values=True)
    if not pairs:
        return ""
    return "&".join(
        f"{quote_plus(key)}={URL_QUERY_REDACTED}" if value else quote_plus(key)
        for key, value in pairs)


def sanitize_sample_url(url: Any) -> Any:
    """把抓包 URL 里 query/fragment 的**取值**换成占位符，只保留参数名。

    非字符串 / 空值原样返回（老 registry 里 ``sample_url`` 可能就是 None）；
    没有 query（因而没有凭据）时 URL 原样透传，不制造 diff 噪音。
    """
    if not isinstance(url, str) or not url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:                       # 极端非法 URL：退回最保守的裁剪
        return url.split("?", 1)[0].split("#", 1)[0]
    if parts.query:
        parts = parts._replace(query=_redact_url_query(parts.query))
    if parts.fragment:
        parts = parts._replace(fragment=_redact_url_query(parts.fragment))
    return urlunsplit(parts)


def as_value_list(value: Any) -> list:
    """把 query 参数的取值样本统一成 list。

    endpoint 的 ``query_params`` 一律是 ``{名: [值…]}``；而 ``auth_login`` 在本次修改
    之前存的是 ``{名: 首个取值}`` 的**标量**，老 registry 里仍可能是那样。清洗与分类
    都按 list 处理，故先把两种形状归一（标量直接当单元素列表，None 当空）。
    长度不是问题的信号——旧值只剩最后一个标量，也不能当「只有一个样本」用。
    """
    if isinstance(value, (list, tuple)):
        return list(value)
    return [] if value is None else [value]


def sanitize_query_params(params: Any) -> dict[str, list[str]]:
    """保留参数名，遮蔽凭据/身份类参数的取值（值本身像数据的也逐值遮蔽）。"""
    cleaned: dict[str, list[str]] = {}
    for name, values in (params or {}).items():
        items = as_value_list(values)
        if query_param_is_sensitive(name):
            cleaned[str(name)] = [_REDACTION_SENTINEL for _ in items]
        else:
            cleaned[str(name)] = [
                _REDACTION_SENTINEL if query_param_is_sensitive(name, value) else value
                for value in items]
    return cleaned


def sanitize_query_param_evidence(evidence: Any) -> dict[str, Any]:
    """与 query_params 同规则清洗 evidence 里逐参数的 ``values`` 样本。"""
    cleaned: dict[str, Any] = {}
    for name, entry in (evidence or {}).items():
        if isinstance(entry, dict) and isinstance(entry.get("values"), list):
            entry = dict(entry)
            if query_param_is_sensitive(name):
                entry["values"] = [_REDACTION_SENTINEL for _ in entry["values"]]
            else:
                entry["values"] = [
                    _REDACTION_SENTINEL if query_param_is_sensitive(name, value) else value
                    for value in entry["values"]]
        cleaned[str(name)] = entry
    return cleaned


# --------------------------------------------------------------------------- #
# C-3: 内置噪音规则（标记 noise:true，不删除——保留人工复核权）
#
# Issue #2: 规则保持**通用**——只收录跨站点成立的遥测/指纹域名与框架内部
# 元数据路径，不得硬编码单一目标系统（Issue #8 的教训）。
# --------------------------------------------------------------------------- #
NOISE_PATH_PATTERNS = (
    # 通用埋点/统计路径
    r"/system/stat/", r"/system/traffic/", r"/tracking/", r"heartbeat",
    r"/breadcrumb", r"/config/menu/", r"/config/banner", r"/visit-history/",
    r"/analytics/", r"/telemetry/", r"/beacon", r"^(?:log|collect)[/-]",
    # 框架/服务端内部元数据（Dynamics/CRM、SAP、SharePoint、Graph 等常见形态）
    r"GetClientMetadata", r"/uclient/", r"/_static/", r"/webresources/",
    r"/formattedvalue|/metadata/|/\$metadata\b",
)

# 遥测/埋点/浏览器指纹域名（通用生态，可被 tracking_domains 参数扩展）
NOISE_DOMAINS = {
    # 中文互联网生态
    "r.clarity.ms", "otheve.beacon.qq.com", "aegis.qq.com", "graph.qq.com",
    "www.google-analytics.com", "analytics.google.com", "log.zhugeio.com",
    # Microsoft 生态（遥测 + 浏览器配置/指纹）
    "vortex.data.microsoft.com", "browser.pipe.aria.microsoft.com",
    "fpc.msedge.net", "v10.events.data.microsoft.com",
    "settings-win.data.microsoft.com", "watson.telemetry.microsoft.com",
    # 其它常见遥测/分析生态
    "www.googletagmanager.com", "stats.g.doubleclick.net",
    "api.segment.io", "cdn.segment.com", "sentry.io", "browser.sentry-cdn.com",
    "js.sentry-cdn.com", "rum.browser-intake-datadoghq.com",
    "browser-intake-datadoghq.com", "api.amplitude.com", "cdn.amplitude.com",
    "api.mixpanel.com", "cdn.mxpnl.com", "static.hotjar.com", "script.hotjar.com",
    "in.hotjar.com", "connect.facebook.net", "www.facebook.com",
    "bat.bing.com", "c.clarity.ms", "sb.scorecardresearch.com",
}
# 子域后缀匹配（同域下大量随机子域的埋点）
NOISE_HOST_SUFFIXES = (
    ".clarity.ms", ".hotjar.com", ".sentry.io", ".datadoghq.com",
    ".amplitude.com", ".mixpanel.com", ".segment.io", ".doubleclick.net",
)


def _bare_host(host: str) -> str:
    """去掉端口再比对域名（IPv6 字面量 ``[::1]:443`` 保持原样）。

    端点的 host **故意保留端口**（生成的多域名路由要用它，见
    `tests/test_iterate_tools.py::TestMergeCaptureTool::test_endpoint_key_host_may_carry_a_port`），
    但噪音规则集里的域名不带端口：直接比较会双向漏判——遥测域名挂在非默认端口上
    （``aegis.qq.com:8443``）逃过标记，而 ``NOISE_DOMAINS`` 里写成 ``host:port`` 也
    永远匹配不到任何端点。
    """
    text = (host or "").strip()
    if text.startswith("["):
        return text
    return text.split(":", 1)[0]


def _is_noise(host: str, path: str) -> bool:
    bare_host = _bare_host(host)
    if bare_host in NOISE_DOMAINS or bare_host.endswith(NOISE_HOST_SUFFIXES):
        return True
    return any(re.search(p, path, re.I) for p in NOISE_PATH_PATTERNS)


# --------------------------------------------------------------------------- #
# Issue #12: 凭据 Cookie 判定
#
# 修复前 auth_required 只检查 Authorization 头与 auth_candidate，**完全没看 Cookie**。
# 于是 CDP 能抓到 Cookie（#1 已修）后，判定仍全部为 False，
# 生成的代码不带任何鉴权（实测生成的工具会因缺少鉴权而全部返回 401）。
#
# 但也不能「见到 Cookie 就算需要鉴权」——埋点 Cookie（Application Insights 的
# ai_user/ai_session、GA 的 _ga 等）几乎每个站点都有，会变成噪音。
# 故按「疑似凭据」的命名特征判定，并显式排除已知埋点。
#
# ⚠️ 这两个问题由**同一份判据**回答（本次重做：此前各用一套，导致摘要与生成物互相
# 矛盾 —— 抓包里只有 `startupapp` 这类无标记名字时，auth_required 报 False，
# 而生成的 server 照样把整罐 Cookie 发出去）：
#   「生成物要让用户填/发送哪些 Cookie？」= `credential_cookie_candidates`
#     —— **观测到的名字默认全保留**，只剔除已知埋点名单。不认识 ≠ 不是凭据：
#     实测 Citrix ADC 的设备靠 SESSID/startupapp/is_cisco_platform/NITRO_SK/
#     rdx_pagination_size 五个 Cookie 一起才认会话。按窄名单过滤会让生成物只填
#     SESSID，服务端回 `1026 Not logged in` 且**不告诉你缺谁**。
#   `is_credential_cookie` 只是「像不像凭据」的窄名单，保留给需要窄判定的地方
#   （如 `credential_cookies_in`）；**它不再参与 auth_required 判定**。
# --------------------------------------------------------------------------- #
_CREDENTIAL_COOKIE_MARKERS = (
    "sess", "auth", "token", "sid", "login", "jwt", "ticket",
    "sso", "credential", "remember", "signin",
)

# 已知埋点/分析类 Cookie，即使名字命中上面的特征也不算凭据
_ANALYTICS_COOKIE_PATTERNS = (
    re.compile(r"^ai_", re.I),            # Application Insights
    re.compile(r"^_ga", re.I),            # Google Analytics
    re.compile(r"^_gid$", re.I),
    re.compile(r"^_gcl", re.I),
    re.compile(r"^amplitude", re.I),
    re.compile(r"^mp_", re.I),            # Mixpanel
    re.compile(r"^hj", re.I),             # Hotjar
    re.compile(r"^_clck|^_clsk", re.I),   # Clarity
    re.compile(r"^optimizely", re.I),
    re.compile(r"^_fbp$|^_fbc$", re.I),   # Facebook Pixel
)


def is_tracking_cookie(name: str) -> bool:
    """是否命中**已知**埋点/分析类 Cookie 名单。

    这是唯一一类「可以证明与凭据无关」的 Cookie（`_ANALYTICS_COOKIE_PATTERNS`
    就是那张名单本身，不是靠猜名字长什么样）。

    >>> is_tracking_cookie("ai_session")
    True
    >>> is_tracking_cookie("NITRO_SK")   # 不认识 —— 不等于埋点
    False
    """
    if not name:
        return False
    return any(p.search(name) for p in _ANALYTICS_COOKIE_PATTERNS)


def is_credential_cookie(name: str) -> bool:
    """Cookie 名是否像会话凭据（**仅用于 auth_required 判定**）。

    注意这是「疑似」名单：它认得 `MSISAuth`，但认不出 `startupapp` /
    `NITRO_SK` / `rdx_pagination_size` 这类真实会话 Cookie。因此**不要**拿它
    过滤生成物要用户填写的 Cookie 名单 —— 那条路用
    `credential_cookie_candidates`（默认全保留）。

    >>> is_credential_cookie("MSISAuth")
    True
    >>> is_credential_cookie("ai_session")   # Application Insights 埋点
    False
    >>> is_credential_cookie("ReqClientId")  # 设备标识，非凭据
    False
    """
    if is_tracking_cookie(name):
        return False
    low = name.lower()
    return any(m in low for m in _CREDENTIAL_COOKIE_MARKERS)


def credential_cookie_candidates(names: Any) -> list[str]:
    """生成物应当要求用户提供的 Cookie 名（保序、去重）。

    原则：**在站点实际接受的请求上观测到的名字，默认全保留**；只有命中
    `is_tracking_cookie`（已知埋点）的才剔除。绝不因为「名字不认识」就丢 ——
    Cookie 鉴权是集合语义，一个会话通常需要整罐 Cookie，而服务端（实测 Citrix
    ADC/NITRO）返回 `1026 Not logged in` 时不会告诉你少了哪一个，用户无从诊断。

    >>> credential_cookie_candidates(["SESSID", "startupapp", "_ga"])
    ['SESSID', 'startupapp']
    """
    found: list[str] = []
    for name in names or []:
        name = str(name).strip()
        if not name or is_tracking_cookie(name) or name in found:
            continue
        found.append(name)
    return found


def credential_cookies_in(header_value: str) -> list[str]:
    """从 Cookie 头值中挑出**疑似凭据**的名字（窄名单，仅供需要「像不像凭据」时用）。"""
    found: list[str] = []
    for part in (header_value or "").split(";"):
        name = part.split("=", 1)[0].strip()
        if is_credential_cookie(name) and name not in found:
            found.append(name)
    return found


def _cookie_names_in(header_value: str) -> list[str]:
    """Cookie 头里观测到、且**不是已知埋点**的名字（与生成物实际发送的名单同源）。

    这条判据必须与 `generator._render_auth_block` 交给 `CREDENTIAL_COOKIES` 的名单
    完全一致（两边都走 `credential_cookie_candidates`），否则会出现
    「生成的 server 会发送整罐 Cookie，而 auth_required 却报 False」这种
    「分析结论与生成行为互相矛盾」的状态：Cookie 鉴权是集合语义，服务端不认缺了谁的
    半罐 Cookie（实测 Citrix ADC 的会话只由 startupapp / NITRO_SK 等无标记名字组成）。
    """
    if not header_value:
        return []
    return credential_cookie_candidates(
        [part.split("=", 1)[0].strip() for part in str(header_value).split(";")])


def _has_credential_cookie(headers: dict[str, Any]) -> bool:
    """请求头里的 Cookie 是否含**生成物会发送**的 Cookie（头名大小写不敏感）。

    Issue #12 的窄名单（`is_credential_cookie`）只认得 SESSID/JSESSIONID 这类名字，
    于是「只用 startupapp 的设备」被报成不需要鉴权，而生成的 server 照样会把这罐
    Cookie 发出去 —— 摘要与生成物对同一件事给出相反结论。这里改用与生成物**同一份**
    名单（观测到的全部名字，减去已知埋点），两侧不再各说各话。
    """
    if not headers:
        return False
    for key, value in headers.items():
        if str(key).lower() == "cookie" and value:
            if _cookie_names_in(str(value)):
                return True
    return False


def _auth_hints_in(headers: dict[str, Any] | None) -> list[str]:
    """单个请求里**实际发出**的鉴权载体（S13 端点级鉴权）。

    返回值的元素只有两类，直接来自这条请求自己的头：

      * Authorization 的 scheme 原文（``"Bearer"`` / ``"Basic"`` / …）；
      * ``"cookie"``（该请求带了**生成物会发送的** Cookie，名单同
        `credential_cookie_candidates`）。

    为什么必须**按端点**记，而不是按主机记一种：实测同一域名下可以混用两种方式
    （``Authorization: Bearer`` 的接口 + 只认 ``JSESSIONID``/``NITRO_SK`` 纯 Cookie 的
    接口）。按主机记一种时，前者会把后者的 scheme 覆盖掉，生成物于是给「只认 Cookie 的
    接口」发 ``Authorization``、根本不发 ``Cookie`` —— 那些接口稳定 401，且服务端不会
    说缺什么。一条都没观测到时返回 ``[]``（由调用方写成 ``["none"]``）。
    """
    hints: list[str] = []
    for key, value in (headers or {}).items():
        if not value:
            continue
        low = str(key).lower()
        if low == "authorization":
            scheme = str(value).split(" ", 1)[0].strip()
            if scheme and scheme not in hints:
                hints.append(scheme)
        elif low == "cookie":
            if _cookie_names_in(str(value)) and "cookie" not in hints:
                hints.append("cookie")
    return hints


def _merge_auth_hints(*groups: Any) -> list[str]:
    """把多组端点级 hint 取并集（保序、去重）。

    ``"none"`` 只是「这一组没观测到」的占位，一旦有任何一组观测到具体方式，它就不该
    继续出现在结果里 —— 否则「合并后这条参数化路径到底要不要鉴权」会被一个占位符
    说成「不用」。全部都是占位时保留 ``["none"]``。
    """
    merged: list[str] = []
    for group in groups:
        for hint in group or []:
            hint = str(hint)
            if hint and hint != "none" and hint not in merged:
                merged.append(hint)
    return merged or ["none"]


def _request_needs_auth(request: dict[str, Any]) -> bool:
    """单个请求是否携带了鉴权凭据。

    三条判据（任一成立即视为需要鉴权）：
      1. 显式 Authorization 头
      2. 抓包阶段标记的 auth_candidate（登录接口、含密码字段等）
      3. **请求携带生成物会发送的 Cookie**（Issue #12 新增；本次重做改为与
         `credential_cookie_candidates` 同一名单，见 `_has_credential_cookie`）
    """
    headers = request.get("headers") or {}
    if headers.get("Authorization") or headers.get("authorization"):
        return True
    if request.get("auth_candidate"):
        return True
    return _has_credential_cookie(headers)


# --------------------------------------------------------------------------- #
# Issue #15: 端点可独立生成性判定
#
# 实测两类端点不适合直接生成工具（修复前被 401 掩盖，鉴权修好后才暴露）：
#
#   1) OData 复合函数调用 —— 路径形如
#        /<entity>(<key>)/<Namespace>.<Function>
#      语义依赖父请求上下文里的必需参数（如 Target=@tid），独立调用必失败。
#
#   2) 从 $batch 还原出的集合端点，若原 query 无分页参数 —— 独立调用即拉全表。
#      量级实测：无分页上限会超时；加 $top=50 约数十秒；加 $top=10 约数秒。
# --------------------------------------------------------------------------- #
# OData 绑定函数段：命名空间限定的函数名（Microsoft.Dynamics.CRM.* / Microsoft.OData.* /
# System.*）。**只认这个形态**，不再「末段含点号」就算 —— 后者把
# `/api/report.csv`、`/api/export/report.pdf`、`/api/files/readme.txt`、
# `/api/export/audit.log` 这类真业务端点误判成 `not_independently_callable`，
# 而 project.session_to_registry_entries 会因此把它们**静默丢弃**（F5 回归）。
_ODATA_FUNCTION_NAMESPACES = ("Microsoft.Dynamics.CRM", "Microsoft.OData", "System.")
_ODATA_QUALIFIED_FUNCTION_RE = re.compile(
    r"(?:^|/)(?:" + "|".join(re.escape(ns) for ns in _ODATA_FUNCTION_NAMESPACES) + r")"
    r"\.[A-Za-z_][A-Za-z0-9_]*\s*$"
)
# 形态二：记录键调用随后紧跟函数名（name(guid) 调用形态），如
#   /systemusers(00000000-0000-0000-0000-000000000000)/RetrievePrincipalAccess
# 键必须是 GUID：普通业务路径（/api/orders(123)/items）不命中。
_GUID_PATTERN = (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                 r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_ODATA_KEY_CALL_RE = re.compile(rf"\({_GUID_PATTERN}\)/[A-Za-z_][A-Za-z0-9_.]*\s*$")


def is_odata_bound_function(path: str) -> bool:
    """路径是否为 OData 绑定函数调用（不适合独立生成工具）。

    只认**两种真实形态**：命名空间限定的函数名，或 ``记录键调用/函数名``
    （``name(guid)`` 形态）。仅凭「末段有点号」判定会把带扩展名的导出端点
    （``/api/export/report.pdf`` 等）一起误杀。

    >>> is_odata_bound_function("/api/data/v9.0/systemusers(abc)/Microsoft.Dynamics.CRM.RetrievePrincipalAccess")
    True
    >>> is_odata_bound_function("/api/data/v9.0/annotations")
    False
    >>> is_odata_bound_function("/api/export/report.pdf")
    False
    """
    if not path:
        return False
    cleaned = path.split("?")[0].rstrip("/")
    if _ODATA_QUALIFIED_FUNCTION_RE.search(cleaned):
        return True
    return bool(_ODATA_KEY_CALL_RE.search(cleaned))


def has_pagination(query_params: dict[str, Any] | None) -> bool:
    """query 里是否已有分页/限量参数。"""
    if not query_params:
        return False
    keys = {str(k).lower() for k in query_params}
    return bool(keys & {"$top", "$skip", "fetchxml", "page", "pagesize", "count", "limit"})


_SINGLE_RECORD_RE = re.compile(r"\([^)]*\)\s*$")


def is_single_record_path(path: str) -> bool:
    """路径是否指向单条记录（形如 /entities(<key>)），取单条无需分页。

    >>> is_single_record_path("/api/data/v9.0/cr_sampleitems(00000000-...)")
    True
    >>> is_single_record_path("/api/data/v9.0/annotations")
    False
    """
    if not path:
        return False
    return bool(_SINGLE_RECORD_RE.search(path.split("?")[0].rstrip("/")))


# 这些参数是「查询的全部内容」而非可选修饰——不传就会退化成危险的默认查询。
# 例如 OData / D365 的 fetchXml：不传等价于「拉全表」，实测会超时。
_QUERY_DEFINING_PARAMS = ("fetchxml", "query", "sql", "odataquery", "filter")


def query_defining_param(query_params: dict[str, Any] | None) -> str | None:
    """返回决定查询内容的必填参数名（若有）。

    这类参数在生成时必须**保持必填**，不能因默认值门槛被降级为 None——
    否则调用方省略它就会触发无界查询。
    """
    if not query_params:
        return None
    for key in query_params:
        if str(key).lower() in _QUERY_DEFINING_PARAMS:
            return str(key)
    return None


def suggest_pagination(query_params: dict[str, Any] | None,
                       from_batch: bool,
                       path: str = "") -> dict[str, Any] | None:
    """集合端点若无任何分页约束，建议注入默认上限。

    注意：若端点带 fetchXml 这类「查询即内容」的参数，说明**分页约束在参数里**
    （如 <fetch count="10" page="1">），此时不应再注入 $top，而应保证该参数必填。
    单条记录查询（/entities(key)）本就只取一条，不适用。
    返回 None 表示无需建议。
    """
    if has_pagination(query_params) or is_single_record_path(path):
        return None
    if not from_batch:
        return None
    return {
        "reason": "batch_derived_without_pagination",
        "suggest": "在生成工具时注入默认分页上限（如 $top=50 或 fetch count）",
        "evidence": "实测同一端点：无上限会超时；$top=50 约数十秒；$top=10 约数秒",
    }


def require_query_param_suggestion(query_params: dict[str, Any] | None) -> dict[str, Any] | None:
    """端点是否依赖「查询即内容」的参数（该参数必须保持必填）。

    实测：`/api/data/v9.0/annotations` 的分页约束在 fetchXml 内
    （`<fetch ... count="10" page="1">`）。生成的工具把 fetchXml 默认为 None，
    调用方省略后即退化为无界查询，实测 >90s 超时。
    """
    name = query_defining_param(query_params)
    if not name:
        return None
    return {
        "param": name,
        "reason": "query_defining_param_must_be_required",
        "evidence": "省略该参数会退化为无界查询（实测 >90s 超时 vs 带参数 3.1s）",
    }


def _heavy_response_suggestion(
    sample_count: int,
    total_size: int,
    max_size: int,
    response_bytes: int,
    sample_threshold: int,
) -> dict[str, Any] | None:
    """Issue #2 体积/频次启发式：只标记「待复核」，绝不直接当噪音删除。

    命中条件（任一）：
      * 累计响应体 >= 阈值（默认 1MB）——通常是框架元数据/静态资源；
      * 单个响应体 >= 阈值且累计 >= 阈值/2——单次巨型响应；
      * 采样次数 >= 阈值（默认 50）——轮询/心跳类高频端点。
    """
    reasons: list[str] = []
    if total_size >= response_bytes:
        reasons.append(f"total_response_bytes={total_size}>={response_bytes}")
    if max_size >= response_bytes and total_size >= response_bytes // 2:
        reasons.append(f"single_response_bytes={max_size}>={response_bytes}")
    if sample_count >= sample_threshold:
        reasons.append(f"sample_count={sample_count}>={sample_threshold}")
    if not reasons:
        return None
    return {"review_suggested": True, "reasons": reasons,
            "total_response_bytes": total_size, "max_response_bytes": max_size,
            "sample_count": sample_count}


# 体积/频次启发式命中项的**人话**说法（S19）。键是 reasons 里的等号前那一段。
_REVIEW_REASON_LABELS = {
    "total_response_bytes": "累计响应体积很大（可能是静态资源或框架元数据）",
    "single_response_bytes": "单次响应体积很大",
    "sample_count": "被请求的次数很多（可能是轮询或心跳）",
}


def review_suggested_hint(reasons: list[str] | None) -> str:
    """把 ``review_reasons`` 的机器码写成人能看懂的一句话。

    S19：``review_suggested`` 此前只给一个裸布尔值，非技术使用者看到一个
    ``true`` 却不知道「为什么值得看一眼」。阈值本身**只标记、不丢弃**
    （丢弃方向会把能用的业务接口一起丢掉，代价更大），所以这里只负责解释。
    """
    labels: list[str] = []
    for reason in reasons or []:
        key = str(reason).split("=", 1)[0]
        label = _REVIEW_REASON_LABELS.get(key, key)
        if label not in labels:
            labels.append(label)
    if not labels:
        return ""
    return ("这个接口" + "、".join(labels)
            + "，生成后建议人工确认它是不是你真正需要的功能"
              "（它仍会照常生成工具，不会被自动丢弃）。")


# --------------------------------------------------------------------------- #
# B-1: 命名参数化（单样本也能参数化——SPA 每个资源通常只请求一次）
# --------------------------------------------------------------------------- #
# 通用层只保留真·通用映射；站点专属语义（article_id / message_id 等）必须外置到
# site_profiles/<site>.py 的 param_alias，由 get_param_alias() 按 host 覆盖/扩展（Issue #8）。
PARAM_ALIAS = {"id": "id", "page": "page"}
PARAM_ALIAS_TEMPLATE = "{name}_id"


def get_param_alias(host: str | None = None) -> dict[str, str]:
    """通用别名 + 站点档案别名（站点优先）。无档案时退化为纯通用映射。"""
    if not host:
        return dict(PARAM_ALIAS)
    profile = _load_site_profile(host)
    if not profile:
        return dict(PARAM_ALIAS)
    try:
        from .site_profiles import merge_param_alias
        return merge_param_alias(PARAM_ALIAS, profile)
    except Exception:
        return dict(PARAM_ALIAS)


# UUID / GUID（8-4-4-4-12 十六进制）。没有哪个接口会把 UUID 当**固定**段名，
# 所以它单独成立就足以判定「这是记录键」。少了这条，`/api/tickets/<guid>` 这类
# 详情/修改接口不参数化 → 抓包时那条记录的 GUID 被写死进生成物（工具永远只操作
# 那一条，且不报错），同一实体的多条记录还会各自变成一个工具。
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def _is_id_segment(seg: str) -> bool:
    """数字 ID、下划线/逗号分隔数字（item_merged.10_773）、<type>-<id>（achievement-12782）、UUID。"""
    return bool(
        re.fullmatch(r"\d+([_,]\d+)*", seg)
        or re.fullmatch(r"item_merged\.\d+(_\d+)*", seg)
        or re.fullmatch(r"[a-z_]+-\d+([_,]\d+)*", seg)
        # 注意：上面那条 `[a-z_]+-\d+` 匹配不到 UUID —— `638ca21c-1111-…` 以数字开头，
        # 且后面几段混有字母，必须由下面这条兜住。
        or _UUID_RE.fullmatch(seg)
    )


# OData 记录键：``实体(键)``。OData v4 的标准寻址语法 —— Dynamics 365 / CRM、
# SharePoint REST、SAP Gateway / NetWeaver、各类 WCF Data Service 都在用。
# 段里「实体名 + 括号 + 键」粘成一段，整段既不是数字也不是 UUID，故上面那条
# 形态判定永远不成立；不单独认它，详情/修改接口就会把抓包时那条记录的 GUID
# 写死进路径与工具名。
_ODATA_KEY_RE = re.compile(r"^([A-Za-z_][\w.\-]*)\(([^()]*)\)$")


def _split_odata_key(segment: str) -> tuple[str, str, str] | None:
    """``实体(键)`` → ``(实体名, 键, 引号)``；不是这个形态返回 None。

    键外层若是 OData 的单引号（``Products('Widget')``），剥掉后再判形态，
    引号原样带回 —— 折成参数时要写回 ``实体('{id}')``，否则生成的 URL 是错的。
    括号内含嵌套括号（``GetMetadata(...)`` 那类表达式）一律不认，保持原样。
    """
    match = _ODATA_KEY_RE.fullmatch(segment)
    if not match:
        return None
    entity, key = match.group(1), match.group(2)
    if len(key) >= 2 and key.startswith("'") and key.endswith("'"):
        return entity, key[1:-1], "'"
    return entity, key, ""


def parameterize(path: str, host: str | None = None) -> tuple[str, list[str]]:
    """把路径中的 ID 段替换为按前段命名的参数，返回 (新路径, 参数名列表)。

    host 用于加载站点档案的专属别名（Issue #8）；不传则只用通用映射。
    """
    alias = get_param_alias(host)
    segs = path.split("/")
    out: list[str] = []
    names: list[str] = []

    def _unique(base: str) -> str:
        name = alias.get(base) or (PARAM_ALIAS_TEMPLATE.format(name=base) if base else "id")
        if name in names:
            name = f"{name}_{names.count(name) + 1}"
        return name

    for i, seg in enumerate(segs):
        # OData 记录键：实体名要留在路径里，只把括号内的键参数化。
        # 键不是 ID 形态（``Products('Widget')`` 这类字面量键）就整段保持原样。
        entity_key = _split_odata_key(seg)
        if entity_key is not None:
            entity, key, quote = entity_key
            if not _is_id_segment(key):
                out.append(seg)
                continue
            base = re.sub(r"[^a-z0-9]+", "_", entity.lower()).strip("_")
            name = _unique(base)
            names.append(name)
            out.append(f"{entity}({quote}{{{name}}}{quote})")
            continue
        if not (_is_id_segment(seg) or re.fullmatch(r"\{[^}]+\}", seg)):
            out.append(seg)
            continue
        if re.fullmatch(r"\{[^}]+\}", seg):
            out.append(seg)  # 已参数化的占位符保持原样
            continue
        prev = segs[i - 1] if i > 0 else ""
        base = re.sub(r"[^a-z0-9]+", "_", prev.lower()).strip("_")
        name = _unique(base)
        names.append(name)
        out.append(f"{{{name}}}")
    return "/".join(out), names


# --------------------------------------------------------------------------- #
# C-1: 账号密码登录接口识别（生成 login/auth_status 专用工具）
# --------------------------------------------------------------------------- #
LOGIN_HINTS = ("login", "signin", "sign_in", "authorize", "auth/token")
ACCOUNT_KEYS = ("account", "username", "user_name", "phone", "mobile", "email", "user")
PASSWORD_KEYS = ("password", "passwd", "pwd", "secret")
TOKEN_KEYS = ("token", "access_token", "accesstoken", "jwt")

# --------------------------------------------------------------------------- #
# 「能不能靠构造请求登录」：两层判据
#
# **第一层（静态，本节的常量与 login_static_signals）** 只看登录请求**自己**的字段名
# 与取值形态。它是**预判**，因此只认强信号（验证码字段 / 二次验证字段 / 无法复现的
# 前端加密口令）；签名 / 时间戳 / 随机数这类参数单独出现时**不足以判死** —— 很多站点
# 的登录并不校验它们，据此生成一个「弹浏览器」的服务反而把本来能用的自动登录弄丢。
#
# **第二层（实测，auth.http_login）** 真的去 POST 一次；失败就换个形态再 POST 一次，
# 并把实际结果落盘成 ``<auth_states>/<site_key>.login_mode.json`` 边车。实测结果一旦
# 存在就**覆盖**静态预判（以实际结果为准）：静态说「要验证码」而实测真能登录的站点，
# 按「能登录」处理；反之亦然。
#
# 判决只影响**生成物**（``auth_login["post_login"]["verdict"] == "interactive"`` 时
# 生成物改为自带交互式登录）。字段缺省（老 registry / 老 analysis.json）时生成物行为
# 与以前**逐字节相同** —— 生成器只在拿到 ``interactive`` 这个明确结论时才改产物。
# --------------------------------------------------------------------------- #
# 验证码 / 图形码 / 短信码字段名：值由人（或验证码服务）当场生成，抓包与 Agent 都无从得知。
CAPTCHA_FIELD_KEYS = frozenset({
    "captcha", "captcha_code", "captchacode", "verify_code", "verifycode",
    "verification_code", "verificationcode", "valid_code", "validcode",
    "img_code", "imgcode", "image_code", "imagecode", "check_code", "checkcode",
    "rand_code", "randcode", "vcode", "sms_code", "smscode", "sms_captcha",
})
# 二次验证（MFA / OTP）字段名：同上，且常常第**二步**才出现。
MFA_FIELD_KEYS = frozenset({
    "otp", "otp_code", "otpcode", "totp", "totp_code", "mfa", "mfa_code",
    "two_factor", "twofactor", "two_factor_code", "twofactorcode", "2fa",
    "auth_code", "authcode", "google_code", "googlecode", "dynamic_code",
    "dynamiccode", "sms_token", "second_factor", "secondfactor",
})
# 签名 / 时间戳 / 随机数类参数：**只记进 signals**，不单独推翻「能 POST」。
SIGNED_PARAM_KEYS = frozenset({
    "sign", "signature", "sig", "nonce", "timestamp", "ts", "hmac", "digest",
    "sign_type", "app_sign", "request_id", "reqid", "requestid",
})
# 只有这几类算「强信号」：出现即预判「构造 POST 登录不可行」。
STRONG_LOGIN_SIGNALS = frozenset({"captcha_field", "mfa_field", "encrypted_password"})
# http_login 落盘的「实测登录方式」边车（第二层结果）的文件后缀。
LOGIN_MODE_SUFFIX = ".login_mode.json"


def _match_key(props: dict, candidates: tuple[str, ...]) -> str | None:
    for key in props:
        if key.lower() in candidates:
            return key
    for key in props:
        if any(c in key.lower() for c in candidates):
            return key
    return None


def _find_token_path(schema: Any, path: tuple[str, ...] = ()) -> list[str] | None:
    if not isinstance(schema, dict):
        return None
    for key, sub in (schema.get("properties") or {}).items():
        if key.lower() in TOKEN_KEYS and (sub or {}).get("type") == "string":
            return list(path) + [key]
    for key, sub in (schema.get("properties") or {}).items():
        found = _find_token_path(sub, path + (key,))
        if found:
            return found
    return None


# --------------------------------------------------------------------------- #
# (a) 类「疑似来源」：登录 query 参数的值疑似来自**前面的某个响应**
#
# 判定必须按**抓包的时间顺序**：``_index_capture`` 是按 requestId 塞进 dict 的
# （重定向还会用同一 id 重发），跨 requestId 的先后已被丢掉；``crypto_analyzer``
# 的 ``_load_capture_requests`` 同样按 requestId 建索引，只借它的「一次读盘」读法，
# 不借它的索引。这里自己按文件顺序流式扫一遍 capture.jsonl。
#
# 判不出来是**常态**、不是边角：值太短、是脱敏哨兵、在前序响应里多命中、来源体被
# 丢/不可用/非 JSON、循环依赖…… 每条都如实报「不可知」，绝不猜。
#
# 能定到**唯一**来源时，这里再判一遍「能不能自动取用」——五条时序闸门全中才算：
#   1. 候选来源唯一（多命中已归为「不可知」）；
#   2. 来源是**公共、无鉴权**的 GET（请求不携带 Authorization / Cookie）；
#   3. 来源接口**自身不需要任何参数**（URL 上没有 query）；
#   4. 来源**既不是**登录端点本身、也**不是** ``auth_login["verify"]`` 端点；
#   5. 来源请求**早于**登录请求，且它的响应是**完整 JSON**（不是 body_dropped、不是 HTML）。
# 全中 → 记录里多一个 ``fetch`` 计划，生成器据此发射「先取后用」的代码（R2）；
# 任一不中 → 记 ``fetch_block`` 原因，生成器把该参数**降级为必填**并说明原因。
# 两条路都**不烘任何抓包取值**。
# --------------------------------------------------------------------------- #
PROVENANCE_SUSPECTED = "suspected_response"
PROVENANCE_UNKNOWN = "unknown"

# 值形态硬闸门：达不到证据强度的值一律「不可知」（短值太容易在别处偶然出现）。
_MIN_PROVENANCE_LEN = 8
_COMMON_PROVENANCE_VALUES = frozenset({
    "1", "0", "2", "true", "false", "yes", "no", "on", "off",
    "cn", "en", "zh", "us", "get", "post", "put", "delete", "json", "html",
    "xml", "text", "utf-8", "utf8", "ascii", "null", "none",
})
_PROVENANCE_SENTINEL = "***"

# 判定结果的原因码（machine-readable；note 是给人看的一句话）。
_PROV_NOT_FOUND = "not_observed_in_preceding_response"
_PROV_EMPTY = "empty_value"
_PROV_SENTINEL = "redaction_sentinel"
_PROV_TOO_SHORT = "value_too_short"
_PROV_COMMON = "common_short_value"
_PROV_AMBIGUOUS = "multiple_sources"
_PROV_CIRCULAR_SELF = "source_is_login_endpoint"
_PROV_CIRCULAR_VERIFY = "source_is_verify_endpoint"
_PROV_CIRCULAR_AUTH = "source_carries_login_auth_header"
_PROV_TEMPORAL = "source_not_before_login"
_PROV_UNSCANNABLE = "preceding_bodies_unavailable"
_PROV_MIXED = "inconsistent_values"
# 来源能定到唯一端点、但**不满足自动取用**的几条（R2）：不是「不可知」，而是
# 「知道来源、但无法安全地替调用方去取」——这些参数照旧降级为必填。
_PROV_SOURCE_NOT_GET = "source_is_not_get"
_PROV_SOURCE_AUTH = "source_request_carries_auth"
_PROV_SOURCE_PARAMS = "source_request_has_params"
_PROV_SOURCE_FIELD = "source_field_not_locatable"

# 自动取用（R2）的人工可读阻塞原因：写进 provenance 记录与摘要，措辞面向使用者。
_PROV_BLOCK_NOTES = {
    _PROV_SOURCE_NOT_GET: "来源请求不是 GET（不能安全重放）",
    _PROV_SOURCE_AUTH: "来源请求带了鉴权头或 Cookie，不是公共接口",
    _PROV_SOURCE_PARAMS: "来源接口自身需要参数（取值已被脱敏，无法复现请求）",
    _PROV_SOURCE_FIELD: "来源响应里定位不到该字段",
    _PROV_MIXED: "不同取值的来源条件不一致",
}

# 需要人/LLM 确认的原因（摘要只收这些 + suspected；其余「干净地没找到」不进摘要，
# 好让摘要保持克制）。因果顺序：歧义 > 循环/时序 > 扫不到 > 值形态。
_PROV_NOTABLE_REASONS = (
    _PROV_AMBIGUOUS, _PROV_CIRCULAR_SELF, _PROV_CIRCULAR_VERIFY,
    _PROV_CIRCULAR_AUTH, _PROV_TEMPORAL, _PROV_UNSCANNABLE, _PROV_MIXED,
)


class _Unparsed:
    """「尚未解析」哨兵，与「解析结果确实是 None」区分开。"""

    __slots__ = ()


_UNPARSED = _Unparsed()


@dataclass
class _CaptureBodyEvent:
    """capture.jsonl 里一条 ``response_body`` 的**顺序化**瘦记录。"""

    position: int
    request_id: Any
    body: str | None
    dropped: bool
    unavailable: Any
    parsed: Any = _UNPARSED


def _ordered_capture_scan(capture_path: Path) -> tuple[dict[Any, dict[str, Any]], list[_CaptureBodyEvent]]:
    """按**文件顺序**流式扫 capture.jsonl，产出 (请求索引, 响应体顺序表)。

    * 请求索引 ``{requestId: {position, method, host, path, headers}}``：**首次出现者
      胜**（重定向会用同一个 requestId 重发 ``requestWillBeSent``，首次那跳才是原始请求）。
    * 响应体表保持**文件顺序**，这是跨 requestId 判定先后的唯一依据。
    坏行/非 dict 行跳过；文件不存在返回空（分析层不在这里静默编造）。
    """
    requests: dict[Any, dict[str, Any]] = {}
    bodies: list[_CaptureBodyEvent] = []
    try:
        stream = capture_path.open("r", encoding="utf-8")
    except OSError:
        return requests, bodies
    with stream:
        position = -1
        for line in stream:
            position += 1
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            kind = event.get("type")
            if kind == "request":
                request_id = event.get("requestId")
                try:
                    known = request_id in requests
                except TypeError:                       # 不可哈希的畸形 id
                    continue
                if known:
                    continue
                parsed = urlsplit(str(event.get("url") or ""))
                requests[request_id] = {
                    "position": position,
                    "method": str(event.get("method") or ""),
                    "host": parsed.netloc,
                    "path": parsed.path or "/",
                    # R2 的自动取用要能**复现**这次来源请求：origin 给全 URL，
                    # query 用来判「来源接口自身是否需要参数」。
                    "origin": f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else "",
                    "query": parsed.query,
                    "headers": event.get("headers") or {},
                }
            elif kind == "response_body":
                bodies.append(_CaptureBodyEvent(
                    position=position,
                    request_id=event.get("requestId"),
                    body=event.get("body"),
                    dropped=bool(event.get("body_dropped")),
                    unavailable=event.get("body_unavailable_reason"),
                ))
    return requests, bodies


def _json_leaf_paths(node: Any, target: str, path: str = "$") -> list[str]:
    """JSON 树里与 ``target`` **完全相等**的字符串叶子路径。

    刻意**不做子串比对**（`"abc" in body` 会把 `token=abc` 命中到 `abc123` 上，
    误报来源）。数字/布尔按字符串比较，其余类型不看。
    """
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            found.extend(_json_leaf_paths(value, target, f"{path}.{key}"))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_json_leaf_paths(value, target, f"{path}[{index}]"))
    elif isinstance(node, str):
        if node == target:
            found.append(path)
    elif isinstance(node, (int, float)) and not isinstance(node, bool):
        if str(node) == target:
            found.append(path)
    return found


def _provenance_values(entry: Any) -> list[str]:
    """取某参数的候选取值。

    兼容两种形状：``{class, values:[…]}``（当前 analysis 的 evidence 形状）与
    直接 ``[值…]``（``auth_login["query_params"]`` / 早期标量归一后的形状）。
    """
    if isinstance(entry, dict):
        raw = entry.get("values")
    elif isinstance(entry, (list, tuple)):
        raw = entry
    else:
        raw = None if entry is None else [entry]
    if not isinstance(raw, (list, tuple)):
        return []
    return [str(value) for value in raw if value is not None]


def _login_auth_header(headers: Any) -> str | None:
    for name, value in (headers or {}).items():
        if str(name).lower() == "authorization" and value:
            return str(value)
    return None


# `_json_leaf_paths` 产出的路径形态只有 `.key` 与 `[数字]` 两种后缀。
_FIELD_SEGMENT = re.compile(r"\.([A-Za-z0-9_\-]+)|\[(\d+)\]")


def _field_tokens(path: Any) -> list | None:
    """把记录的字段路径（``$.data.csrf`` / ``$.data[0].csrf``）切成取值用的键列表。

    只认上面那两种后缀；出现别的形态（键名里带点、带引号、非 ASCII…）就返回 None ——
    宁可不自动取用（降级为必填），也不生成一段**会取到错值**的代码。
    """
    if not isinstance(path, str) or not path.startswith("$"):
        return None
    tokens: list = []
    index = 1
    while index < len(path):
        match = _FIELD_SEGMENT.match(path, index)
        if not match:
            return None
        tokens.append(match.group(1) if match.group(1) is not None
                      else int(match.group(2)))
        index = match.end()
    return tokens or None


def _has_request_auth(headers: Any) -> bool:
    """这次请求带了 Authorization 或 Cookie 吗？（带了就不是「公共、无鉴权」的接口）"""
    lowered = {str(name).lower() for name in (headers or {})}
    return bool(lowered & {"authorization", "cookie"})


def _fetch_block_reason(method: str, request: dict[str, Any],
                        field: Any, field_tokens: list | None) -> str | None:
    """自动取用（R2）在**分析期**能判的那几条闸门；命中即返回原因码（不取用）。

    判定只看这条来源请求自身：是不是 GET、带没带鉴权头、URL 上有没有参数、
    响应里的字段路径能不能静态表达。时序那两条在 ``_resolve_value_source``
    的上游已经判过（来源必须在登录之前、响应必须是完整 JSON）。
    """
    if str(method or "").upper() != "GET":
        return _PROV_SOURCE_NOT_GET
    if _has_request_auth((request or {}).get("headers")):
        return _PROV_SOURCE_AUTH
    if str((request or {}).get("query") or "").strip():
        return _PROV_SOURCE_PARAMS
    if not field or not field_tokens:
        return _PROV_SOURCE_FIELD
    return None


def _fetch_plan_for(method: str, request: dict[str, Any], field: Any,
                    field_tokens: list | None) -> tuple[dict[str, Any] | None, str | None]:
    """产出「先取后用」的计划，或「为什么不能取用」的原因码。二者互斥。"""
    block = _fetch_block_reason(method, request, field, field_tokens)
    if block:
        return None, block
    request = request or {}
    origin = str(request.get("origin") or "")
    if not origin:
        return None, _PROV_SOURCE_FIELD
    # 路径不带 query —— 闸门已保证 query 是空的，所以这就是可以**原样重放**的 URL。
    return ({"name": None, "method": "GET",
             "url": origin + str(request.get("path") or "/"),
             "field": field_tokens, "field_display": field}, None)


def _gate_value(value: str) -> str | None:
    """值本身的硬闸门：命中即返回原因码（不可知），否则 None。"""
    if not value:
        return _PROV_EMPTY
    if value == _PROVENANCE_SENTINEL or set(value) == {"*"}:
        return _PROV_SENTINEL
    if len(value) < _MIN_PROVENANCE_LEN:
        return _PROV_TOO_SHORT
    if value.lower() in _COMMON_PROVENANCE_VALUES:
        return _PROV_COMMON
    return None


def _resolve_value_source(value: str, bodies: list[_CaptureBodyEvent], login_pos: int,
                          login_ep: tuple[str, str], verify_ep: tuple[str, str] | None,
                          login_auth: str | None, requests: dict[Any, dict[str, Any]],
                          unscannable: dict[str, int]) -> dict[str, Any]:
    """给单个取值定来源。返回 ``{source, field, reason, note}``（source 为 None 即不可知）。"""
    matches: list[tuple[int, tuple[str, str, str], str | None, dict[str, Any]]] = []
    for record in bodies:
        parsed = _parse_body_cached(record)
        if parsed is None:
            continue
        paths = _json_leaf_paths(parsed, value)
        if not paths:
            continue
        request = requests.get(record.request_id) or {}
        endpoint = (str(request.get("method") or ""), str(request.get("host") or ""),
                    str(request.get("path") or ""))
        matches.append((record.position, endpoint,
                        paths[0] if len(paths) == 1 else None, request))

    if not matches:
        if unscannable["total"]:
            return {"source": None, "field": None, "reason": _PROV_UNSCANNABLE,
                    "note": (f"未在前序响应里找到该值，但无法核对全部前序响应体："
                             f"{unscannable['gone']} 条被丢弃/不可用、"
                             f"{unscannable['non_json']} 条非 JSON → 不可知")}
        return {"source": None, "field": None, "reason": _PROV_NOT_FOUND,
                "note": "未在任何前序响应体里出现 → 不可知"}

    preceding = [item for item in matches if item[0] < login_pos]
    if not preceding:
        # 命中的全部在登录请求之后：时序不成立（循环/晚到），不可知。
        endpoint_pairs = {item[1][1:] for item in matches}
        if login_ep in endpoint_pairs or (verify_ep and verify_ep in endpoint_pairs):
            return {"source": None, "field": None, "reason": _PROV_CIRCULAR_SELF,
                    "note": "命中项来自登录端点自身或登录校验端点（循环依赖）→ 不可知"}
        return {"source": None, "field": None, "reason": _PROV_TEMPORAL,
                "note": "唯一命中出现在登录请求之后，时序不成立 → 不可知"}

    endpoints = {item[1] for item in preceding}
    if len(endpoints) > 1:
        return {"source": None, "field": None, "reason": _PROV_AMBIGUOUS,
                "note": f"在前序 {len(endpoints)} 个不同端点的响应里都出现该值，"
                        "无法判定来源（歧义）→ 不可知"}

    method, host, path = next(iter(endpoints))
    source_matches = [item for item in preceding if item[1] == (method, host, path)]
    # 循环依赖硬闸门（按顺序判，全部归为「不可知」）。
    if (host, path) == login_ep:
        return {"source": None, "field": None, "reason": _PROV_CIRCULAR_SELF,
                "note": "来源端点就是登录端点自身（循环依赖）→ 不可知"}
    if verify_ep and (host, path) == verify_ep:
        return {"source": None, "field": None, "reason": _PROV_CIRCULAR_VERIFY,
                "note": "来源端点与登录校验端点相同（循环依赖）→ 不可知"}
    if login_auth and any(
            _login_auth_header(item[3].get("headers")) == login_auth
            for item in source_matches):
        return {"source": None, "field": None, "reason": _PROV_CIRCULAR_AUTH,
                "note": "来源请求带了与登录请求相同的鉴权头（循环依赖）→ 不可知"}
    if any(int(item[3].get("position") or 0) >= login_pos for item in source_matches):
        return {"source": None, "field": None, "reason": _PROV_TEMPORAL,
                "note": "来源请求晚于登录请求，时序不成立 → 不可知"}

    field = next((item[2] for item in source_matches if item[2]), None)
    source = {"method": method, "host": host, "path": path}
    if field:
        source["response_field"] = field
    plan, block = _fetch_plan_for(method, source_matches[0][3], field,
                                  _field_tokens(field))
    where = f"{method} {host}{path}"
    if plan:
        plan["name"] = None          # 由调用方按参数名补齐
        note = (f"该参数的值在抓包时取自前序响应 {where}"
                + (f"（响应字段 {field}）" if field else "")
                + "：生成的服务会在登录前**自动**调用该接口取值，无需你填写；"
                "分享之前请确认它不需要登录就能访问")
    else:
        note = f"疑似来自前序响应 {where}"
        if field:
            note += f"（响应字段 {field}）"
        note += ("；无法自动取用（" + _PROV_BLOCK_NOTES.get(block, "不满足自动取用的条件")
                 + "），该参数仍必须由调用方提供")
    return {"source": source, "field": field, "reason": None, "note": note,
            "fetch": plan, "fetch_block": block if not plan else None}


def _parse_body_cached(record: _CaptureBodyEvent) -> Any:
    """响应体解析（带缓存）。丢弃/不可用/非 JSON 一律返回 None（**不当来源**）。"""
    if record.dropped or record.unavailable or record.body is None:
        return None
    if not isinstance(record.parsed, _Unparsed):
        return record.parsed
    try:
        parsed: Any = json.loads(record.body)
    except (TypeError, json.JSONDecodeError):
        parsed = None
    record.parsed = parsed
    return parsed


def _unscannable_kind(record: _CaptureBodyEvent) -> str | None:
    """这条响应体为什么不能当来源：``gone``（丢弃/不可用）/ ``non_json`` / None（可扫）。"""
    if record.dropped or record.unavailable or record.body is None:
        return "gone"
    return None if _parse_body_cached(record) is not None else "non_json"


def _unscannable_counts(bodies: list[_CaptureBodyEvent], before: int) -> dict[str, int]:
    kinds = [kind for record in bodies if record.position < before
             for kind in [_unscannable_kind(record)] if kind]
    return {"total": len(kinds),
            "gone": sum(1 for kind in kinds if kind == "gone"),
            "non_json": sum(1 for kind in kinds if kind == "non_json")}


def _value_reason_priority(reason: str | None) -> int:
    if reason in _PROV_NOTABLE_REASONS:
        return _PROV_NOTABLE_REASONS.index(reason)
    return len(_PROV_NOTABLE_REASONS)


def analyze_query_param_provenance(session_dir: Path | None,
                                   login: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """逐登录 query 参数判定「值疑似来自前面的哪个响应」——判定 + 能否自动取用。

    返回 ``{参数名: {name, class, suspected_source, note, reason, needs_confirmation,
    fetch, fetch_block}}``。``class`` 只有两个取值：``suspected_response``（能定到唯一
    来源）或 ``unknown``（判不出，含脱敏哨兵 / 太短 / 歧义 / 循环 / 时序不成立 /
    前序体不可扫）。判不出时 ``suspected_source`` 为 None，**绝不编**。
    ``fetch`` 是「先取后用」的计划（五条闸门全中时非空，见文件开头的说明），
    否则 ``fetch_block`` 给出为什么不能自动取用 —— 生成器据此决定取用还是降级为必填。
    """
    if session_dir is None:
        return {}
    capture_path = Path(session_dir) / "capture.jsonl"
    if not capture_path.exists():
        return {}
    requests, bodies = _ordered_capture_scan(capture_path)

    login_host = str(login.get("host") or "")
    login_path = str(login.get("path") or "")
    login_method = str(login.get("method") or "POST")
    login_pos: int | None = None
    login_headers: Any = {}
    for request in requests.values():
        if (str(request.get("method") or "") == login_method
                and str(request.get("host") or "") == login_host
                and str(request.get("path") or "") == login_path):
            position = int(request.get("position") or 0)
            if login_pos is None or position < login_pos:
                login_pos, login_headers = position, request.get("headers") or {}
    verify = login.get("verify") or {}
    verify_ep = ((str(verify.get("host") or ""), str(verify.get("path") or ""))
                 if verify.get("host") and verify.get("path") else None)
    login_auth = _login_auth_header(login_headers)

    evidence = login.get("query_param_evidence")
    if not isinstance(evidence, dict) or not evidence:
        evidence = login.get("query_params") or {}
    provenance: dict[str, dict[str, Any]] = {}
    for name, entry in (evidence or {}).items():
        values = _provenance_values(entry)
        if login_pos is None:
            provenance[str(name)] = {
                "name": str(name), "class": PROVENANCE_UNKNOWN, "suspected_source": None,
                "reason": _PROV_NOT_FOUND, "needs_confirmation": False,
                "note": "本次抓包里找不到该登录请求（无法按时间顺序比对）→ 不可知"}
            continue
        unscannable = _unscannable_counts(bodies, login_pos)
        outcomes: list[dict[str, Any]] = []
        for value in values:
            gate = _gate_value(value)
            if gate:
                outcomes.append({"source": None, "field": None, "reason": gate,
                                 "note": _gate_note(gate)})
            else:
                outcomes.append(_resolve_value_source(
                    value, bodies, login_pos, (login_host, login_path), verify_ep,
                    login_auth, requests, unscannable))
        provenance[str(name)] = _aggregate_provenance(str(name), outcomes)
    return provenance


def _gate_note(reason: str) -> str:
    return {
        _PROV_EMPTY: "取值为空 → 不可知",
        _PROV_SENTINEL: "取值是脱敏哨兵（真实值在落盘时已被遮蔽）→ 不可知",
        _PROV_TOO_SHORT: f"取值长度不足 {_MIN_PROVENANCE_LEN} 字符，证据强度不够 → 不可知",
        _PROV_COMMON: "取值是常见短值/枚举值，命中也说明不了来源 → 不可知",
    }.get(reason, "不可知")


def _aggregate_provenance(name: str, outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    """把逐取值结论合成为逐参数结论。保守：任何不一致都判不可知，**绝不**硬凑来源。"""
    if not outcomes:
        return {"name": name, "class": PROVENANCE_UNKNOWN, "suspected_source": None,
                "reason": _PROV_NOT_FOUND, "needs_confirmation": False,
                "note": "无取值可判定 → 不可知"}
    resolved = [item for item in outcomes if item.get("source")]
    unresolved = [item for item in outcomes if not item.get("source")]
    if resolved and not unresolved:
        keys = {(item["source"]["method"], item["source"]["host"], item["source"]["path"])
                for item in resolved}
        if len(keys) == 1:
            entry = {"name": name, "class": PROVENANCE_SUSPECTED,
                     "suspected_source": resolved[0]["source"], "reason": None,
                     "needs_confirmation": True, "note": resolved[0]["note"]}
            return _with_fetch(entry, resolved)
        return {"name": name, "class": PROVENANCE_UNKNOWN, "suspected_source": None,
                "reason": _PROV_AMBIGUOUS, "needs_confirmation": True,
                "note": "该参数的不同取值指向不同来源（歧义）→ 不可知"}
    if resolved and unresolved:
        return {"name": name, "class": PROVENANCE_UNKNOWN, "suspected_source": None,
                "reason": _PROV_MIXED, "needs_confirmation": True,
                "note": "部分取值疑似有来源、部分被判不出/被闸门拦下，证据不一致 → 不可知"}
    chosen = min(outcomes, key=lambda item: _value_reason_priority(item.get("reason")))
    reason = chosen.get("reason")
    return {"name": name, "class": PROVENANCE_UNKNOWN, "suspected_source": None,
            "reason": reason, "needs_confirmation": reason in _PROV_NOTABLE_REASONS,
            "note": chosen.get("note") or "不可知"}


def _with_fetch(entry: dict[str, Any], resolved: list[dict[str, Any]]) -> dict[str, Any]:
    """给「能定到唯一来源」的结论补上**自动取用计划**（或为什么不能取用）。

    所有取值的取用计划必须完全一致才算可自动取用（只有一个取值时 trivially 成立）；
    有任何不一致就退回「不能自动取用」，由生成器把参数降级为必填（R2：宁要必填，
    也不要一段会取到错值的代码）。
    """
    plans = {json.dumps(item.get("fetch"), sort_keys=True) for item in resolved}
    plan = resolved[0].get("fetch")
    if len(plans) == 1 and isinstance(plan, dict):
        entry["fetch"] = plan
        entry["fetch_block"] = None
        return entry
    if len(plans) == 1:
        entry["fetch"] = None
        entry["fetch_block"] = resolved[0].get("fetch_block")
        return entry
    source = entry["suspected_source"]
    entry["fetch"] = None
    entry["fetch_block"] = _PROV_MIXED
    entry["note"] = (f"疑似来自前序响应 {source.get('method')} "
                     f"{source.get('host')}{source.get('path')}；"
                     + _PROV_BLOCK_NOTES[_PROV_MIXED]
                     + "，该参数仍必须由调用方提供")
    return entry


# 这些原因**证明**取值确实出现在前序响应体里（只是来源定不下来）→ 生成器据此知道
# 「它派生自响应」，因而**绝不烘快照**（烘的是那一次会话的值，很快失效）。
_RESPONSE_DERIVED_REASONS = frozenset({
    _PROV_AMBIGUOUS, _PROV_CIRCULAR_SELF, _PROV_CIRCULAR_VERIFY,
    _PROV_CIRCULAR_AUTH, _PROV_TEMPORAL, _PROV_MIXED,
})


def value_is_response_derived(entry: Any) -> bool:
    """这条 provenance 记录是否说明该取值**确实来自前序响应**（⇒ 生成器绝不烘快照）。

      * ``suspected_response`` —— 定到了唯一来源（能取用就取用，取用不了就退必填）；
      * 「在前序响应体里出现过、但来源定不下来」的原因（多命中歧义 / 循环依赖 /
        时序不成立 / 证据混合）。

    相对地，``not_observed_in_preceding_response`` 与值形态闸门（哨兵 / 太短 /
    常见值）**没有**证明值来自响应 —— 那些走普通的默认值规则即可。
    """
    if not isinstance(entry, dict):
        return False
    if entry.get("class") == PROVENANCE_SUSPECTED:
        return True
    return entry.get("reason") in _RESPONSE_DERIVED_REASONS


def _provenance_is_actionable(entry: Any) -> bool:
    """这条线索**可行动**吗？—— 只有「疑似来自响应」且**真给出**了来源端点才算。

    ``suspected_source`` 为空的条目（无论被归到哪一类）都不指向任何行动，不算线索。
    """
    if not isinstance(entry, dict):
        return False
    if entry.get("class") != PROVENANCE_SUSPECTED:
        return False
    source = entry.get("suspected_source")
    return isinstance(source, dict) and bool(source)


def login_query_leads(auth_login: dict[str, Any] | None) -> list[dict[str, Any]]:
    """把 ``query_param_provenance`` 收敛成给摘要用的**可行动**线索列表。

    只保留 ``class == suspected_response`` 且 ``suspected_source`` 非空的那几条 ——
    这才是使用者能据以行动的（去确认 / 去取用）。每条只带参数名 / 分类 / 来源端点 /
    是否需人工确认 / **自动取用计划**（`auto_fill`，含来源 URL 与字段路径）/
    一句话说明，**绝不**带取值（避免二次泄漏，也避免被当成"可以烘的值"）。

    为什么把「不可知」整类滤掉：「不可知」是**常态** —— 登录流程必然先加载 HTML/JS/图片，
    任何没在 JSON 响应体里找到的取值都落到「前序体不可用」，于是逐条列出来就是**每个登录
    query 参数一条**，既不指向行动、又制造噪音。这里只过滤**列表**，逐参数的完整细节仍
    留在 ``analysis.json`` 的 ``auth_login["query_param_provenance"]``；摘要里知其规模
    即可（见 ``login_query_unknown_count``）。
    """
    leads: list[dict[str, Any]] = []
    provenance = (auth_login or {}).get("query_param_provenance")
    if not isinstance(provenance, dict):
        return leads
    for entry in provenance.values():
        if not _provenance_is_actionable(entry):
            continue
        plan = entry.get("fetch") if isinstance(entry.get("fetch"), dict) else None
        leads.append({
            "param": entry.get("name"),
            "class": entry.get("class"),
            "suspected_source": entry.get("suspected_source"),
            "needs_confirmation": bool(entry.get("needs_confirmation")),
            # 自动取用：生成的服务会在登录前自己去这个地址取该字段，无需使用者填写。
            # `None` 表示这次不满足条件（生成器把参数降级为必填），原因见 note。
            "auto_fill": ({"from": f"{plan.get('method')} {plan.get('url')}",
                           "field": plan.get("field_display")} if plan else None),
            "note": entry.get("note"),
        })
    return leads


def login_query_unknown_count(auth_login: dict[str, Any] | None) -> int:
    """登录 query 参数里**判不出**（不可知）的**条数** —— 只给聚合计数，不逐条列。

    与 ``login_query_leads`` 互补：``leads`` 汇出可行动的那几条，其余（常态的「不可知」）
    在这里汇总成一个数字，让摘要既不漏报规模、又不被逐条噪音淹没。
    """
    provenance = (auth_login or {}).get("query_param_provenance")
    if not isinstance(provenance, dict):
        return 0
    return sum(1 for entry in provenance.values() if not _provenance_is_actionable(entry))


def _login_request_fields(ep: dict[str, Any]) -> set[str]:
    """登录请求里出现过的字段名（小写）。

    两个来源都要看：``request_schema``（JSON 体推出来的）与 ``request_body_params``
    （表单编码体）。只看前者会漏掉**表单编码**的登录接口，而验证码站点恰恰多是表单。
    """
    props = ((ep.get("request_schema") or {}).get("properties")) or {}
    names = {str(key).lower() for key in props}
    names |= {str(key).lower() for key in (ep.get("request_body_params") or {})}
    return names


def _password_scheme_unreproducible(session_dir: Path | None, ep: dict[str, Any]) -> bool:
    """前端加密口令、但**取不到公钥** → 生成物只会照原样把明文发出去，登录必然失败。

    判据复用现有的 ``detect_password_encryption``（登录接口带 ``encrypt`` 类版本参数，
    公钥从前端 JS 的 PEM 块里取）。取到公钥时**不算**信号 —— 那正是生成物已经会复现的
    情形（``_encrypt_password`` 发射 RSA-OAEP 加密），判成「不能 POST」会把能用的登录弄丢。
    """
    probe = {"query_params": ep.get("query_params") or {}}
    enc = detect_password_encryption(session_dir, probe)
    return bool(enc) and not enc.get("public_key")


def login_static_signals(ep: dict[str, Any], session_dir: Path | None = None) -> list[str]:
    """第一层：从登录请求自身的字段名 / 取值形态预判「能不能构造 POST」。

    返回**信号码**列表（给 analysis / registry 用，也写进生成物 README 的说明）。
    强信号见 :data:`STRONG_LOGIN_SIGNALS`；``signed_params`` 是弱信号，只作提示。
    """
    names = _login_request_fields(ep)
    signals: list[str] = []
    if names & CAPTCHA_FIELD_KEYS:
        signals.append("captcha_field")
    if names & (MFA_FIELD_KEYS - CAPTCHA_FIELD_KEYS):
        signals.append("mfa_field")
    if names & SIGNED_PARAM_KEYS:
        signals.append("signed_params")
    if _password_scheme_unreproducible(session_dir, ep):
        signals.append("encrypted_password")
    return signals


def _load_measured_login_mode(session_dir: Path | None, host: str) -> dict[str, Any] | None:
    """读第二层（实测）的落盘结果；没有就返回 None。

    位置：这次抓包会话的 ``session.json`` 记着 ``auth_state_path``，而 ``http_login``
    把实测结论写成它的**同级边车** ``<同名>.login_mode.json``（与登录态文件同一个
    ``auth_states/`` 目录）。找不到会话、没传过 auth_state、或边车里记的是别的站点都
    返回 None —— 读不到实测结果只意味着「退回静态预判」，绝不该让分析失败。

    返回值只保留**判定本身**（verdict / attempts / reason / statuses / checked_at），
    边车里的其它内容（URL、host）不往 analysis 里搬：registry 是要分发的，少带一个
    字段就少一个泄漏面。
    """
    if not session_dir or not host:
        return None
    try:
        metadata = json.loads((Path(session_dir) / "session.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(metadata, dict):
        return None
    auth_state_path = metadata.get("auth_state_path")
    if not isinstance(auth_state_path, str) or not auth_state_path:
        return None
    states_dir = Path(auth_state_path).parent
    target = str(host).split(":")[0].lower()
    try:
        candidates = sorted(states_dir.glob("*" + LOGIN_MODE_SUFFIX))
    except OSError:
        return None
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        if str(data.get("host") or "").split(":")[0].lower() != target:
            continue
        verdict = data.get("verdict")
        if verdict not in ("post_ok", "interactive"):
            continue
        measured: dict[str, Any] = {"verdict": verdict}
        for key in ("attempts", "reason", "checked_at"):
            if data.get(key) not in (None, ""):
                measured[key] = data[key]
        statuses = data.get("statuses")
        if isinstance(statuses, list):
            # 只保留整数状态码 —— 边车是本地文件，不给它夹带别的东西的机会。
            measured["statuses"] = [s for s in statuses if isinstance(s, int)]
        return measured
    return None


def login_post_verdict(auth_login: dict[str, Any], session_dir: Path | None,
                       signals: list[str]) -> dict[str, Any]:
    """合成 ``auth_login["post_login"]``：**实测优先**，没有实测才用静态预判。

    * 实测成功 → ``post_ok``（静态说「有验证码」也以实测为准）；
    * 实测失败 → ``interactive``（这就是「生成物必须自带交互式登录」的判据）；
    * 没实测过 → 有强静态信号才 ``interactive``，否则 ``post_ok``。
    """
    measured = _load_measured_login_mode(session_dir, str(auth_login.get("host") or ""))
    if measured is not None:
        verdict = "post_ok" if measured["verdict"] == "post_ok" else "interactive"
        basis = "measured"
    else:
        verdict = "interactive" if (set(signals) & STRONG_LOGIN_SIGNALS) else "post_ok"
        basis = "static"
    result: dict[str, Any] = {"verdict": verdict, "basis": basis, "signals": list(signals)}
    if measured is not None:
        result["measured"] = measured
    return result


def login_post_summary(auth_login: dict[str, Any] | None) -> dict[str, Any]:
    """`analyze_traffic` 摘要用：`post_login` 判据的**精简**形式（键常驻）。

    只给结论与依据（`verdict` / `basis` / `signals` / 实测原因码），不给 HTTP 状态码之类细节：
    摘要是喂给 LLM 的，够它向用户交代「为什么这个站点的产物会弹浏览器登录」即可。逐字段的
    完整记录仍在 `analysis.json` / `registry.json` 的 `auth_login["post_login"]` 里。
    没有登录接口时为全 `None` / 空列表 —— 消费方可以无条件读它（风格同 `needs_more_samples`）。
    """
    post_login = (auth_login or {}).get("post_login")
    if not isinstance(post_login, dict):
        return {"verdict": None, "basis": None, "signals": [], "measured_reason": None}
    measured = post_login.get("measured")
    measured = measured if isinstance(measured, dict) else {}
    return {
        "verdict": post_login.get("verdict"),
        "basis": post_login.get("basis"),
        "signals": [str(s) for s in (post_login.get("signals") or [])],
        "measured_reason": measured.get("reason"),
    }


def detect_auth_login(endpoints: list[dict[str, Any]], session_dir: Path | None = None) -> dict[str, Any] | None:
    """找到「账号+密码换取 token」的接口；找不到强信号则返回 None。"""
    for ep in endpoints:
        props = ((ep.get("request_schema") or {}).get("properties")) or {}
        if not props:
            continue
        path_low = ep["path"].lower()
        if not any(h in path_low for h in LOGIN_HINTS):
            continue
        account_field = _match_key(props, ACCOUNT_KEYS)
        password_field = _match_key(props, PASSWORD_KEYS)
        if not (account_field and password_field):
            continue
        token_path = _find_token_path(ep.get("response_schema")) or ["data", "token"]
        verify = next(
            (c for c in endpoints
             if c["method"] == "GET" and c.get("auth_required") and "/my" in c["path"].lower()),
            None,
        )
        login = {
            "host": ep["host"],
            "method": ep.get("method", "POST"),
            "path": ep["path"],
            # 与 endpoint 条目同一形状：`{名: [值…]}`。此前只留「第一个取值」，既不
            # 够生成器判断「这个值是不是抓包当时那一次会话特有的」，也会让 registry
            # 里带着那次登录请求的真实 query 取值（`?tenant=acme`）。清洗与分类都
            # 按 list 处理，故这里从一开始就保持 list。
            "query_params": {k: as_value_list(v)
                             for k, v in (ep.get("query_params") or {}).items()},
            # 参数证据随登录端点被移出 `endpoints` 而丢弃 → 这里保留进 auth_login，
            # 生成器据此区分「无害固定参数（照旧烘默认值）」与「判不出、必须由调用方
            # 提供」。向后兼容：只增字段，老 registry 没有它时生成器按「判不出」处理。
            # 与 endpoint 条目一样，这里保留**原始**证据（它进的是本地 analysis.json）；
            # registry.json / 分发包那一侧的擦除由 project._sanitize_registry_urls 负责
            # （见那里的 `_sanitize_registry_auth_login`），规则不在此另写一份。
            "query_param_evidence": ep.get("query_param_evidence") or {},
            "account_field": account_field,
            "password_field": password_field,
            "token_path": token_path,
            "verify": ({"host": verify["host"], "path": verify["path"]} if verify else None),
        }
        # (a) 类「来源判定 + 自动取用」：按抓包文件顺序比对，绝不烘任何真实值；
        # 闸门全中时给出取用计划（生成器据此发射「先取后用」的代码）。
        login["query_param_provenance"] = analyze_query_param_provenance(session_dir, login)
        enc = detect_password_encryption(session_dir, login)
        if enc:
            login["password_encryption"] = enc
        # 「能不能靠构造请求登录」的结论（两层判据见本节开头）。字段**总是**写，
        # 但生成器只在 verdict == "interactive" 时才改产物 —— 其余取值下产物与
        # 以前逐字节相同（老 analysis.json 没有这个键时同理）。
        login["post_login"] = login_post_verdict(
            login, session_dir, login_static_signals(ep, session_dir))
        return login
    return None


# --------------------------------------------------------------------------- #
# 站点档案（可选加载：语义化命名与站点专属噪音规则外置在 site_profiles/）
# --------------------------------------------------------------------------- #
def _load_site_profile(host: str) -> dict[str, Any] | None:
    try:
        from .site_profiles import get_profile
        return get_profile(host)
    except Exception:
        return None


def _looks_like_parameter(value: str) -> bool:
    return any(pattern.fullmatch(value) for pattern in VALUE_SHAPES)


@dataclass(frozen=True)
class NormalizedPath:
    path: str
    sample_indexes: tuple[int, ...]
    parameter_names: tuple[str, ...]


def normalize_paths(paths: list[str]) -> list[NormalizedPath]:
    """Group paths conservatively, preserving literals such as ``latest``."""
    groups: dict[tuple[int, ...], list[tuple[int, list[str]]]] = defaultdict(list)
    for index, path in enumerate(paths):
        segments = [segment for segment in urlsplit(path).path.split("/") if segment]
        groups[tuple([len(segments)])].append((index, segments))

    results: list[NormalizedPath] = []
    for entries in groups.values():
        if len(entries) == 1:
            index, segments = entries[0]
            results.append(NormalizedPath("/" + "/".join(segments), (index,), ()))
            continue
        columns = list(zip(*(segments for _, segments in entries)))
        variants: dict[tuple[str, ...], list[int]] = defaultdict(list)
        for row, (index, _) in enumerate(entries):
            normalized: list[str] = []
            for column in columns:
                values = list(column)
                # Strict ">" : with 2 identical samples distinct_ratio == 0.5 exactly,
                # and a constant column must never be parameterized.
                distinct_ratio = len(set(values)) / len(values)
                shaped_ratio = sum(_looks_like_parameter(value) for value in values) / len(values)
                current = values[row]
                normalized.append("{id}" if distinct_ratio > 0.5 and shaped_ratio >= 0.8 and _looks_like_parameter(current) else current)
            variants[tuple(normalized)].append(index)
        for normalized, indexes in variants.items():
            names = tuple("id" for value in normalized if value == "{id}")
            results.append(NormalizedPath("/" + "/".join(normalized), tuple(indexes), names))
    return sorted(results, key=lambda result: result.sample_indexes)


STATIC_TYPES = {"Script", "Stylesheet", "Image", "Font", "Media"}
STATIC_EXTENSIONS = re.compile(r"\.(?:js|css|map|png|jpg|jpeg|gif|svg|woff2?|ico|webp)(?:\?|$)", re.I)


def _json_schema(value: Any, samples: list[Any] | None = None) -> dict[str, Any]:
    samples = samples or [value]
    if isinstance(value, dict):
        properties = {}
        for key in value:
            values = [sample[key] for sample in samples if isinstance(sample, dict) and key in sample]
            properties[key] = _json_schema(values[0], values)
        return {"type": "object", "properties": properties, "required": [key for key in value if all(isinstance(sample, dict) and key in sample for sample in samples)]}
    if isinstance(value, list):
        return {"type": "array", "items": _json_schema(value[0]) if value else {}}
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    return {"type": "string"}


# --------------------------------------------------------------------------- #
# Issue #3: OData / OData-like $batch 子请求解析
#
# POST /api/data/v9.0/$batch（multipart/mixed）内部的子请求才是真正的业务查询，
# 顶层 URL 只看到 $batch 一个端点。此机制通用于所有 multipart 批处理服务端：
# Dynamics 365 / SharePoint / SAP Gateway / Salesforce Composite / Graph API。
# 子请求解析为独立端点后，才能被生成为独立 MCP 工具（调用方无需手工拼 multipart）。
# --------------------------------------------------------------------------- #
_MULTIPART_CT = re.compile(r"multipart/\w+", re.I)
_BOUNDARY_RE = re.compile(r'boundary\s*=\s*"?([^";,\s]+)"?', re.I)
# 子请求起始行：METHOD <relative-path> HTTP/1.1（路径可能含复杂查询串）
_METHOD_LINE = re.compile(r"^([A-Z]{3,7})[ \t]+(\S+)[ \t]+HTTP/[\d.]+", re.M)
# 显式声明 OData 批处理的 URL 形态
_BATCH_URL = re.compile(r"(?:^|/)\$(?:batch|b1)\b", re.I)
# 抓包中的 postData 可能是 CRLF 或 LF（Chromium/存储链路会归一化），两者都要兼容。
_BLANK_LINE = re.compile(r"\r?\n\r?\n")


def _header_value(headers: dict[str, Any] | None, name: str) -> str:
    """大小写不敏感地取头值（redact_headers 保留原始大小写，可能是 content-type）。"""
    for key, value in (headers or {}).items():
        if str(key).lower() == name.lower():
            return str(value)
    return ""


def _is_json_content_type(content_type: str | None) -> bool:
    """响应 Content-Type 是否为 JSON（含 OData / ``+json`` / text/json 变体）。

    Issue #16：页面/控件端点（.axd/.aspx/.asmx/.svc 等）响应 text/html 或 302，
    不是 JSON 数据接口，不能生成「调用并解析 JSON」的工具。
    """
    if not content_type:
        return False
    media = content_type.split(";", 1)[0].strip().lower()
    return media in {"application/json", "text/json"} or media.endswith("+json")


def _looks_like_json_body(raw: Any) -> bool:
    """响应体是否是 JSON（严格解析，不是「首字符像」就算）。"""
    if not isinstance(raw, str) or not raw.strip():
        return False
    if raw.lstrip()[:1] not in ("{", "["):
        return False
    try:
        json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return False
    return True


def _non_json_response(responses: list[dict[str, Any]],
                       bodies: list[Any] | None = None) -> bool:
    """Issue #16 / #19：端点样本的响应是否「非 JSON」（页面/控件端点）。

    Issue #19：判定必须**同时看响应体**。大量 Java / 遗留系统
    用 ``Content-Type: text/plain`` 返回 JSON 体，只看响应头会把这类站点的接口
    整体误杀（实测大量端点只剩个位数）。

    判定仍保守：任一响应头是 JSON，**或任一响应体能解析为 JSON**，即视为数据接口、
    不标记。反之，观察到非 JSON 响应头或 3xx 重定向、且全无 JSON 证据才标记。
    仅标记不删除，保留人工复核权。
    """
    saw_json = False
    saw_non_json = False
    for response in responses:
        content_type = _header_value(response.get("headers"), "Content-Type")
        if content_type:
            if _is_json_content_type(content_type):
                saw_json = True
            else:
                saw_non_json = True
        status = response.get("status")
        if isinstance(status, int) and 300 <= status < 400:
            saw_non_json = True
    for raw in bodies or []:
        if _looks_like_json_body(raw):
            saw_json = True
    return saw_non_json and not saw_json


# --------------------------------------------------------------------------- #
# Fix 1: 业务文件下载端点（报表 / 导出 / 附件）
#
# 实测：``GET /api/report.csv`` 的响应是 ``Content-Type: text/csv``，
# ``_non_json_response`` 判 True，``project.session_to_registry_entries`` 随即把整条
# 端点丢弃 —— **0 个端点**进 registry，一个工具都不生成。而「下载报表」正是这类
# 系统的主要用途，属于能力缺口，不是策略偏好。
#
# 但也不能「非 JSON 一律放行」：把 HTML 页面 / 追踪像素当数据工具返回给调用方，
# 比不生成更糟。故这里要求**至少一条具体证据**（见 is_business_file_download）。
# --------------------------------------------------------------------------- #
# 直接构成证据的文档类媒体类型（不要求额外线索）
_FILE_CONTENT_TYPES = frozenset({
    "text/csv", "text/tab-separated-values", "application/csv",
    "application/pdf",
    "application/vnd.ms-excel",                 # .xls
    "application/vnd.ms-excel.sheet.macroenabled.12",
    "application/zip", "application/x-zip-compressed",
})
# OOXML 一族（.xlsx/.docx/.pptx …）都是这个前缀，逐个列举必然会漏
_FILE_CONTENT_TYPE_PREFIXES = ("application/vnd.openxmlformats-officedocument.",)
# octet-stream 是**泛二进制**：页面下载附件、追踪像素、字体都可能是它，
# 单凭它证据不足，必须再有文件名 / 路径线索才认。
_FILE_CONTENT_TYPE_NEEDS_NAME_HINT = "application/octet-stream"
# 路径末段 / Content-Disposition 文件名里的文档扩展名（后接引号、查询串或行尾）
_DOCUMENT_EXTENSION_RE = re.compile(
    r"\.(?:csv|xlsx?|pdf|docx?|zip)(?=[\"'?#]|\s*$)", re.I)
_FILENAME_PARAM_RE = re.compile(r"filename\*?\s*=", re.I)


def is_attachment_disposition(disposition: str | None) -> bool:
    """Content-Disposition 的 disposition-type 是否为 ``attachment``。

    只看**类型**：``inline; filename=...`` 是浏览器内联展示（页面/图片），不算下载；
    服务端也可能发 ``attachment; filename*=UTF-8''...``（RFC 5987）。
    """
    return bool(disposition) and str(disposition).strip().lower().startswith("attachment")


def _has_filename_hint(path: str, disposition: str | None) -> bool:
    """路径或 Content-Disposition 里有没有文档文件名（供 octet-stream 佐证）。"""
    if _DOCUMENT_EXTENSION_RE.search(path or ""):
        return True
    return bool(_FILENAME_PARAM_RE.search(disposition or ""))


def _media_type(headers: dict[str, Any] | None) -> str:
    """响应头里的媒体类型（去掉参数、小写）。"""
    raw = _header_value(headers, "Content-Type")
    return raw.split(";", 1)[0].strip().lower()


def is_business_file_download(method: str, path: str,
                              responses: list[dict[str, Any]] | None = None) -> bool:
    """端点是否是**业务文件下载**（报表 / 导出 / 附件），而不是页面或埋点。

    修复前：``GET /api/report.csv`` 的响应是 ``text/csv`` → ``_non_json_response``
    判 True → 生成阶段静默丢弃。本判据给它一条生路，但必须证据充分，**三条任一**：

      1. 响应带 ``Content-Disposition: attachment``（浏览器行为就是「下载」）；
      2. 响应 ``Content-Type`` 是文档 / 表格 / 压缩包类型：``text/csv``、
         ``application/pdf``、``application/vnd.ms-excel``、
         ``application/vnd.openxmlformats-officedocument.*``、``application/zip``；
         ``application/octet-stream`` 太笼统，**必须**再有文件名 / 路径线索
         （见 ``_has_filename_hint``）才认；
      3. 路径以文档扩展名结尾（``.csv/.xls/.xlsx/.pdf/.doc/.docx/.zip``）**且**方法是 GET。

    拒绝的例子（负例见 ``tests/test_non_json_response.py``）：``text/html`` 页面、
    ``image/gif`` 追踪像素、``application/octet-stream`` 且无任何文件名线索。

    >>> is_business_file_download("GET", "/api/report.csv",
    ...                           [{"headers": {"Content-Type": "text/csv"}}])
    True
    >>> is_business_file_download("GET", "/dashboard",
    ...                           [{"headers": {"Content-Type": "text/html"}}])
    False
    >>> is_business_file_download("GET", "/pixel.gif",
    ...                           [{"headers": {"Content-Type": "image/gif"}}])
    False
    """
    disposition = ""
    for response in responses or []:
        headers = (response or {}).get("headers") or {}
        if not disposition:
            disposition = _header_value(headers, "Content-Disposition")
        media = _media_type(headers)
        if not media:
            continue
        if media in _FILE_CONTENT_TYPES or media.startswith(_FILE_CONTENT_TYPE_PREFIXES):
            return True
        if media == _FILE_CONTENT_TYPE_NEEDS_NAME_HINT and _has_filename_hint(path, disposition):
            return True
    if disposition and is_attachment_disposition(disposition):
        return True
    return str(method or "").upper() == "GET" and bool(_DOCUMENT_EXTENSION_RE.search(path or ""))


def _parse_json_batch(body: str) -> list[dict[str, Any]]:
    """OData JSON-batch / Graph batch：{"requests": [{method, url, body}]}。"""
    try:
        payload = json.loads(body)
    except (TypeError, json.JSONDecodeError):
        return []
    requests = (payload or {}).get("requests") if isinstance(payload, dict) else None
    if not isinstance(requests, list):
        return []
    return [{"method": str(item.get("method", "GET")).upper(), "path": item.get("url", ""),
             "headers": item.get("headers") or {}, "body": item.get("body")}
            for item in requests if isinstance(item, dict) and item.get("url")]


def _parse_multipart_requests(body: str | None,
                              content_type: str | None = None) -> list[dict[str, Any]]:
    """解析 multipart/mixed 批处理请求体，返回 [{method, path, headers, body}]。

    兼容三种形态（通用，不针对单一站点）：
      * OData multipart/mixed（Dynamics / SharePoint / SAP Gateway）；
      * Salesforce Composite 风格的 JSON batch（{"batchRequests": [...]}）；
      * Graph JSON-batch（{"requests": [...]}）。
    boundary 优先取 Content-Type，缺失时从 body 首个 ``--`` 行推断——
    抓包的 postData 存的就是 multipart 原文。
    """
    if not body:
        return []
    lowered = (content_type or "").lower()
    if "json" in lowered:
        parsed = _parse_json_batch(body)
        if parsed:
            return parsed

    boundary = ""
    match = _BOUNDARY_RE.search(content_type or "")
    if match:
        boundary = match.group(1)
    if not boundary:
        first_line = body.lstrip("﻿ \t\r\n").split("\n", 1)[0].strip()
        if first_line.startswith("--"):
            boundary = first_line[2:].strip()
    if not boundary:
        return _parse_json_batch(body)

    out: list[dict[str, Any]] = []
    for chunk in body.split("--" + boundary)[1:]:
        if chunk.startswith("--"):
            continue  # 结束标记 --boundary--
        match = _METHOD_LINE.search(chunk)
        if not match:
            continue
        method, target = match.group(1).upper(), match.group(2)
        # 子请求自身的头与体以空行分隔；无体时空行后即为下一个 boundary 段。
        remainder = chunk[match.end():]
        pieces = _BLANK_LINE.split(remainder, 1)
        request_body = pieces[1] if len(pieces) == 2 else ""
        # 嵌套 changeset 的结尾 boundary（--cs1--）不属于子请求体，需截掉。
        request_body = re.split(r"\r?\n--", request_body, 1)[0].strip("\r\n")
        out.append({"method": method, "path": target, "headers": {}, "body": request_body or None})
    return out


def _absolute_url(base_netloc: str, scheme: str, target: str) -> str:
    """把子请求的相对路径与父请求的 scheme+host 拼接成绝对 URL。"""
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"{scheme or 'https'}://{base_netloc}" + (target if target.startswith("/") else "/" + target)


def _iter_capture_events(capture_path: Path) -> Iterator[dict[str, Any]]:
    """逐行解析 capture.jsonl：坏行跳过，文件不存在时什么都不产出。

    C-3 修复：此前 ``_load_events`` 先 ``read_text()`` 把整份文件读进内存、再拆成
    ``list[dict]``，于是长抓包在建立索引前会以「原文 + 全部事件 dict」两份形态同时
    驻留——这是整条分析链路里最大的一笔内存。逐行解析后，常驻内存只与实际用到的
    记录成正比（响应体等仍需保留，见 ``_index_capture``）。
    """
    try:
        stream = capture_path.open("r", encoding="utf-8")
    except FileNotFoundError:
        # 与修复前的 ``capture_path.exists()`` 等价；其余 OSError（权限、路径是目录）
        # 照旧抛给调用方，不在这里静默变成「空分析」。
        return
    with stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                yield value


@dataclass
class CaptureIndex:
    """一次抓包的索引（**不保留原始事件列表**，故内存不随抓包长度线性膨胀）。

    ``requests`` 以 ``(requestId, 跳数)`` 为键：CDP 对重定向链会用**同一个
    requestId 重新发出** ``requestWillBeSent``（capture.py 的注释也承认这一点），
    只按 requestId 建键会把整条链塌成最后一跳——``POST /form/x → 302 → GET /result``
    里真正干活的 POST 被丢掉，只剩一个没用的 GET 被生成成工具。
    ``responses`` / ``bodies`` 仍按 requestId 取**最后一条**（与修复前一致：
    重定向链的末条响应就是这条请求最终得到的响应；3xx 那一跳因此不会漏进
    ``_non_json_response``，把最终端点误标成「非 JSON」）。
    """

    requests: dict[tuple[Any, int], dict[str, Any]]
    responses: dict[Any, dict[str, Any]]
    bodies: dict[Any, dict[str, Any]]
    request_count: int


def _index_capture(capture_path: Path) -> CaptureIndex:
    """逐行建索引，顺带把 ``headers_patch`` 折进对应的 request 记录（Defect B）。"""
    requests: dict[tuple[Any, int], dict[str, Any]] = {}
    responses: dict[Any, dict[str, Any]] = {}
    bodies: dict[Any, dict[str, Any]] = {}
    patches: dict[Any, dict[str, Any]] = {}
    hops: dict[Any, int] = {}
    for event in _iter_capture_events(capture_path):
        kind = event.get("type")
        request_id = event.get("requestId")
        if kind == "request":
            hop = hops.get(request_id, 0)
            hops[request_id] = hop + 1
            requests[(request_id, hop)] = event
        elif kind == "response":
            responses[request_id] = event
        elif kind == "response_body":
            bodies[request_id] = event
        elif kind == "headers_patch":
            # B-1（Defect B）：requestWillBeSentExtraInfo 晚到时，capture.py 会补发一条
            # headers_patch（Cookie / Sec-* 这类浏览器合成头的**权威来源**）。此前
            # analyzer 只认 request/response/response_body，这类事件被整个忽略：请求行
            # 一旦已经落盘就永远缺 Cookie，auth_required / auth_schemes 判错，
            # 生成的工具不带鉴权（每个工具 401）。这里按 requestId 折回去。
            patches[request_id] = _merge_headers(patches.get(request_id), event.get("headers"))
    for key, request in requests.items():
        patch = patches.get(key[0])
        if patch:
            # 补丁更晚、更权威：它带的头以它为准，它没带的头一个都不能丢。
            requests[key] = {**request, "headers": _merge_headers(request.get("headers"), patch)}
    return CaptureIndex(requests, responses, bodies, len(hops))


# --------------------------------------------------------------------------- #
# 本次重做：参数默认值必须由「**不同**请求之间的比较」决定
#
# 实测事故（Citrix ADC 真实抓包生成的 MCP）：`count=yes`、`pageno=1`、
# `pagesize=25`、`bulkbindings=yes`、`filter=...` 被当成默认值烘进工具签名，
# 于是「列出全部」静默只返回 `__count`、分页被截断、语义被改、甚至 599。
# 根因是旧门槛只有 `sample_count >= 2 and len(values) == 1`：它把「这个端点被
# 采样了两次」当成了「这个参数的值被观测过两次」——两个请求完全相同时也算「两轮
# 采样」，于是任何参数都满足 `len(values) == 1`，默认值照烘。
#
# 新规则（离线、纯函数，**不发任何网络请求**）：
#   1. 先按请求签名去重，数出**不同请求**个数；少于 2 个 → 什么都分类不了；
#   2. 按「不同请求」之间的比较给每个参数分类：
#        fixed      每个请求都有、值完全一样 → 烘默认值；
#        variable   每个请求都有、但值会变   → 永不烘默认值，暴露为**必填**真参数；
#        occasional 有的请求没有它           → 可选、无默认值；
#   3. 顺便记录「疑似行为开关」（`switch_risk`，按名字/取值判定）及其验证结论
#      （`behaviour_switch`：拿抓包内「带它（取此值）」与「不带它 / 取别的值」的同端点
#      响应比结构；结构不同 → True；结构相同 → False；找不到对照 → None）。
#      注意：`verified` **不再**一票否决 —— `fixed` 参数按定义没有对照请求，
#      拿它当门槛等于把参数永久丢给使用者。
#      **但 `switch_risk` / `behaviour_switch is True` 是拦阻**：这类参数的取值会
#      切换响应形态（`count=yes` 只回 `__count`），烘任何一个快照值都会**静默**给出错误
#      的业务结论 —— 故一律不烘，并在 docstring 里说明。烘不烘只有一档（都不烘），
#      「必填 / 可选无默认值」**分两档**：实测 `behaviour_switch is True` → 必填；
#      只是名字/取值命中、无实测证据 → **可选且无默认值**（不传时请求里不带这个键，
#      服务端用自己的默认值）—— 名字表很宽（`page` / `sort` / `format` / `view` /
#      `search` / `query` / `filter` …），普通 CRUD 项目里这些参数大多并不切换形态，
#      一律逼成必填只会让调用方回头问使用者（见 generator 的 `_switch_blocks_default` /
#      `_param_is_required` / `_evidence_note`）。
#      **本结构只记「会不会切换」（True/False/None），不记「哪个取值 → 哪种响应形态」**：
#      `detect_behaviour_switch` 比的是两个**集合**是否相等（`shapes != others`），
#      结构签名本身也不落盘（`_structure_signature` 的结果只在本次调用内存里）。所以生成器
#      **无法**据它选出「返回完整数据」的那个取值 —— 那需要另一份证据（见 tests 与文档）。
#      没有证据时，生成器按「观测取值唯一」决定要不要烘（见 generator）。
# --------------------------------------------------------------------------- #
# 名字看起来可能改变响应**结构/语义**的参数（行为开关候选）。
_SWITCH_PARAM_NAMES = frozenset({
    "count", "filter", "bulkbindings", "pageno", "pagesize", "page",
    "top", "skip", "limit", "offset", "start", "size", "per_page", "perpage",
    "sort", "order", "orderby", "sortby", "scope", "view", "format",
    "expand", "select", "fields", "attrs", "include", "exclude",
    "all", "full", "detail", "details", "verbose", "raw", "meta", "metadata",
    "stats", "summary", "groupby", "aggregate", "distinct", "search",
    "query", "keyword", "csv", "export", "download", "attachment", "filterby",
})
# 取值本身就像开关的参数（yes/no/true/false/on/off）——无论叫什么名字都算候选。
_SWITCH_VALUES = frozenset({"yes", "no", "true", "false", "on", "off"})

# 少于 2 个不同请求时的提示语（软警告：不阻断生成，但要如实告诉 Agent）。
INSUFFICIENT_SAMPLES_HINT = (
    "该端点只观测到 {count} 个不同请求（其余为重复请求），没有可比较的对象，"
    "无法判断哪些参数固定、哪些会变；本次只对**取值唯一且取值不会改变返回内容**的参数"
    "沿用抓包取值作默认值（`count` / `pagesize` / `bulkbindings` / `page` 这类名字或取值"
    "像开关的参数一律不烘：实测过会切换形态的是必填，其余是可选、无默认值），"
    "其余参数不设默认值。"
    "请让用户再用一次该功能（产生至少第二个**不同**的请求：换筛选条件/翻页/"
    "带与不带某个开关各一次），再重新抓包分析。"
)


def is_switch_risk_param(name: str, values: list | None = None) -> bool:
    """参数是否「看起来可能改变响应」——只需要这种参数才做行为开关验证。

    判据是**名字**（count / filter / pageno / bulkbindings …）或**取值形态**
    （yes/no/true/false/on/off）。这是「值不值得去验证」的启发式，不是结论：
    真正的结论只能来自对照抓包里的**响应结构比较**（见 detect_behaviour_switch）。

    >>> is_switch_risk_param("count", ["yes"])
    True
    >>> is_switch_risk_param("status", ["open"])
    False
    """
    if str(name).strip().lower() in _SWITCH_PARAM_NAMES:
        return True
    lowered = {str(v).strip().lower() for v in (values or [])}
    return bool(lowered & _SWITCH_VALUES)


def _canonical_body(payload: Any) -> str:
    """请求体的规范化文本：表单按字段名排序，JSON 按键排序，其它原样。

    目的是让「同一个请求」在两次抓包里得到同一个签名（字段顺序不该算差异）。
    """
    if not payload or not isinstance(payload, str):
        return ""
    pairs = parse_form_urlencoded(payload)
    if pairs is not None:
        return "&".join(f"{unquote_plus(k)}={unquote_plus(v)}"
                        for k, v in sorted(pairs))
    try:
        parsed = json.loads(payload)
    except (TypeError, json.JSONDecodeError):
        return payload
    try:
        return json.dumps(parsed, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"))
    except (TypeError, ValueError):
        return payload


def request_signature(request: dict[str, Any]) -> tuple:
    """一个请求的「身份」：方法 + 主机 + 路径 + 排序后的 query + 规范化后的请求体。

    **刻意不含请求头**：Cookie / token / Sec-* 每次都在变，把它们算进来会让同一个
    请求被数成多个不同请求 —— 那正是本次要修的毛病（`sample_count >= 2` 的旧门槛
    把「重复的同一个请求」也当成两轮采样）。
    """
    request = request or {}
    parsed = urlsplit(request.get("url") or "")
    query = tuple(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return (str(request.get("method") or "GET").upper(),
            parsed.netloc.lower(), parsed.path, query,
            _canonical_body(request.get("postData")))


def _structure_signature(value: Any) -> Any:
    """只保留**结构**（键名 / 类型 / 嵌套），丢掉具体取值。"""
    if isinstance(value, dict):
        return ("obj", tuple(sorted((str(k), _structure_signature(v))
                                    for k, v in value.items())))
    if isinstance(value, list):
        # 列表只看首个元素的结构：多几行记录、计数变大都不算「结构变了」。
        return ("arr", _structure_signature(value[0]) if value else None)
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "num"
    return "str"


def response_structure(body: Any) -> Any:
    """响应体的结构签名；无法解析成 JSON 的非空文本记为 ``"text"``。

    行为开关的判据是「响应**结构**不同」而不是「响应内容不同」：
    `{"__count": 3}` vs `{"vserver": [...]}` 结构不同（是开关），
    同一个数组里多返回几行则结构相同（不是开关）。

    >>> response_structure('{"__count": 3}') == response_structure('{"vserver": []}')
    False
    """
    if isinstance(body, (dict, list)):
        return _structure_signature(body)
    if isinstance(body, str) and body.strip():
        try:
            return _structure_signature(json.loads(body))
        except (TypeError, json.JSONDecodeError):
            return "text"
    return None


def classify_request_params(param_sets: list[dict[str, str]]) -> dict[str, dict[str, Any]]:
    """按「不同请求」之间的比较给参数分类（本次规则的核心实现）。

    ``param_sets``：每个**不同请求**一份「参数名 → 值」（重复请求必须先去重，
    见 :func:`request_signature`）。少于 2 个不同请求时返回空 dict —— 没有比较
    对象就什么都分类不了，这也是「不烘任何默认值」的依据。

      * fixed      —— 每个请求都有、且值完全一样（**唯一**有资格烘默认值的一类）；
      * variable   —— 每个请求都有、但值会变（永不烘默认值，暴露为必填参数）；
      * occasional —— 有的请求没有它（可选、无默认值）。

    >>> classify_request_params([{"page": "1"}, {"page": "2"}])["page"]["class"]
    'variable'
    >>> classify_request_params([{"page": "1"}, {"page": "1"}])
    {}
    """
    total = len(param_sets or [])
    if total < 2:
        return {}
    values_by_name: dict[str, list[str]] = {}
    present_in: dict[str, int] = defaultdict(int)
    for params in param_sets:
        for name, value in (params or {}).items():
            bucket = values_by_name.setdefault(str(name), [])
            if value not in bucket:
                bucket.append(value)
            present_in[str(name)] += 1
    classified: dict[str, dict[str, Any]] = {}
    for name, values in values_by_name.items():
        if present_in[name] < total:
            klass = "occasional"
        elif len(values) > 1:
            klass = "variable"
        else:
            klass = "fixed"
        classified[name] = {"class": klass, "values": values,
                            "present_in": present_in[name], "requests": total}
    return classified


def detect_behaviour_switch(name: str, value: Any,
                            requests: list[dict[str, Any]]) -> bool | None:
    """离线比较「带该参数（取此值）」与「不带 / 取别的值」的**响应结构**。

    ``requests``：该端点的不同请求，每项为
    ``{"params": {名: 值}, "structure": <response_structure 的结果>}``。

    返回 True（结构不同 → 行为开关，生成物里照样会显示该值、请显式传别的值改变行为）/
    False（结构相同 → 不是开关）/ None（抓包里根本没有这种对照 → ``unverified``，绝不猜）。

    **本函数只比较已经落盘的抓包，绝不发网络请求**（owner 明确要求：对照由用户
    重新操作产生，分析器不提供任何请求重放能力）。

    注意：按规则 2，``fixed`` 参数（每个请求都带、值相同）**不存在**「不带」的
    对照请求，故对 fixed 参数的调用必然返回 None —— 这是这条判据的固有边界
    （fixed 参数照样烘默认值，见 `_annotate_evidence`），不是漏判。

    **返回的是三态布尔，不是「取值 → 响应形态」的映射**：这里只回答「换值会不会让
    结构变」（``shapes != others``），两个结构签名集合各自长什么样、哪个更完整，**都不
    返回、也不落盘**。所以生成器**无法**据此判定「哪个取值返回完整数据」；要支持那个
    判定，必须在这里额外产出「逐取值 → 结构签名」并写进证据 —— 这条**尚未实现**，
    现阶段的降级是「不烘 + 文档说明」，且**实测档（`True`）才必填**、名字档可选无默认值
    （见 generator 的 `_switch_blocks_default` / `_param_is_required`，
    以及 `docs/reference.md` 的「取值会切换响应形态的参数」一节）。
    """
    present, contrast = [], []
    for request in requests or []:
        params = request.get("params") or {}
        if name in params and params[name] == value:
            present.append(request)
        else:
            contrast.append(request)
    shapes = {r.get("structure") for r in present if r.get("structure") is not None}
    others = {r.get("structure") for r in contrast if r.get("structure") is not None}
    if not shapes or not others:
        return None
    return shapes != others


def _annotate_evidence(name: str, evidence: dict[str, Any],
                       requests: list[dict[str, Any]]) -> dict[str, Any]:
    """给一条分类结果补上「要不要验证 / 验证结果」字段。

    ``verified`` 的语义是「检查过（或根本没有需要检查的东西）且确认安全」，
    **它是一个记录，不再是一票否决**（生成器烘不烘默认值只看 `class`、观测取值，
    以及名字/取值那道闸门；`behaviour_switch` 才是「必填还是可选」的那一档）：

      * 不是开关候选（名字/取值都不像）→ 无需验证 → True；
      * 是候选、且抓包里有「带 / 不带」对照 → 结构相同 True / 不同 False；
      * 是候选、但抓包里没有对照（`fixed` 参数按定义就没有）→ None 判定 → False。

    为什么不再拿它当门槛：`fixed` 参数在每个请求里都取同一个值，烘它就是复现抓包时的
    行为；而「拿不到对照就永不烘」等于把参数永久丢给不懂 HTTP 的使用者去填。
    """
    evidence = dict(evidence)
    risk = is_switch_risk_param(name, evidence.get("values"))
    evidence["switch_risk"] = risk
    evidence["behaviour_switch"] = (
        detect_behaviour_switch(name, evidence["values"][0], requests)
        if risk and evidence.get("values") else None)
    evidence["verified"] = (not risk) or (evidence["behaviour_switch"] is False)
    return evidence


def analyze_param_evidence(selected: list[dict[str, Any]]) -> dict[str, Any]:
    """从端点的样本里算出「不同请求」证据 + 每个 query / 表单参数的分类。

    返回::

        {"distinct_request_count": int,        # 去重后的不同请求数
         "insufficient_samples": bool,         # < 2 → 什么都分类不了
         "evidence_hint": str | None,          # 给 Agent 的「请用户再操作一次」提示
         "query_params": {名: 证据},            # 见 classify_request_params
         "form_params": {名: 证据}}

    证据字段：``class`` / ``values`` / ``present_in`` / ``requests`` /
    ``switch_risk`` / ``behaviour_switch`` / ``verified``。生成器只看 ``class`` 与
    取值（`fixed` 或「无证据 + 取值唯一」才烘；行为开关结论只在 variable / occasional
    上作说明），不再看 ``sample_count``（那是「采样次数」，不是「比较次数」）。
    """
    requests: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for sample in selected or []:
        request = (sample or {}).get("request") or {}
        signature = request_signature(request)
        if signature in seen:
            continue                      # 重复请求不提供任何比较证据
        seen.add(signature)
        query: dict[str, str] = {}
        for key, value in parse_qsl(urlsplit(request.get("url") or "").query,
                                    keep_blank_values=True):
            query.setdefault(key, value)
        form: dict[str, str] = {}
        for name, raw_value in parse_form_urlencoded(request.get("postData")) or []:
            form.setdefault(unquote_plus(name), unquote_plus(raw_value))
        requests.append({
            "params": query,
            "form_params": form,
            "structure": response_structure(((sample or {}).get("body") or {}).get("body")),
        })
    distinct = len(requests)
    query_evidence = {name: _annotate_evidence(name, ev, requests)
                      for name, ev in classify_request_params(
                          [r["params"] for r in requests]).items()}
    form_evidence = {name: _annotate_evidence(name, ev, requests)
                     for name, ev in classify_request_params(
                         [r["form_params"] for r in requests]).items()}
    return {
        "distinct_request_count": distinct,
        "insufficient_samples": distinct < 2,
        "evidence_hint": (INSUFFICIENT_SAMPLES_HINT.format(count=distinct)
                          if distinct < 2 else None),
        "query_params": query_evidence,
        "form_params": form_evidence,
    }


def merge_param_evidence(old: dict[str, Any] | None,
                         new: dict[str, Any] | None) -> dict[str, Any]:
    """合并两轮抓包（或两个同构端点）的参数证据——**证据只会变弱，不会变强**。

    旧实现把 ``sample_count`` 累加，于是「同一个请求抓了两次」也会变成「两轮采样」，
    默认值照烘（F7 的教训换了个形态重来）。这里取**保守**合并：

      * ``requests`` 取 max、``present_in`` 取 min —— 任一轮观测到「有的请求没带它」，
        合并后仍是 occasional，不会被反向洗白成 fixed；
      * ``values`` 并集 —— 跨轮出现的不同取值照样判成 variable；
      * ``behaviour_switch`` 只能从「结构相同」被推翻成「结构不同」，反之不然；
        任一轮没拿到对照（None）时，只要另一轮判出结构不同就是行为开关。
    """
    old = old or {}
    new = new or {}
    if not old:
        return dict(new)
    if not new:
        return dict(old)
    values = list(old.get("values") or [])
    for value in new.get("values") or []:
        if value not in values:
            values.append(value)
    requests_total = max(int(old.get("requests") or 0), int(new.get("requests") or 0))
    present_in = min(int(old.get("present_in") or 0), int(new.get("present_in") or 0))
    if present_in < requests_total:
        klass = "occasional"
    elif len(values) > 1:
        klass = "variable"
    else:
        klass = "fixed"
    old_switch, new_switch = old.get("behaviour_switch"), new.get("behaviour_switch")
    if old_switch is True or new_switch is True:
        switch: bool | None = True
    elif old_switch is False and new_switch is False:
        switch = False
    else:
        switch = None
    merged = {"class": klass, "values": values,
              "present_in": present_in, "requests": requests_total}
    risk = bool(old.get("switch_risk") or new.get("switch_risk")
                or is_switch_risk_param("", values))
    merged["switch_risk"] = risk
    merged["behaviour_switch"] = switch
    merged["verified"] = (not risk) or (switch is False)
    return merged


def analyze_capture(
    session_dir: Path,
    tracking_domains: set[str] | None = None,
    response_bytes_threshold: int = 1024 * 1024,
    sample_count_threshold: int = 50,
) -> dict[str, Any]:
    """分析一次抓包。response_bytes_threshold / sample_count_threshold 为
    Issue #2 的体积与频次启发式阈值（只产生 review_suggested 标记）。"""
    index = _index_capture(session_dir / "capture.jsonl")
    tracking_domains = tracking_domains or set()
    # C-3：请求以 (requestId, 跳数) 为键，重定向链的每一跳都保留（不再只留最后一跳）。
    requests, responses, bodies = index.requests, index.responses, index.bodies
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    filtered = 0
    auth_candidates: list[dict[str, Any]] = []
    candidate_ids: set[Any] = set()
    for (request_id, _hop), request in requests.items():
        url = request.get("url", "")
        parsed = urlsplit(url)
        path = parsed.path or "/"
        if request.get("method") == "OPTIONS" or request.get("resourceType") in STATIC_TYPES or STATIC_EXTENSIONS.search(path) or parsed.netloc in tracking_domains:
            filtered += 1
            continue
        response = responses.get(request_id, {})
        body = bodies.get(request_id, {})
        sample = {"request": request, "response": response, "body": body}
        grouped[(request.get("method", "GET"), parsed.netloc)].append(sample)
        if request.get("auth_candidate") and request_id not in candidate_ids:
            # 同一 requestId 的每一跳都指向同一个请求，候选只记一次（修复前按
            # requestId 建 dict 天然去重，这里不能因为保留了各跳就记成多条）。
            candidate_ids.add(request_id)
            auth_candidates.append({"request_id": request_id, "url": url, "method": request.get("method"), "token_paths": request.get("token_paths", [])})
        # Issue #3: 解析 multipart/mixed（或 JSON-batch）里的子请求，作为独立端点。
        # 仅对显式批处理 URL 或 multipart Content-Type 的请求尝试，避免误伤普通 POST。
        content_type = _header_value(request.get("headers"), "Content-Type")
        post_data = request.get("postData")
        if post_data and (_BATCH_URL.search(path) or _MULTIPART_CT.search(content_type)):
            scheme = parsed.scheme or "https"
            for sub in _parse_multipart_requests(post_data, content_type):
                sub_url = _absolute_url(parsed.netloc, scheme, sub["path"])
                grouped[(sub["method"], parsed.netloc)].append({
                    "request": {
                        "url": sub_url, "method": sub["method"],
                        "headers": request.get("headers", {}),
                        "postData": sub.get("body"),
                        "resourceType": "XHR", "auth_candidate": request.get("auth_candidate"),
                        "token_paths": request.get("token_paths", []),
                    },
                    "response": {},
                    # 子请求响应体无独立记录；复用父请求的元数据（size 等）
                    "body": {},
                    "batch_parent": {"request_id": request_id, "url": url,
                                     "method": request.get("method"), "path": path},
                })
    endpoints: list[dict[str, Any]] = []
    for (method, host), samples in grouped.items():
        normalized = normalize_paths([sample["request"].get("url", "") for sample in samples])
        for item in normalized:
            selected = [samples[index] for index in item.sample_indexes]
            first = selected[0]
            request_body_values = []
            response_values = []
            total_size = 0
            max_size = 0
            for sample in selected:
                request_body = sample["request"].get("postData")
                response_body = sample["body"].get("body")
                size = int(sample["body"].get("size") or 0)
                total_size += size
                max_size = max(max_size, size)
                for target, values in ((request_body, request_body_values), (response_body, response_values)):
                    try:
                        parsed_value = json.loads(target) if target else None
                    except (TypeError, json.JSONDecodeError):
                        parsed_value = None
                    if parsed_value is not None:
                        values.append(parsed_value)
            endpoint_id = f"ep_{len(endpoints) + 1:03d}"
            # Issue #12: 判定纳入凭据 Cookie（此前只看 Authorization 与 auth_candidate，
            # 导致 CDP 抓到 Cookie 后仍判为无需鉴权）。
            auth_required = any(
                _request_needs_auth(sample["request"]) for sample in selected
            )
            # S13：这条端点**自己**实测到的鉴权方式（本端点的样本并集）。
            # 与 auth_required 的布尔互补 —— 布尔回答「要不要凭据」，hint 回答
            # 「要哪一种」。生成物据此逐端点决定发 Authorization 还是 Cookie。
            auth_hint = _merge_auth_hints(
                *[_auth_hints_in(sample["request"].get("headers")) for sample in selected])
            # 本次重做：默认值的唯一依据 —— 去重后的「不同请求」之间的比较。
            evidence = analyze_param_evidence(selected)
            # Query-parameter samples across all captured URLs of this endpoint —
            # the generator turns these into typed function signatures.
            query_params: dict[str, list[str]] = defaultdict(list)
            for sample in selected:
                for key, value in parse_qsl(urlsplit(sample["request"].get("url", "")).query):
                    if value not in query_params[key]:
                        query_params[key].append(value)
            # Issue #23: 表单编码请求体的字段同样要变成工具参数。传统服务端渲染系统
            # 的接口全靠 POST 体传参，此前只解析 JSON 体导致参数全丢——工具能连通
            # 但缺参数必然业务报错。
            request_body_params: dict[str, list[str]] = defaultdict(list)
            for sample in selected:
                for name, raw_value in parse_form_urlencoded(sample["request"].get("postData")) or []:
                    value = unquote_plus(raw_value)
                    if value and value not in request_body_params[name]:
                        request_body_params[name].append(value)
            endpoints.append({
                "endpoint_id": endpoint_id,
                "method": method,
                "host": host,
                "path": item.path,
                "url": first["request"].get("url"),
                "sample_count": len(selected),
                "single_sample": len(selected) < 2,
                # 本次重做：**不同请求**个数（重复请求不算证据）。默认值只看它。
                "distinct_request_count": evidence["distinct_request_count"],
                "insufficient_samples": evidence["insufficient_samples"],
                "evidence_hint": evidence["evidence_hint"],
                "query_param_evidence": evidence["query_params"],
                "request_body_param_evidence": evidence["form_params"],
                "param_provenance": {},
                "auth_required": auth_required,
                # S13：本端点实测到的鉴权载体（["Bearer"] / ["cookie"] /
                # ["Bearer", "cookie"] / ["none"]）。生成物按它逐端点发凭据。
                "auth_hint": auth_hint,
                "query_params": {k: v for k, v in query_params.items()},
                # Issue #23: 表单编码体字段的样本值 → 生成器据此出具名参数
                "request_body_params": {k: v for k, v in request_body_params.items()},
                "request_schema": _json_schema(request_body_values[0], request_body_values) if request_body_values else None,
                "response_schema": _json_schema(response_values[0], response_values) if response_values else None,
                # Issue #16: 响应非 JSON（页面/控件端点）→ 标记不删除，生成阶段默认跳过
                # Issue #19: 判定同时看响应体（text/plain 返回 JSON 的接口不该被误杀）
                "non_json_response": _non_json_response(
                    [s["response"] for s in selected],
                    [s["body"].get("body") for s in selected]),
                # Fix 1: 业务文件下载（报表/导出）——响应确实不是 JSON，但它是**用户
                # 要的东西**。单独打标后，生成阶段不再按 non_json_response 丢弃它
                # （见 project.generation_skip_reasons），生成器则改为原样返回响应体。
                "file_response": is_business_file_download(
                    method, item.path, [s["response"] for s in selected]),
                # S20：本次采样里是否有响应体因超过体积上限被**整条丢弃**（只留 size）。
                # 丢掉之后 response_schema 必然是 None，使用者/LLM 却看不到「响应没抓到」，
                # 会据不完整的数据推断出错的参数——故在端点与摘要上都如实标出来。
                "response_body_dropped": any(
                    s["body"].get("body_dropped") for s in selected),
                "description": None,
                "notes": None,
                "param_name_guessed": bool(item.parameter_names),
                "total_response_bytes": total_size,
                "max_response_bytes": max_size,
                # Issue #3 溯源：子请求记录其父 $batch，便于人工复核拼装关系
                "batch_parent": first.get("batch_parent"),
            })
    # ---- C-3: 噪音标记（不删除，保留人工复核权） --------------------------
    for endpoint in endpoints:
        endpoint["noise"] = _is_noise(endpoint["host"], endpoint["path"])

    # ---- Issue #15: 可独立生成性标记（标记不删除，保留人工复核权） --------
    for endpoint in endpoints:
        ep_path = endpoint.get("path") or ""
        if is_odata_bound_function(ep_path):
            # 绑定函数依赖父请求上下文参数，独立成工具必失败
            endpoint["not_independently_callable"] = True
            endpoint["not_callable_reason"] = "odata_bound_function"
        pagination = suggest_pagination(endpoint.get("query_params"),
                                        bool(endpoint.get("batch_parent")),
                                        ep_path)
        if pagination:
            endpoint["pagination_suggested"] = pagination
        required_query = require_query_param_suggestion(endpoint.get("query_params"))
        if required_query:
            endpoint["required_query_param"] = required_query

    # ---- B-1: 命名参数化二遍处理 + 同构合并 -------------------------------
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for ep in endpoints:
        new_path, param_names = parameterize(ep["path"], ep["host"])
        ep["path_params"] = param_names or [seg.strip("{}") for seg in new_path.split("/") if seg.startswith("{")]
        key = (ep["method"], ep["host"], new_path)
        if key not in merged:
            ep = dict(ep)
            ep["path"] = new_path
            ep["query_params"] = dict(ep.get("query_params") or {})
            merged[key] = ep
        else:
            keep = merged[key]
            keep["sample_count"] = keep.get("sample_count", 1) + ep.get("sample_count", 1)
            keep["auth_required"] = keep.get("auth_required") or ep.get("auth_required")
            # S13：同一条参数化路径的不同形态，鉴权方式取**并集**（保守方向：宁可多发
            # 一种凭据，也不能因为合并把某一形态需要的 Cookie 丢掉）。
            keep["auth_hint"] = _merge_auth_hints(keep.get("auth_hint"), ep.get("auth_hint"))
            keep["noise"] = keep.get("noise") and ep.get("noise")  # 任一非噪音即保留
            keep["non_json_response"] = keep.get("non_json_response", False) and ep.get("non_json_response", False)
            # Fix 1: 与 noise/auth_required 同向（任一成立即成立）——合并的是同一个
            # 参数化路径，其中任一形态被证据认定为文件下载，就不该因为它被丢掉。
            keep["file_response"] = keep.get("file_response", False) or ep.get("file_response", False)
            # S20：与 file_response 同向（任一次采样丢掉响应体即成立）——合并后的端点
            # 只要有一跳的响应没抓到，它的 response_schema 就同样不可信。
            keep["response_body_dropped"] = (keep.get("response_body_dropped", False)
                                             or ep.get("response_body_dropped", False))
            keep["total_response_bytes"] = keep.get("total_response_bytes", 0) + ep.get("total_response_bytes", 0)
            keep["max_response_bytes"] = max(keep.get("max_response_bytes", 0), ep.get("max_response_bytes", 0))
            for k, v in (ep.get("query_params") or {}).items():
                bucket = keep["query_params"].setdefault(k, [])
                for val in v:
                    if val not in bucket:
                        bucket.append(val)
            # Issue #23: 同构合并时表单体字段也要并入
            keep_body = keep.setdefault("request_body_params", {})
            for k, v in (ep.get("request_body_params") or {}).items():
                bucket = keep_body.setdefault(k, [])
                for val in v:
                    if val not in bucket:
                        bucket.append(val)
            # 本次重做：参数证据同样合并（保守方向：证据只会变弱，见
            # merge_param_evidence）。不同请求数取 max，避免把两条相同路径的端点
            # 拼成「有对照」的假象。
            keep["distinct_request_count"] = max(
                int(keep.get("distinct_request_count") or 0),
                int(ep.get("distinct_request_count") or 0))
            keep["insufficient_samples"] = keep["distinct_request_count"] < 2
            if keep["insufficient_samples"] and not keep.get("evidence_hint"):
                keep["evidence_hint"] = INSUFFICIENT_SAMPLES_HINT.format(
                    count=keep["distinct_request_count"])
            for field in ("query_param_evidence", "request_body_param_evidence"):
                keep_ev = dict(keep.get(field) or {})
                for name, ev in (ep.get(field) or {}).items():
                    keep_ev[name] = merge_param_evidence(keep_ev.get(name), ev)
                keep[field] = keep_ev
    endpoints = list(merged.values())
    # F6: endpoint_id **只分配一次**（上面建端点时按首次出现顺序），合并与后续删除都
    # 不得再按位置重排。修复前这里有一遍 `ep["endpoint_id"] = f"ep_{i:03d}"`，把
    # 合并后（以及 auth_login 被移出后）的 id 重新编号，于是 analyze_traffic 摘要里
    # 给出的衔接键与 generate_mcp_server(endpoint_ids=[...]) 的解释**不是同一个东西**：
    # 噪声端点排在前面时，摘要的 ep_002 会被生成阶段解析成另一个路径。
    # 合并后 id 出现空档（如 ep_001/ep_003）是**正确**的：空档代表被合并/被移出的
    # 端点，衔接键的价值正在于「一次分配、全程不变」。

    # ---- Issue #2: 体积/频次启发式——只标记「待复核」，不删除、不当噪音 -----
    for ep in endpoints:
        hint = _heavy_response_suggestion(
            ep.get("sample_count", 1),
            ep.get("total_response_bytes", 0),
            ep.get("max_response_bytes", 0),
            response_bytes_threshold,
            sample_count_threshold,
        )
        ep["review_suggested"] = bool(hint)
        ep["review_reasons"] = hint["reasons"] if hint else []

    # ---- 站点档案（可选）：语义化 tool_name / 描述 / 站点专属噪音 ----------
    profile = _load_site_profile(base_host) if (base_host := _majority_host(endpoints)) else None
    if profile:
        for ep in endpoints:
            info = profile["describe"](ep["host"], ep["path"])
            if info:
                ep["tool_name"], ep["description"] = info
            if any(re.search(p, ep["path"]) for p in profile.get("drop_path_patterns", [])) \
                    or ep["host"] in profile.get("drop_hosts", []):
                ep["noise"] = True

    # ---- C-1: 登录接口识别（移出普通工具列表，转 auth_login） --------------
    auth_login = detect_auth_login(endpoints, session_dir)
    if auth_login:
        endpoints = [e for e in endpoints
                     if not (e["host"] == auth_login["host"] and e["path"] == auth_login["path"])]

    host_counts = defaultdict(int)
    for endpoint in endpoints:
        host_counts[endpoint["host"]] += 1
    base_host = max(host_counts, key=host_counts.get) if host_counts else None
    for endpoint in endpoints:
        endpoint["cross_host"] = endpoint["host"] != base_host
    # Per-host auth schemes: redacted headers keep the scheme ("Basic ***") and
    # cookie names, which is exactly what the generator needs to emit correct auth.
    #
    # S13：这里是**主机级兜底**（登录工具、以及没记 auth_hint 的旧条目在用），
    # 端点级结论已经在上面的 `auth_hint` 里逐条记下。两条修复：
    #   1. `cookie_names` 跨该主机**全部**分组取并集 —— 修复前是「最后一个带非空
    #      Authorization 的分组覆盖前面所有分组的集合」，实测把 NITRO_SK 这类
    #      无标记名字整类丢掉，生成物只填半罐 Cookie，服务端回 1026 且不说是缺谁。
    #   2. 记下该主机**观测到的全部** scheme（`schemes`），供 `diff_hosts` 报告
    #      「同一域名混用多种登录方式」，而不是静默取其一。
    auth_schemes: dict[str, dict[str, Any]] = {}
    for (method, host), samples in grouped.items():
        slot = auth_schemes.setdefault(
            host, {"scheme": None, "cookie_names": [], "schemes": []})
        for sample in samples:
            headers = sample["request"].get("headers", {}) or {}
            for name, value in headers.items():
                if not value:
                    continue
                low = name.lower()
                if low == "authorization":
                    scheme = str(value).split(" ", 1)[0].strip()
                    if not scheme:
                        continue
                    if scheme not in slot["schemes"]:
                        slot["schemes"].append(scheme)
                    # 主机级主方案：**第一条**观测到的 Authorization，保序且可复现
                    # （端点级结论不受这里影响，见 auth_hint）。
                    if slot["scheme"] is None:
                        slot["scheme"] = scheme
                elif low == "cookie":
                    for part in str(value).split(";"):
                        cname = part.split("=", 1)[0].strip()
                        if cname and cname not in slot["cookie_names"]:
                            slot["cookie_names"].append(cname)
    result = {
        "endpoints": endpoints,
        "auth_login": auth_login,
        "auth_metadata": {"auth_candidates": auth_candidates, "auth_schemes": auth_schemes},
        # total 仍是**不同 requestId 的个数**（重定向的重复事件不算新请求），
        # 与修复前同义；filtered 统计被过滤掉的记录数。
        "stats": {"total": index.request_count, "filtered": filtered, "unique": len(endpoints),
                  "noise_marked": sum(1 for e in endpoints if e.get("noise")),
                  # Fix 1: 文件/流式端点计数（它们**不会**被生成阶段跳过，见
                  # project.generation_skip_reasons）
                  "file_response": sum(1 for e in endpoints if e.get("file_response")),
                  # S20：响应体被整条丢弃的端点个数（丢失必须可见，不能静默）。
                  "response_body_dropped": sum(
                      1 for e in endpoints if e.get("response_body_dropped")),
                  "review_suggested": sum(1 for e in endpoints if e.get("review_suggested")),
                  "noise_response_bytes": sum(e.get("total_response_bytes", 0) for e in endpoints if e.get("noise")),
                  "total_response_bytes": sum(e.get("total_response_bytes", 0) for e in endpoints),
                  # 本次重做：样本不足（少于 2 个不同请求）的端点个数。软警告，不阻断生成。
                  "insufficient_samples": sum(1 for e in endpoints if e.get("insufficient_samples"))},
        "base_url": f"https://{base_host}" if base_host else None,
    }
    (session_dir / "analysis.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def _majority_host(endpoints: list[dict[str, Any]]) -> str | None:
    counts: dict[str, int] = defaultdict(int)
    for ep in endpoints:
        counts[ep.get("host", "")] += 1
    return max(counts, key=counts.get) if counts else None