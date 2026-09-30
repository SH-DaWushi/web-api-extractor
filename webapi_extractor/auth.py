"""HTTP and interactive authentication workflows."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from . import dialog, win_crypto
from .analyzer import LOGIN_MODE_SUFFIX
from .domain import same_site
from .proxy_env import sanitize_no_proxy
from .redaction import is_auth_candidate
from .storage import sanitize_path_segment


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _site_key(url: str) -> str:
    """把 URL 映射成 ``auth_states`` 里的安全文件名片段（不含扩展名）。

    D2：旧的 ``netloc.replace(...) or "site"`` 有两个问题——
    netloc 超长/含控制字符时会生成无法创建的文件名；netloc 为空（无 scheme 的
    输入）时一律塌成 ``"site"``，不同目标于是共用、互相覆盖同一份登录态。

    普通主机保持可读形态（``oa.example.com:8443`` → ``oa_example_com_8443``）；
    一旦该形态需要净化/截断（超长、含控制字符等），或 netloc 为空，就改为
    按**整个 URL** 取确定性散列，保证不同目标得到不同且可创建的名字。
    """
    try:
        netloc = urlparse(url).netloc
    except ValueError:
        # 畸形方括号 IPv6 等会让 urlparse 直接抛错（如 "http://[::1"）。
        netloc = ""
    if netloc:
        readable = netloc.replace(":", "_").replace(".", "_")
        sanitized = sanitize_path_segment(readable, default="site")
        if sanitized == readable:
            return sanitized
    digest = hashlib.sha256(url.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return f"site_{digest}"


def _secure_file(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _cookie_key(cookie: dict[str, Any]) -> tuple[str, str, str]:
    return (cookie.get("domain") or "", cookie.get("path") or "", cookie.get("name") or "")


def _cookie_baseline(cookies: list[dict[str, Any]]) -> dict[tuple[str, str, str], Any]:
    """Issue #20：登录前落下的 Cookie 基线（键 → 值），用于识别「登录后新出现」。"""
    return {_cookie_key(cookie): cookie.get("value") for cookie in cookies}


class _LoginFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.action: str | None = None
        self.fields: dict[str, str] = {}
        self._in_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "form" and not self._in_form:
            self._in_form = True
            self.action = attributes.get("action")
        elif tag == "input" and self._in_form and attributes.get("name"):
            self.fields[attributes["name"]] = attributes.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._in_form = False


# --------------------------------------------------------------------------- #
# 凭据的落盘/读回：DPAPI 密文（`secrets_enc`），**不再写明文**。
#
# 旧版本在登录态文件里写 `"secrets": {"username":…, "password":…}`——明文。
# 该文件是长期留存的登录态（后续 start_capture 直接复用，还可能被备份/同步/
# 截图），凭据落进去就等于泄露。既然「存下账号密码、下次可复用」这个能力要保留，
# 落盘的那一份就必须只有**同一台机器上的同一个 Windows 用户**能解开：
# 整个 {"username","password"} 先 JSON 编码，再交给 win_crypto（DPAPI，用户作用域），
# base64 后存进 `secrets_enc` 一个字段。
#
# 加密不可用时**绝不回退成明文**：凭据只留在本进程内存（下面的 _MEMORY_SECRETS），
# 并把「没保存成功」如实回报给调用方——不能对用户谎称已保存。
# --------------------------------------------------------------------------- #
_SECRETS_ENC_FIELD = "secrets_enc"
_LEGACY_SECRETS_FIELD = "secrets"

# 进程内兜底：DPAPI 不可用（或加密失败）时，账号密码只存在这里，随进程消失。
# 键是 auth_state 文件名（即 _site_key(url)），与磁盘文件一一对应。
_MEMORY_SECRETS: dict[str, dict[str, str]] = {}


def _encrypt_secrets(username: str, password: str) -> str:
    """把 ``{"username","password"}`` 加密成 base64 字符串（DPAPI，用户作用域）。

    编码顺序是 JSON → UTF-8 → DPAPI → base64：base64 让密文能安全地放进 JSON
    字符串，一个字段同时覆盖账号与密码。失败会抛 ``DPAPIError``/``OSError``，
    由调用方决定「不落盘」的降级——本函数不会退回明文。
    """
    payload = json.dumps(
        {"username": username, "password": password}, ensure_ascii=False
    ).encode("utf-8")
    return base64.b64encode(win_crypto.protect(payload)).decode("ascii")


def _store_secrets(state: dict[str, Any], site_key: str, username: str, password: str) -> str | None:
    """把凭据放进待落盘的 ``state``；成功返回 ``None``，失败返回原因（给用户看）。

    失败时**只**把凭据留在 ``_MEMORY_SECRETS``（本次会话可用），不写任何明文。
    """
    _MEMORY_SECRETS[site_key] = {"username": username, "password": password}
    if not win_crypto.available():
        return "当前平台无法使用 DPAPI（非 Windows，或 crypt32 加载失败）"
    try:
        state[_SECRETS_ENC_FIELD] = _encrypt_secrets(username, password)
    except Exception as exc:  # noqa: BLE001 —— 见下
        # 这里**故意**兜住所有异常：加密失败既不该让已经成功的登录整体失败
        # （Cookie 已经拿到了），更不该退化成明文落盘；只需如实上报「没存成」。
        return f"{type(exc).__name__}: {exc}"
    return None


def _load_state_file(path: Path) -> dict[str, Any] | None:
    """读登录态 JSON；文件不存在/读不动/不是对象一律返回 None，不抛异常。"""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _preserve_encrypted_secrets(path: Path) -> dict[str, Any]:
    """整体重写文件**之前**，先把 ``secrets_enc`` 取出来（没有则空字典）。

    Playwright 的 ``storage_state`` 会**整体覆盖**文件，只写 cookies/origins。
    旧实现直接覆盖，于是 ``http_login`` 存下的 DPAPI 密文凭据被抹掉（残留②）：
    用户下次想复用账号密码就得重输。这里先把密文捞出来，写完再合并回去。
    """
    state = _load_state_file(path)
    if state is None:
        return {}
    blob = state.get(_SECRETS_ENC_FIELD)
    return {_SECRETS_ENC_FIELD: blob} if isinstance(blob, str) and blob else {}


def _merge_encrypted_secrets(path: Path, preserved: dict[str, Any]) -> bool:
    """把重写前保留的 ``secrets_enc`` 合并回新文件；返回是否真的合并了。

    密文只在本机同一个 Windows 用户下可解，搬到别处也读不出，所以合并它不扩大
    泄露面；合并失败只是维持旧行为（没有凭据可复用），**绝不影响**已保存的登录态。
    """
    if not preserved:
        return False
    state = _load_state_file(path)
    if state is None:
        return False
    if state.get(_SECRETS_ENC_FIELD):
        # 新文件里已经有密文（不该发生）——不覆盖，避免用旧值盖掉更新的凭据。
        return False
    state.update(preserved)
    try:
        path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        return False
    _secure_file(path)
    return True


def _migrate_legacy_secrets(path: Path, state: dict[str, Any], secrets: dict[str, str]) -> bool:
    """把旧版明文 ``secrets`` 就地换成 ``secrets_enc``（顺手把明文从磁盘抹掉）。

    加不加密得成，取决于 DPAPI 是否可用：加不了就**保持原样**继续可读，
    绝不把文件改坏、也绝不写出一份「半明文」。返回是否迁移成功。
    """
    if not win_crypto.available():
        return False
    try:
        state[_SECRETS_ENC_FIELD] = _encrypt_secrets(secrets["username"], secrets["password"])
    except Exception:  # noqa: BLE001 —— 迁移是尽力而为，失败就让文件维持明文可读
        return False
    state.pop(_LEGACY_SECRETS_FIELD, None)
    try:
        path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        return False
    _secure_file(path)
    return True


def read_auth_state_secrets(path: Path | str) -> dict[str, str] | None:
    """读回登录态文件里的账号密码 —— 定位是**迁移 / 排查工具，不是生产依赖**。

    生产路径**刻意不调用它**：抓包与分析只要 Cookie；生成物与它的 401 自动重登录
    用的是**生成物自己**的 ``cred_cache.bin``，都不需要从这里读回账号密码。既然
    没有真实调用点，就**不虚构**一个（为了「用上它」而加调用点只会制造假依赖）。
    它只为两件事存在：

    1. 把旧版遗留的**明文** ``secrets`` 迁移成 ``secrets_enc``（读一次即迁移，
       顺手把明文从磁盘抹掉）；
    2. 排查 / 运维时确认「这份登录态里到底有没有可复用的凭据」。

    查找顺序：

    1. ``secrets_enc``（DPAPI 密文）→ 解密；
    2. 旧版本的明文 ``secrets`` 对象 → 直接返回，**不会崩**；能加密时顺手迁移成
       ``secrets_enc`` 并把明文从文件里删掉（迁移失败则维持原样，仍可读）；
    3. 都取不到 → 退回本进程内存里的副本（DPAPI 不可用时的兜底）。

    任何失败（缺文件、JSON 坏了、密文解不开、换了 Windows 用户……）都返回
    ``None``：读不到凭据只意味着「需要重新登录」，不该让调用方崩掉。
    """
    state_path = Path(path)
    state = _load_state_file(state_path)
    if state is not None:
        blob = state.get(_SECRETS_ENC_FIELD)
        if isinstance(blob, str) and blob:
            try:
                parsed = json.loads(win_crypto.unprotect(base64.b64decode(blob)).decode("utf-8"))
            except Exception:  # noqa: BLE001 —— 解不开就当「没有」，见 docstring
                parsed = None
            if isinstance(parsed, dict):
                return {
                    "username": str(parsed.get("username", "")),
                    "password": str(parsed.get("password", "")),
                }
        legacy = state.get(_LEGACY_SECRETS_FIELD)
        if isinstance(legacy, dict):
            secrets = {
                "username": str(legacy.get("username", "")),
                "password": str(legacy.get("password", "")),
            }
            _migrate_legacy_secrets(state_path, state, secrets)
            return secrets
    memory = _MEMORY_SECRETS.get(state_path.stem)
    return dict(memory) if memory else None


# --------------------------------------------------------------------------- #
# 第二层（实测）：真的 POST 一次，失败换个形态再 POST 一次，并把**实际结果落盘**。
#
# 为什么要落盘：`http_login` 失败时此前只把 `fallback=interactive` 回给对话，
# 生成期（读 analysis.json / registry.json）对「这个站点到底能不能靠构造请求登录」
# 一无所知，于是照旧发射一个假装能 401 自动重登录的 `login()` —— 而它必然失败。
# 落盘之后 `analyzer.login_post_verdict` 就能读到实测结论（实测优先于静态预判）。
# --------------------------------------------------------------------------- #
# 失败响应里出现这些词 → 服务端自己说「要人工过验证」，这是最强的一手证据。
_INTERACTIVE_TEXT_HINTS = (
    "captcha", "recaptcha", "hcaptcha", "geetest", "极验", "验证码", "图形码",
    "two-factor", "two factor", "2fa", "mfa", "otp", "二次验证", "两步验证",
    "短信验证", "手机验证", "verification code",
)
# 表单里按名字识别账号 / 口令字段（含 analyzer 认的那批同义词）。
_FORM_ACCOUNT_FIELDS = {"user", "username", "email", "login", "account"}
_FORM_PASSWORD_FIELDS = {"password", "passwd", "pwd", "secret"}


@dataclass
class _LoginAttempts:
    """一次实测的**事实**记录：用过哪些形态、各拿到什么 HTTP 状态码。

    刻意只留这几样：不记响应文本、不记账号口令 —— 它会被写进边车文件。
    """

    shapes: list[str] = field(default_factory=list)
    statuses: list[int] = field(default_factory=list)

    def note(self, shape: str, response: Any) -> None:
        self.shapes.append(shape)
        code = getattr(response, "status_code", None)
        if isinstance(code, int):
            self.statuses.append(code)


def _classify_login_failure(response: Any) -> str:
    """从失败响应里判一个**原因码**（进边车与对话，绝不带凭据或响应正文）。"""
    try:
        text = (response.text or "")[:4000]
    except Exception:      # noqa: BLE001 —— 响应对象千奇百怪，读不到就当没文本
        text = ""
    lowered = text.lower()
    if any(hint in lowered for hint in _INTERACTIVE_TEXT_HINTS):
        return "interactive_required"
    code = getattr(response, "status_code", 0)
    if code in (401, 403):
        return "rejected_credentials"
    if isinstance(code, int) and code >= 500:
        return f"server_error_{code}"
    # 保持与修复前同一句话：调用方/文档里引用过它。
    return "login response did not contain credentials"


def _fill_form_fields(fields: dict[str, str], username: str, password: str) -> dict[str, str]:
    for name in fields:
        lowered = name.lower()
        if lowered in _FORM_ACCOUNT_FIELDS:
            fields[name] = username
        elif lowered in _FORM_PASSWORD_FIELDS:
            fields[name] = password
    return fields


async def _post_form_from_page(client: Any, url: str, username: str, password: str) -> tuple[Any, bool]:
    """抓登录页 → 带上页面里的隐藏字段（CSRF / 防重放 token）→ POST 到 form action。

    返回 ``(响应, 是否真的找到了表单)``：没找到表单时原样返回页面响应，与修复前的
    行为一致（调用方随后按「响应里有凭据吗」判定成功与否）。
    """
    page = await client.get(url)
    if page.status_code >= 400:
        return page, False
    parser = _LoginFormParser()
    parser.feed(page.text)
    if not parser.fields:
        return page, False
    fields = _fill_form_fields(parser.fields, username, password)
    action = urljoin(str(page.url), parser.action or str(page.url))
    return await client.post(action, data=fields), True


def _evaluate_login_response(response: Any, client: Any) -> tuple[dict[str, Any], bool]:
    """解析响应体里的 token，并按**修复前同一套**规则判定成败（兼容既有调用方）。"""
    token_data: dict[str, Any] = {}
    try:
        parsed = response.json()
        if isinstance(parsed, dict):
            token_data = parsed
    except ValueError:
        pass
    cookies = client.cookies.jar
    has_token = any("token" in str(key).lower() for key in token_data)
    success = response.status_code in {200, 201, 204, 302} and (bool(cookies) or has_token)
    return token_data, success


def _cookie_snapshot(client: Any) -> set[tuple[str, str]]:
    """当前 Cookie 罐的 (名, 值) 快照 —— 用来判「这次 POST 到底有没有换来新凭据」。"""
    try:
        return {(cookie.name, cookie.value) for cookie in client.cookies.jar}
    except Exception:      # noqa: BLE001
        return set()


# Cookie 名里带这些词才算是「登录凭据」的证据（埋点 / 匿名会话不算）。
_CREDENTIAL_COOKIE_MARKS = ("token", "session", "sid", "auth", "jwt", "ticket")


def _has_login_credentials(client: Any, token_data: dict[str, Any],
                           cookies_before: set[tuple[str, str]]) -> bool:
    """这次 POST 到底有没有换来**登录凭据** —— 只看有没有、不看是什么。

    * 响应体里（**含嵌套**）出现像 token 的键（`data.token` 也算）；
    * 或 Cookie 罐里**新增**了名字像凭据的 Cookie（相对 POST 前的基线）。
      「相对基线」很关键：登录页自己就会下发 JSESSIONID，只看「有没有」必然误判。
    """
    if _contains_token_key(token_data):
        return True
    try:
        jar = list(client.cookies.jar)
    except Exception:      # noqa: BLE001
        return False
    for cookie in jar:
        name = str(getattr(cookie, "name", "") or "")
        if (getattr(cookie, "name", None), getattr(cookie, "value", None)) in cookies_before:
            continue
        if any(mark in name.lower() for mark in _CREDENTIAL_COOKIE_MARKS):
            return True
    return False


def _contains_token_key(data: Any, depth: int = 0) -> bool:
    """响应体里**任意层级**有没有像 token 的键（不取值，只看键名）。"""
    if depth > 4 or not isinstance(data, dict):
        return False
    for key, value in data.items():
        if "token" in str(key).lower():
            return True
        if _contains_token_key(value, depth + 1):
            return True
    return False


def record_login_mode(path_dir: Path, url: str, verdict: str, *, attempts: int,
                      reason: str, statuses: list[int]) -> Path | None:
    """把**实测**结论写成边车 ``<auth_states>/<site_key>.login_mode.json``。

    为什么是独立边车、而不是写进登录态文件：

    * 失败时压根没有登录态可写，而失败结论恰恰最需要留给生成期；
    * 一个「其实没登录成功」的 auth_state 文件会被后续 ``start_capture(auth_state_path=…)``
      当成有效登录态复用 —— 那是个假绿灯，比没有更糟。

    内容只有判定事实（verdict / 尝试次数 / 原因码 / HTTP 状态码 / 时间 / host），
    **不含**账号、口令、Cookie 或响应正文。写不进去只返回 None（读不到实测结果时
    分析会退回静态预判），绝不影响登录流程本身。
    """
    try:
        path_dir = Path(path_dir)
        path_dir.mkdir(parents=True, exist_ok=True)
        path = path_dir / f"{_site_key(url)}{LOGIN_MODE_SUFFIX}"
        path.write_text(json.dumps({
            "host": urlparse(url).netloc,
            "verdict": verdict,
            "attempts": int(attempts),
            "reason": reason,
            "statuses": [int(s) for s in statuses if isinstance(s, int)],
            "checked_at": _now(),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        _secure_file(path)
        return path
    except OSError:
        return None


async def http_login(
    url: str,
    username: str,
    password: str,
    auth_states_dir: Path,
    login_endpoint: str | None = None,
) -> dict[str, Any]:
    """Try a JSON endpoint first when known, then fall back to an HTML form.

    第二层（实测）：**真的 POST 一次**；失败就**换个形态再 POST 一次**（声明了 JSON
    登录接口 → 改走登录页里那张表单，反之亦然 —— 参数与承载方式一并修正），然后把这
    次实测的结论落盘（见 :func:`record_login_mode`），供生成期判定该站点属于
    「能构造请求登录」还是「必须交互式登录」。

    成功路径与修复前**逐字节同序**：声明了登录接口就 POST JSON，否则先 GET 登录页、
    找到表单再提交；第二次尝试只在第一次失败时发生。
    """
    # 构造客户端前清洗 NO_PROXY：httpx 解析方括号 IPv6（[::1]）会抛
    # InvalidURL: Invalid port ':1]'，客户端在构造阶段就崩——与是否走代理无关。
    # 详见 proxy_env 模块说明。
    sanitize_no_proxy()
    attempts = _LoginAttempts()
    async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
        endpoint = login_endpoint or url
        payload: dict[str, Any] = {"username": username, "password": password}
        cookies_before = _cookie_snapshot(client)
        token_data: dict[str, Any] = {}
        success = False
        # 真的**发出去过**的 POST：`(响应, 解析出的响应体)`。判定「实测能不能换来凭据」
        # 只看它们 —— 登录页的 GET 响应不算（它本来就会发一个会话 Cookie）。
        posted: list[tuple[Any, dict[str, Any]]] = []

        def _record_attempt(shape: str, resp: Any) -> None:
            nonlocal response, token_data, success
            attempts.note(shape, resp)
            if shape in ("json", "form"):
                response = resp
                token_data, success = _evaluate_login_response(resp, client)
                posted.append((resp, token_data))
            elif response is None:
                # 一次 POST 都还没发出去（登录页里根本没有表单）：沿用修复前对**页面**
                # 响应的判定，别把「登录页自己下发的会话 Cookie」当成登录成功的新证据。
                response = resp
                token_data, success = _evaluate_login_response(resp, client)

        response: Any = None
        if login_endpoint:
            _record_attempt("json", await client.post(endpoint, json=payload))
            if not success:
                # 修正重试：改用登录页里那张表单（带上页面里的隐藏字段）。
                page, found = await _post_form_from_page(client, url, username, password)
                _record_attempt("form" if found else "page", page)
        else:
            page, found = await _post_form_from_page(client, url, username, password)
            _record_attempt("form" if found else "page", page)
            if not success:
                # 修正重试：改发 JSON（不少站点同一个地址两种编码都收）。
                _record_attempt("json", await client.post(url, json=payload))
        # 「实测有凭据」必须比「工具报成功」严：修复前的成功判据只看 Cookie 罐非空，
        # 而**登录页自己**就会下发 JSESSIONID —— 只 GET 一下就报成功，等于把带验证码的
        # 站点记成「能构造请求登录」，生成物又会假装有 401 自动重登录。所以：
        # 只有真的发过 POST、且响应给出 token 或**新增的**凭据类 Cookie，才算实测通过。
        evidence = any(
            getattr(resp, "status_code", 0) in (200, 201, 204, 302)
            and _has_login_credentials(client, data, cookies_before)
            for resp, data in posted)
        # 实测拿到凭据 = 事实上的登录成功。工具的历史成功判据偏窄（只认**顶层** token 或
        # Cookie 罐非空），这里不推翻它，而是把实测证据**并**进去：响应把 token 放在
        # `data.token` 这类嵌套字段里时，旧判据说「失败」，会把 Agent 引向「改用浏览器
        # 登录」—— 而生成物其实能自动登录。结论与回报必须一致，不能各说各话。
        success = success or evidence
        if evidence:
            # 实测确认「构造请求能换来凭据」→ 这个站点能自动登录（静态说啥都以此为准）。
            verdict = "post_ok"
        elif success:
            # 工具按旧判据算「成功」（多半是登录页的会话 Cookie），但没有凭据证据：
            # 不下结论，交回静态预判（边车里记 no_evidence）。
            verdict = "no_evidence"
        else:
            verdict = "interactive"
        reason = "" if success else _classify_login_failure(response)
        site_key = _site_key(url)
        recorded = record_login_mode(
            auth_states_dir, url, verdict, attempts=len(attempts.shapes), reason=reason,
            statuses=attempts.statuses)
        if not success:
            # 结论落盘 + 一句说得通、可行动的下一步（面向完全不懂 HTTP 的人）。
            return {
                "success": False,
                "fallback": "interactive",
                "reason": reason,
                "attempts": len(attempts.shapes),
                "statuses": attempts.statuses,
                "login_mode_recorded": recorded is not None,
                "message": (
                    f"这个站点用构造请求登录没有成功（试了 {len(attempts.shapes)} 次：{reason}）。"
                    + ("已记下这个结论：本次生成的 MCP 会**自带交互式登录** —— "
                       "登录时会弹出一个真实浏览器窗口，验证码 / 短信 / 二次验证由你本人完成。"
                       if recorded is not None else
                       "本次结论**没能记到磁盘**，生成的 MCP 可能仍按「能自动登录」生成；"
                       "如需交互式登录的产物，请重新生成一次。")
                    + "现在请改用 open_browser_login(url) 让用户手动登录一次，"
                      "再用 confirm_login 保存登录态。"
                ),
            }
        cookies = client.cookies.jar
        state_path = auth_states_dir / f"{site_key}.json"
        state: dict[str, Any] = {
            "site_key": site_key,
            "created_at": _now(),
            # 注意：**不再**有明文的 "secrets" 字段。账号密码见下方
            # _store_secrets() 写入的 "secrets_enc"（DPAPI 密文，仅同一 Windows
            # 用户可解）；结构上的其余部分（cookies / storage_state 契约）不变。
            # 与 Playwright storage_state 对齐，保留 domain/path/secure。
            # 多域 SSO 站点下同名 Cookie（如 .example.com 与 crm.example.com 各有一条
            # SSOAuthSession）值不同，摊平成 {name: value} 会互相覆盖。
            "cookies": [
                {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": bool(cookie.secure),
                    "expires": cookie.expires,
                }
                for cookie in cookies
            ],
            # 仅为兼容旧的下游消费者保留；**新代码请用上面的 cookies**——
            # 它丢弃了域名维度，在多域站点上不准确。
            "cookies_raw": {cookie.name: cookie.value for cookie in cookies},
            "auth_candidates": [{"login_endpoint": f"POST {endpoint}"}],
            "token_response": token_data,
        }
        failure = _store_secrets(state, site_key, username, password)
        result: dict[str, Any] = {
            "success": True,
            "token_type": "cookie" if cookies else "json",
            "secrets_persisted": failure is None,
            "auth_state_path": str(state_path),
        }
        if failure is not None:
            # 不能对用户谎称「已保存」：凭据只在内存里，重启即失效。
            result["warning"] = "secrets_not_persisted"
            result["message"] = (
                "账号与密码**未能保存到磁盘**（DPAPI 加密不可用："
                f"{failure}）。凭据只在本次服务进程内存中保留，重启后需重新登录；"
                "Cookie 登录态已正常保存，抓包与复用不受影响。"
            )
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        _secure_file(state_path)
        return result


@dataclass
class LoginSession:
    session_id: str
    url: str
    timeout_seconds: int
    auth_states_dir: Path
    status: str = "waiting"
    auth_state_path: str | None = None
    auth_summary: dict[str, Any] = field(default_factory=dict)
    browser: Any = None
    context: Any = None
    task: asyncio.Task[Any] | None = None
    # Issue #20: 首次导航后落下的 Cookie 基线（name/domain/path → value）。
    # 登录证据必须相对它「新增或值变化」，否则登录页自设的 JSESSIONID /
    # PHPSESSID 会被当成已登录证据，浏览器随即被关。
    baseline_cookies: dict[tuple[str, str, str], Any] = field(default_factory=dict)
    # 仅供报告：是否观察到看似登录成功的凭据证据。
    # **不驱动状态流转**——完成一律由用户/Agent 显式确认（confirm_login 或确认对话框）。
    # 自动判定曾在用户还在输密码时就把会话判成 completed 并关掉浏览器，
    # Agent 据此往下跑（Issue: 登录阶段自动放行）。
    auth_evidence: bool = False
    # 确认对话框是否正在显示：既用于拒绝重复弹出，也用于在弹窗期间暂停会话超时，
    # 避免「用户点了『是』但会话早已超时」造成的死弹窗。
    dialog_open: bool = False


class LoginManager:
    def __init__(self, auth_states_dir: Path) -> None:
        self.auth_states_dir = auth_states_dir
        self.sessions: dict[str, LoginSession] = {}

    async def open(self, url: str, timeout_seconds: int = 300) -> dict[str, Any]:
        session_id = f"login_{secrets.token_urlsafe(8)}"
        record = LoginSession(session_id, url, timeout_seconds, self.auth_states_dir)
        self.sessions[session_id] = record
        record.task = asyncio.create_task(self._run(record))
        return {
            "login_session_id": session_id,
            "status": "waiting",
            "message": (
                "浏览器已打开。请让用户在窗口里完成登录（验证码 / 二次验证 / SSO 都由用户完成），"
                "**然后由用户确认是否已登录完成**：用户在对话里确认后，调用 "
                "confirm_login(login_session_id) 保存登录态。"
                "get_login_status 返回的 auth_evidence 只是旁证，**不会自动放行**——"
                "务必等用户确认，不要在用户尚未答复时自行往下走。"
                "若对话里问不方便，可用 request_login_confirm_dialog(login_session_id) "
                "弹出系统对话框让用户点选。"
            ),
        }

    async def _run(self, record: LoginSession) -> None:
        try:
            from playwright.async_api import async_playwright
            async with async_playwright() as playwright:
                record.browser = await playwright.chromium.launch(headless=False)
                # 同上：交互式登录页多为自签名证书，不放开校验则页面根本打不开。
                # 同上：登录页要能随窗口重排（响应式登录页在固定 viewport 下可能渲染成移动布局）。
                record.context = await record.browser.new_context(ignore_https_errors=True, no_viewport=True)
                # Issue #14: 不再注入页内控制条——认证完成完全依赖三层外置信号
                # （Cookie 证据 / 系统原生对话框 / confirm_login 工具），
                # 这三层本就不依赖页内控制条，去掉后同时消除了对目标页面的脚本注入。
                page = await record.context.new_page()
                await page.goto(record.url, wait_until="domcontentloaded", timeout=30000)
                # Issue #20: 登录页往往自己就设 JSESSIONID / PHPSESSID 这类会话
                # Cookie。先让页面沉降、把它们收进基线；此后
                # 证据要求「相对基线新增或值变化」，登录页的 Cookie 便不再误触发
                # （修复前会在 ~6 秒后误判 completed 并关掉浏览器）。
                await page.wait_for_timeout(2000)
                record.baseline_cookies = _cookie_baseline(await record.context.cookies())

                target_host = urlparse(record.url).hostname or ""
                loop = asyncio.get_running_loop()
                deadline = loop.time() + record.timeout_seconds

                # **只观察，不判定。** 证据只写进 auth_evidence 供上报告知；
                # 状态一律由显式确认翻转（confirm_login 工具，或用户点确认对话框）。
                # 以前这里在证据稳定 5 秒后自动置 completed 并关掉浏览器——
                # 而登录页自己就会设 session 类 Cookie，于是用户还在输密码，
                # Agent 就已经拿到 completed 往下跑了。
                while record.status == "waiting":
                    if record.dialog_open:
                        # 对话框显示期间暂停计时：否则用户还没点，会话先超时，
                        # 之后再点「是」就成了死弹窗。
                        deadline = loop.time() + record.timeout_seconds
                    elif loop.time() >= deadline:
                        break
                    try:
                        record.auth_evidence = await self._login_evidence(record, page, target_host)
                    except Exception:
                        pass
                    await asyncio.sleep(1)

                if record.status == "waiting":
                    record.status = "timeout_failed"
                if record.status == "completed":
                    storage_path = self.auth_states_dir / f"{_site_key(record.url)}.json"
                    # 残留②：`storage_state` 整体覆盖文件、只写 cookies/origins。先把它
                    # 里面 `http_login` 存下的 DPAPI 密文凭据捞出来，写完再合并回去——
                    # 否则浏览器登录一次就把加密凭据抹掉，用户下次还得重输。
                    preserved = _preserve_encrypted_secrets(storage_path)
                    await record.context.storage_state(path=str(storage_path))
                    _merge_encrypted_secrets(storage_path, preserved)
                    record.auth_state_path = str(storage_path)
                    _secure_file(storage_path)
                    record.auth_summary = {
                        "site_key": _site_key(record.url),
                        "storage_state": str(storage_path),
                        "status": "completed",
                        "auth_evidence": record.auth_evidence,
                    }
                if record.browser:
                    await record.browser.close()
        except Exception as exc:
            record.status = "cancelled"
            record.auth_summary = {"error": f"{type(exc).__name__}: {exc}"}

    async def _login_evidence(self, record: LoginSession, page: Any, target_host: str) -> bool:
        """观察到的凭据旁证：目标域上**相对登录前基线新增或值变化**的凭据类 Cookie。

        **这是旁证，不是判定。** 结果只写进 ``auth_evidence`` 供上报告知
        （Agent 可据此提醒用户「看起来已登录，请确认」），绝不自动置 completed。

        Issue #20: 只看「有没有名字像凭据的 Cookie」会误判——登录页自己就会设
        JSESSIONID / PHPSESSID / ASP.NET_SessionId 之类。
        必须要求它是登录后才出现、或值发生了变化，才算是登录的证据。
        """
        cookies = await record.context.cookies()
        baseline = record.baseline_cookies

        def is_new_or_changed(cookie: dict[str, Any]) -> bool:
            if not baseline:
                # 尚未拍到基线（快照前的窗口期）→ 退回旧行为，避免误伤正常流程
                return True
            return baseline.get(_cookie_key(cookie)) != cookie.get("value")

        has_token_cookie = any(
            any(marker in (cookie.get("name") or "").lower() for marker in ("token", "session", "sid", "auth"))
            and same_site(cookie.get("domain") or "", target_host)
            and is_new_or_changed(cookie)
            for cookie in cookies
        )
        on_target_site = target_host in (urlparse(page.url).hostname or "")
        return has_token_cookie and on_target_site

    _CONFIRM_PROMPT = "已完成网站登录？\n\n是 = 登录完成，保存登录态\n否 = 还没登好（浏览器保持打开）"

    def _ask_native(self) -> bool | None:
        """弹出阻塞式系统确认对话框（实现见 `dialog` 模块，与抓包环节共用）。

        返回 True/False；无法显示对话框时返回 None（无图形环境等）。
        """
        return dialog.ask_yes_no(self._CONFIRM_PROMPT)

    async def _ask_native_async(self) -> bool | None:
        """在线程上跑阻塞对话框，便于在协程里 await 用户的点选。"""
        return await dialog.run_blocking(self._ask_native)

    async def request_confirm_dialog(self, session_id: str) -> dict[str, Any]:
        """按需弹出系统确认对话框，并把用户的点选结果**原样返回**。

        旧实现把对话框在浏览器刚打开时就弹出来（用户还没登录，多半点「否」），
        只处理「是」，点「否」不改变任何状态、且对话框**再也不会出现**——
        所谓「确认框完全闲置无用」即由此而来。现在：

        * 只在调用方明确请求时弹出（不再在打开浏览器时抢焦点，也不干扰输密码）；
        * 「否」不再被丢弃：会话保持 ``waiting``，返回 ``confirmed=false``，
          对话继续进行，之后可以再次请求弹出（可重复）;
        * 已经不在等待的会话直接拒绝，不会弹出必然变成死物的对话框。
        """
        record = self.sessions.get(session_id)
        if record is None:
            return {"success": False, "error": "login_session_not_found", "login_session_id": session_id}
        if record.status != "waiting":
            return {"success": False, "error": "not_waiting", "status": record.status}
        if record.dialog_open:
            return {"success": False, "error": "dialog_already_open", "status": record.status}

        record.dialog_open = True
        try:
            answer = await self._ask_native_async()
        finally:
            record.dialog_open = False

        if answer is None:
            return {"success": False, "error": "dialog_unavailable", "status": record.status,
                    "message": "无法显示系统对话框，请在对话里直接向用户确认后调用 confirm_login。"}
        if not answer:
            # 「否」= 用户还没登好。会话继续等待，对话框可再次请求。
            return {"success": True, "confirmed": False, "login_session_id": session_id,
                    "status": record.status,
                    "message": "用户表示还没登录完成；浏览器保持打开，可稍后再次请求确认。"}
        record.status = "completed"
        return {"success": True, "confirmed": True, "login_session_id": session_id, "status": record.status}

    def confirm(self, session_id: str) -> dict[str, Any]:
        """主路径：Agent 在对话里问过用户、得到肯定答复后，代用户确认登录完成。
        由 ``confirm_login`` 工具调用。"""
        record = self.sessions.get(session_id)
        if record is None:
            return {"success": False, "error": "login_session_not_found", "login_session_id": session_id}
        if record.status != "waiting":
            return {"success": False, "error": "not_waiting", "status": record.status}
        record.status = "completed"
        result: dict[str, Any] = {"success": True, "login_session_id": session_id, "status": "completed"}
        if not record.auth_evidence:
            # 用户说登录好了，但浏览器里没观察到凭据类 Cookie——存下来的登录态
            # 很可能是未认证状态。不阻止（用户可能比启发式更清楚），但必须说出来。
            result["warning"] = "no_credential_evidence"
            result["message"] = (
                "未观察到凭据类 Cookie。若用户其实尚未登录成功，"
                "保存的登录态将是未认证状态，后续抓包会缺少登录接口。"
            )
        return result

    # Issue #14: 页内控制条已移除，其 login_complete 通道不再存在。
    # 认证完成只由**显式确认**决定：confirm()（confirm_login 工具，主路径）或
    # request_confirm_dialog()（系统对话框，可选兜底）。
    # _login_evidence() 仅提供 auth_evidence 旁证，不驱动状态流转。

    def status(self, session_id: str) -> dict[str, Any]:
        record = self.sessions.get(session_id)
        if record is None:
            return {"success": False, "error": "login_session_not_found", "login_session_id": session_id}
        return {
            "login_session_id": session_id,
            "status": record.status,
            "auth_state_path": record.auth_state_path,
            "auth_summary": record.auth_summary,
            # 旁证 + 对话框状态，供 Agent 决定「问用户」还是继续等。
            "auth_evidence": record.auth_evidence,
            "dialog_open": record.dialog_open,
        }