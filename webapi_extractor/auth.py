"""HTTP and interactive authentication workflows."""

from __future__ import annotations

import asyncio
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

from . import dialog
from .domain import same_site
from .proxy_env import sanitize_no_proxy
from .redaction import is_auth_candidate


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _site_key(url: str) -> str:
    return urlparse(url).netloc.replace(":", "_").replace(".", "_") or "site"


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


async def http_login(
    url: str,
    username: str,
    password: str,
    auth_states_dir: Path,
    login_endpoint: str | None = None,
) -> dict[str, Any]:
    """Try a JSON endpoint first when known, then fall back to an HTML form."""
    # 构造客户端前清洗 NO_PROXY：httpx 解析方括号 IPv6（[::1]）会抛
    # InvalidURL: Invalid port ':1]'，客户端在构造阶段就崩——与是否走代理无关。
    # 详见 proxy_env 模块说明。
    sanitize_no_proxy()
    async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
        endpoint = login_endpoint or url
        payload: dict[str, Any] = {"username": username, "password": password}
        response = await client.post(endpoint, json=payload) if login_endpoint else await client.get(url)
        if not login_endpoint and response.status_code < 400:
            parser = _LoginFormParser()
            parser.feed(response.text)
            if parser.fields:
                fields = parser.fields
                for field in fields:
                    lowered = field.lower()
                    if lowered in {"user", "username", "email", "login"}:
                        fields[field] = username
                    elif lowered in {"password", "passwd", "pwd"}:
                        fields[field] = password
                action = urljoin(str(response.url), parser.action or str(response.url))
                response = await client.post(action, data=fields)
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
        if not success:
            return {"success": False, "fallback": "interactive", "reason": "login response did not contain credentials"}
        state_path = auth_states_dir / f"{_site_key(url)}.json"
        state = {
            "site_key": _site_key(url),
            "created_at": _now(),
            "secrets": {"username": username, "password": password},
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
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        _secure_file(state_path)
        return {"success": True, "token_type": "cookie" if cookies else "json", "auth_state_path": str(state_path)}


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
                record.context = await record.browser.new_context()
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
                    await record.context.storage_state(path=str(storage_path))
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