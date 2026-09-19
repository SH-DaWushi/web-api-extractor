"""HTTP and interactive authentication workflows."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

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
    completed: asyncio.Event = field(default_factory=asyncio.Event)
    # Issue #20: 首次导航后落下的 Cookie 基线（name/domain/path → value）。
    # 登录证据必须相对它「新增或值变化」，否则登录页自设的 JSESSIONID /
    # PHPSESSID 会被当成已登录证据，浏览器随即被关。
    baseline_cookies: dict[tuple[str, str, str], Any] = field(default_factory=dict)


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
                "浏览器已打开，请完成登录。登录完成的判定（三层，自动进行）："
                "① 检测到目标站点的 token/session Cookie 并稳定 5 秒 → 自动完成；"
                "② 弹出的系统对话框点「是」；"
                "③ 60 秒后状态变为 waiting_user_confirm，由 Agent 询问用户后调用 confirm_login 确认。"
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
                # Issue #20: 登录页往往自己就设 JSESSIONID / PHPSESSID /
                # PHPSESSID 这类会话 Cookie。先让页面沉降、把它们收进基线；此后
                # 证据要求「相对基线新增或值变化」，登录页的 Cookie 便不再误触发
                # （修复前会在 ~6 秒后误判 completed 并关掉浏览器）。
                await page.wait_for_timeout(2000)
                record.baseline_cookies = _cookie_baseline(await record.context.cookies())

                # Layer 2 (backup): native OS dialog, fully outside the target page —
                # immune to CSP / iframes / cross-origin popups that break in-page bars.
                self._spawn_native_confirm(record)

                target_host = urlparse(record.url).hostname or ""
                loop = asyncio.get_running_loop()
                started = loop.time()
                deadline = started + record.timeout_seconds
                evidence_since: float | None = None
                no_evidence_confirm_at = started + 60  # after this, agent may confirm out-of-band

                while record.status in {"waiting", "waiting_user_confirm"} and loop.time() < deadline:
                    try:
                        if await self._login_evidence(record, page, target_host):
                            if evidence_since is None:
                                evidence_since = loop.time()
                            # Layer 1 (primary): stable credential evidence for 5s → auto-complete.
                            elif loop.time() - evidence_since >= 5:
                                record.status = "completed"
                                record.completed.set()
                                break
                        else:
                            evidence_since = None
                            if record.status == "waiting" and loop.time() >= no_evidence_confirm_at:
                                # Layer 3 (fallback): out-of-band confirmation via confirm_login tool.
                                record.status = "waiting_user_confirm"
                    except Exception:
                        pass
                    await asyncio.sleep(1)

                if record.status in {"waiting", "waiting_user_confirm"}:
                    record.status = "timeout_failed"
                if record.status == "completed":
                    storage_path = self.auth_states_dir / f"{_site_key(record.url)}.json"
                    await record.context.storage_state(path=str(storage_path))
                    record.auth_state_path = str(storage_path)
                    _secure_file(storage_path)
                    record.auth_summary = {"site_key": _site_key(record.url), "storage_state": str(storage_path), "status": "completed"}
                if record.browser:
                    await record.browser.close()
        except Exception as exc:
            record.status = "cancelled"
            record.auth_summary = {"error": f"{type(exc).__name__}: {exc}"}

    async def _login_evidence(self, record: LoginSession, page: Any, target_host: str) -> bool:
        """Layer 1 evidence: a credential-like cookie on the *target* site's domain
        that appeared (or changed) **after** the pre-login baseline snapshot.

        Issue #20: 只看「有没有名字像凭据的 Cookie」会误判——登录页自己就会设
        JSESSIONID / PHPSESSID / PHPSESSID / ASP.NET_SessionId 之类。
        必须要求它是登录后才出现、或值发生了变化，才算已登录的证据。
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

    def _spawn_native_confirm(self, record: LoginSession) -> None:
        """Layer 2: OS-native dialog (Windows MessageBoxW, else tkinter) in a daemon
        thread so the user can confirm even when in-page signals are impossible."""
        import threading

        def _worker() -> None:
            try:
                if sys.platform == "win32":
                    import ctypes

                    # 4 = Yes/No, 0x30 = question icon, 0x40000 = topmost
                    answer = ctypes.windll.user32.MessageBoxW(
                        0,
                        "已完成网站登录？\n\n是 = 登录完成，保存登录态\n否 = 还没登好（浏览器保持打开）",
                        "WebAPIExtractor 登录确认",
                        4 | 0x20 | 0x40000,
                    )
                    if answer == 6 and record.status in {"waiting", "waiting_user_confirm"}:  # IDYES
                        record.status = "completed"
                        record.completed.set()
                else:
                    import tkinter as tk
                    from tkinter import messagebox

                    root = tk.Tk()
                    root.withdraw()
                    root.attributes("-topmost", True)
                    answer = messagebox.askyesno(
                        "WebAPIExtractor 登录确认",
                        "已完成网站登录？\n\n是 = 登录完成，保存登录态\n否 = 还没登好（浏览器保持打开）",
                    )
                    root.destroy()
                    if answer and record.status in {"waiting", "waiting_user_confirm"}:
                        record.status = "completed"
                        record.completed.set()
            except Exception:
                pass  # Layer 2 is best-effort; layers 1/3 remain available.

        threading.Thread(target=_worker, daemon=True, name="wae-login-confirm").start()

    def confirm(self, session_id: str) -> dict[str, Any]:
        """Layer 3 entry point: the agent confirms login on the user's behalf after
        asking them out-of-band (chat). Called by the confirm_login MCP tool."""
        record = self.sessions.get(session_id)
        if record is None:
            return {"success": False, "error": "login_session_not_found", "login_session_id": session_id}
        if record.status not in {"waiting", "waiting_user_confirm"}:
            return {"success": False, "error": "not_waiting", "status": record.status}
        record.status = "completed"
        record.completed.set()
        return {"success": True, "login_session_id": session_id, "status": "completed"}

    # Issue #14: _control() 已移除——页内控制条的 login_complete 通道不再存在。
    # 认证完成由三层外置信号决定：_login_evidence()（层1）、_spawn_native_confirm()
    # （层2）、confirm()（层3，由 confirm_login 工具触发）。

    def status(self, session_id: str) -> dict[str, Any]:
        record = self.sessions.get(session_id)
        if record is None:
            return {"success": False, "error": "login_session_not_found", "login_session_id": session_id}
        return {"login_session_id": session_id, "status": record.status, "auth_state_path": record.auth_state_path, "auth_summary": record.auth_summary}