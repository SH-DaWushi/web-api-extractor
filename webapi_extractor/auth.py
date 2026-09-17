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

from .login_detector import detect_login_success
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
            "message": "浏览器已打开，请在页面中完成登录，登录成功后会自动关闭；无需点击任何控制条",
        }

    async def _run(self, record: LoginSession) -> None:
        try:
            from playwright.async_api import async_playwright
            async with async_playwright() as playwright:
                record.browser = await playwright.chromium.launch(headless=False)
                record.context = await record.browser.new_context()
                page = await record.context.new_page()
                await page.goto(record.url, wait_until="domcontentloaded", timeout=30000)

                deadline = asyncio.get_running_loop().time() + record.timeout_seconds
                while record.status == "waiting" and asyncio.get_running_loop().time() < deadline:
                    try:
                        cookies = await record.context.cookies()
                        session_storage = await page.evaluate("() => { const raw = {}; for (let i = 0; i < window.sessionStorage.length; i++) { const key = window.sessionStorage.key(i); raw[key] = window.sessionStorage.getItem(key); } return raw; }")
                        url_history = [page.url]
                        if hasattr(page, "context"):
                            url_history.extend([page.url])
                        result = detect_login_success(
                            request_urls=url_history,
                            observed_headers={
                                "Authorization": "Bearer auto-detected",
                                "Cookie": "" if not cookies else "; ".join(f"{cookie['name']}={cookie['value']}" for cookie in cookies),
                            },
                            storage_state={"cookies": cookies},
                            session_storage=session_storage,
                        )
                        if result["auth_ready"]:
                            record.status = "completed"
                            record.completed.set()
                            break
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
                    record.auth_summary = {"site_key": _site_key(record.url), "storage_state": str(storage_path), "status": "completed"}
                if record.browser:
                    await record.browser.close()
        except Exception as exc:
            record.status = "cancelled"
            record.auth_summary = {"error": f"{type(exc).__name__}: {exc}"}

    def _control(self, record: LoginSession, action: str) -> None:
        if action == "login_complete":
            record.status = "completed"
            record.completed.set()

    def status(self, session_id: str) -> dict[str, Any]:
        record = self.sessions.get(session_id)
        if record is None:
            return {"success": False, "error": "login_session_not_found", "login_session_id": session_id}
        return {"login_session_id": session_id, "status": record.status, "auth_state_path": record.auth_state_path, "auth_summary": record.auth_summary}