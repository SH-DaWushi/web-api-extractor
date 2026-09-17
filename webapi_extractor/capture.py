"""Playwright/CDP network capture with immediate redaction and JSONL flushes."""

from __future__ import annotations

import asyncio
import base64
import json
import mimetypes
import time
from pathlib import Path
from typing import Any

from .control_bar import CONTROL_BAR_JS
from .redaction import is_auth_candidate, redact_headers, redact_payload
from .storage import SessionStore, utc_now


class CaptureSession:
    def __init__(self, session_id: str, url: str, store: SessionStore, response_limit: int, idle_timeout: int, auth_state_path: str | None = None) -> None:
        self.session_id = session_id
        self.url = url
        self.store = store
        self.response_limit = response_limit
        self.idle_timeout = idle_timeout
        self.auth_state_path = auth_state_path
        self.status = "authenticating" if not auth_state_path else "capturing"
        self.auth_ready = bool(auth_state_path)
        self.stop_reason: str | None = None
        self.pause_reason: str | None = None
        self.endpoint_count = 0
        self.started_at = time.monotonic()
        self.last_activity = self.started_at
        self.browser: Any = None
        self.context: Any = None
        self.pages: set[Any] = set()
        self.cdp_sessions: dict[Any, Any] = {}
        self.request_targets: dict[str, Any] = {}
        self.request_meta: dict[str, dict[str, Any]] = {}
        self.event_queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
        self.writer_task: asyncio.Task[Any] | None = None
        self.idle_task: asyncio.Task[Any] | None = None
        self.stop_lock = asyncio.Lock()
        self.script_bytes = 0

    @property
    def directory(self) -> Path:
        return self.store.session_path(self.session_id)

    @property
    def capture_path(self) -> Path:
        return self.directory / "capture.jsonl"

    async def start(self) -> None:
        from playwright.async_api import async_playwright

        if self.auth_state_path and Path(self.auth_state_path).exists():
            self.status = "capturing"
            self.auth_ready = True
        else:
            self.status = "authenticating"
            self.auth_ready = False
        self.directory.mkdir(parents=True, exist_ok=True)
        self.writer_task = asyncio.create_task(self._writer())
        self.idle_task = asyncio.create_task(self._idle_monitor())
        self.playwright = await async_playwright().start()
        state = self.auth_state_path if self.auth_state_path and Path(self.auth_state_path).exists() else None
        self.browser = await self.playwright.chromium.launch(headless=False)
        self.context = await self.browser.new_context(storage_state=state)
        await self.context.add_init_script(CONTROL_BAR_JS)
        self.context.on("page", lambda page: asyncio.create_task(self.attach_page(page)))
        page = await self.context.new_page()
        await self.attach_page(page)
        await page.goto(self.url, wait_until="domcontentloaded", timeout=30000)

    def mark_auth_ready(self) -> None:
        self.auth_ready = True
        if self.status == "authenticating":
            self.status = "capturing"
            self.pause_reason = None

    async def attach_page(self, page: Any) -> None:
        if page in self.pages:
            return
        self.pages.add(page)
        await page.expose_binding("__mcp_control", lambda source, action: self.control(action))
        cdp = await self.context.new_cdp_session(page)
        self.cdp_sessions[page] = cdp
        await cdp.send("Network.enable")
        await cdp.send("Network.setCacheDisabled", {"cacheDisabled": True})
        await cdp.send("Runtime.enable")
        await cdp.send("Target.setAutoAttach", {"autoAttach": True, "flatten": True, "waitForDebuggerOnStart": False})
        cdp.on("Network.requestWillBeSent", lambda event: asyncio.create_task(self.on_request(event, cdp)))
        cdp.on("Network.responseReceived", lambda event: asyncio.create_task(self.on_response(event, cdp)))
        cdp.on("Network.loadingFinished", lambda event: asyncio.create_task(self.on_finished(event, cdp)))
        cdp.on("Network.loadingFailed", lambda event: asyncio.create_task(self.emit({"type": "loading_failed", **event})))
        cdp.on("Network.webSocketCreated", lambda event: asyncio.create_task(self.emit({"type": "websocket", **event})))

    async def on_request(self, event: dict[str, Any], cdp: Any) -> None:
        if self.status != "capturing":
            return
        self.last_activity = time.monotonic()
        request = event.get("request", {})
        body = request.get("postData")
        redacted_body, token_paths = redact_payload(body)
        headers = redact_headers(request.get("headers", {}))
        request_id = event.get("requestId", "")
        self.request_targets[request_id] = cdp
        self.request_meta[request_id] = {"url": request.get("url", ""), "resourceType": event.get("type")}
        await self.emit({
            "type": "request", "ts": utc_now(), "requestId": request_id,
            "url": request.get("url"), "method": request.get("method"),
            "headers": headers, "postData": redacted_body,
            "resourceType": event.get("type"), "auth_candidate": is_auth_candidate(request.get("url", ""), body),
            "token_paths": token_paths,
        })
        if event.get("hasUserGesture") and request.get("url", "").startswith("http"):
            self.endpoint_count += 1

    async def on_response(self, event: dict[str, Any], cdp: Any) -> None:
        if self.status != "capturing":
            return
        response = event.get("response", {})
        await self.emit({
            "type": "response", "ts": utc_now(), "requestId": event.get("requestId"),
            "status": response.get("status"), "url": response.get("url"),
            "headers": redact_headers(response.get("headers", {})),
            "mimeType": response.get("mimeType"), "resourceType": event.get("type"),
        })

    async def on_finished(self, event: dict[str, Any], cdp: Any) -> None:
        if self.status != "capturing":
            return
        request_id = event.get("requestId")
        try:
            body_result = await cdp.send("Network.getResponseBody", {"requestId": request_id})
            body = body_result.get("body", "")
            encoded = body_result.get("base64Encoded", False)
            if encoded:
                decoded = base64.b64decode(body)
                size = len(decoded)
                payload = None if size > self.response_limit else body
            else:
                decoded = body.encode("utf-8")
                size = len(body.encode("utf-8"))
                payload = body[: self.response_limit] if size <= self.response_limit else body[: self.response_limit]
            meta = self.request_meta.get(request_id, {})
            if meta.get("resourceType") in {"Script", "Document"} and decoded:
                scripts_dir = self.directory / "scripts"
                scripts_dir.mkdir(parents=True, exist_ok=True)
                script_path = scripts_dir / f"{request_id.replace(':', '_')}.js"
                script_path.write_bytes(decoded[: 2 * 1024 * 1024])
            await self.emit({"type": "response_body", "requestId": request_id, "body": payload, "body_truncated": size > self.response_limit, "size": size, "base64Encoded": encoded})
        except Exception as exc:
            await self.emit({"type": "response_body", "requestId": request_id, "body_unavailable_reason": type(exc).__name__})

    async def emit(self, event: dict[str, Any]) -> None:
        if self.status == "capturing":
            await self.event_queue.put(event)

    async def _writer(self) -> None:
        batch: list[dict[str, Any]] = []
        while True:
            try:
                item = await asyncio.wait_for(self.event_queue.get(), timeout=1)
            except asyncio.TimeoutError:
                item = None
            if item is not None:
                batch.append(item)
            if batch and (len(batch) >= 50 or item is None):
                with self.capture_path.open("a", encoding="utf-8") as stream:
                    for event in batch:
                        stream.write(json.dumps(event, ensure_ascii=False) + "\n")
                    stream.flush()
                batch.clear()
            if item is None and self.status == "stopping" and self.event_queue.empty():
                break

    async def _idle_monitor(self) -> None:
        while self.status in {"capturing", "paused"}:
            await asyncio.sleep(1)
            if self.status == "capturing" and time.monotonic() - self.last_activity >= self.idle_timeout:
                await self.pause("idle_timeout")

    async def control(self, action: str) -> None:
        if action == "pause":
            await self.pause("control_bar")
        elif action == "resume":
            await self.resume()
        elif action == "stop":
            await self.stop("control_bar")

    async def pause(self, reason: str) -> None:
        if self.status != "capturing":
            return
        self.status = "paused"
        self.pause_reason = reason
        await self._broadcast_state()

    async def resume(self) -> None:
        if self.status != "paused":
            return
        self.status = "capturing"
        self.pause_reason = None
        self.last_activity = time.monotonic()
        await self._broadcast_state()

    async def _broadcast_state(self) -> None:
        for page in self.pages:
            try:
                await page.evaluate("state => window.__mcp_set_state && window.__mcp_set_state(state)", self.status)
            except Exception:
                pass

    async def stop(self, reason: str = "agent_requested") -> dict[str, Any]:
        async with self.stop_lock:
            if self.status in {"stopped", "failed"}:
                return self.metadata()
            self.status = "stopping"
            self.stop_reason = reason
            await self.event_queue.put(None)
            if self.writer_task:
                await self.writer_task
            if self.browser:
                await self.browser.close()
            if getattr(self, "playwright", None):
                await self.playwright.stop()
            self.status = "stopped"
            self.store.write_metadata(self.session_id, self.metadata())
            return self.metadata()

    def metadata(self) -> dict[str, Any]:
        return {"session_id": self.session_id, "url": self.url, "status": self.status, "stop_reason": self.stop_reason, "pause_reason": self.pause_reason, "endpoint_count": self.endpoint_count, "created_at": utc_now(), "auth_state_path": self.auth_state_path}