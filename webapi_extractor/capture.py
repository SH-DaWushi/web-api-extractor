"""Playwright/CDP network capture with immediate redaction and JSONL flushes."""

from __future__ import annotations

import asyncio
import base64
import json
import mimetypes
import time
from pathlib import Path
from typing import Any

from .domain import same_site
from .redaction import is_auth_candidate, redact_headers, redact_payload
from .storage import SessionStore, utc_now


# Chromium M117+ 把 Cookie/Sec-* 等「浏览器合成头」从 requestWillBeSent 移到
# requestWillBeSentExtraInfo。两个事件共用 requestId，ExtraInfo 通常先到。
# 未配对的 ExtraInfo 缓存上限与存活时长（防止长会话内存膨胀）。
_MAX_PENDING_EXTRA = 2048
_PENDING_EXTRA_TTL = 300.0


def _merge_headers(base: dict[str, Any] | None, extra: dict[str, Any] | None) -> dict[str, Any]:
    """合并两批头，大小写不敏感；ExtraInfo（Cookie/Sec-* 的权威来源）优先。"""
    merged: dict[str, tuple[str, Any]] = {}
    for source in (base, extra):
        for name, value in (source or {}).items():
            merged[name.lower()] = (name, value)
    return {name: value for name, value in merged.values()}


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
        # 仅上报：目标域上是否出现名字像凭据的 Cookie。**不驱动状态流转**——
        # 何时开始记录只由显式确认决定（confirm_login_ready）。
        self.auth_evidence = False
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
        # requestId -> 已写入 capture.jsonl 的 request 事件；ExtraInfo 后到时原地补丁。
        self.emitted_requests: dict[str, dict[str, Any]] = {}
        # requestId -> (monotonic, ExtraInfo headers)；ExtraInfo 先到时暂存待配对。
        self.pending_extra: dict[str, tuple[float, dict[str, Any]]] = {}
        # ExtraInfo 已到、requestWillBeSent 未到：合并逻辑交给 on_request 处理，
        # 这里只需在 on_request 取用后清理，避免长会话内存泄漏。
        self.event_queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
        self.writer_task: asyncio.Task[Any] | None = None
        self.idle_task: asyncio.Task[Any] | None = None
        self.login_task: asyncio.Task[Any] | None = None
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
        if not self.auth_ready:
            self.login_task = asyncio.create_task(self._login_monitor())
        self.playwright = await async_playwright().start()
        state = self.auth_state_path if self.auth_state_path and Path(self.auth_state_path).exists() else None
        self.browser = await self.playwright.chromium.launch(headless=False)
        # Issue #14: 不再向目标页面注入任何脚本（原页内控制条已移除）。
        # 减少侵入、避免被目标站检测，也让 CSP/iframe 场景不再有失效面。
        self.context = await self.browser.new_context(storage_state=state)
        # Issue #13: 用户直接关闭浏览器时自动收尾。
        # 此前无此监听——会话会卡在 capturing、元数据不落盘、list_sessions 看不到它。
        self.browser.on("disconnected", lambda *_: asyncio.create_task(self._on_browser_closed()))
        self.context.on("page", lambda page: asyncio.create_task(self.attach_page(page)))
        page = await self.context.new_page()
        await self.attach_page(page)
        await page.goto(self.url, wait_until="domcontentloaded", timeout=30000)

    def mark_auth_ready(self) -> None:
        self.auth_ready = True
        if self.status == "authenticating":
            self.status = "capturing"
            self.pause_reason = None

    async def _enter_capturing(self) -> None:
        """登录完成：开始记录。"""
        self.mark_auth_ready()
        self.last_activity = time.monotonic()

    async def _on_browser_closed(self) -> None:
        """Issue #13: 用户关闭浏览器 → 自动收尾，保留已抓数据。

        此前无此处理：会话卡在 capturing、元数据不落盘、list_sessions 看不到它，
        用户会以为整轮采集白干（实际 capture.jsonl 是逐条落盘、数据完整的）。
        """
        if self.status in {"stopped", "failed", "stopping"}:
            return
        prev = self.status
        try:
            # 复用 stop() 的收尾流程；stop() 内部对 browser.close() 是幂等的。
            await self.stop("browser_closed")
        except Exception as exc:  # 收尾失败也要保证状态与元数据可用
            self.status = "stopped"
            self.stop_reason = "browser_closed"
            self.pause_reason = f"auto_stop_error:{type(exc).__name__}"
            try:
                self.store.write_metadata(self.session_id, self.metadata())
            except OSError:
                pass
        # 记录一条可读提示，随 list_sessions 一并返回
        try:
            meta = self.store.read_metadata(self.session_id) or {}
            size = self.capture_path.stat().st_size if self.capture_path.exists() else 0
            meta["captured_bytes"] = size
            meta["recovered"] = size > 0
            meta["recovered_hint"] = (
                f"检测到浏览器已关闭（原状态 {prev}），已自动收尾。"
                f"已落盘 {size / 1024:.1f} KB 数据，可直接对该会话调用 analyze_traffic。"
            )
            meta.setdefault("status_history", []).append(
                {"status": "stopped", "ts": utc_now(), "reason": "browser_closed"}
            )
            self.store.write_metadata(self.session_id, meta)
        except OSError:
            pass

    async def _login_monitor(self) -> None:
        """只观察登录旁证，**从不自动开始记录**。

        旧实现沿用「目标域上出现名字像凭据的 Cookie，稳定 5 秒」就自动
        ``_enter_capturing()``。但登录页**自己就会设** JSESSIONID /
        JSESSIONID / PHPSESSID，于是 ``start_capture`` 之后约 6 秒——
        用户人还在登录页——会话就翻成 ``capturing``；Agent 轮询到 capturing,
        自然以为可以往下走。（这段注释过去还声称「与 auth.py 同一证据标准」，
        其实从未同步 Issue #20 的 Cookie 基线比对，两份实现早已分叉。）

        现在这里只把观察结果写进 ``auth_evidence``，由 ``get_capture_status``
        上报给 Agent 作参考；真正开始记录必须显式确认：
        ``confirm_login_ready(session_id)``（Agent 问过用户之后再调）。
        """
        from urllib.parse import urlparse as _urlparse

        target_host = _urlparse(self.url).hostname or ""
        while self.status == "authenticating":
            await asyncio.sleep(1)
            if not getattr(self, "context", None):
                continue
            try:
                cookies = await self.context.cookies()
                self.auth_evidence = any(
                    any(marker in (c.get("name") or "").lower() for marker in ("token", "session", "sid", "auth"))
                    and same_site(c.get("domain") or "", target_host)
                    for c in cookies
                )
            except Exception:
                pass

    async def attach_page(self, page: Any) -> None:
        if page in self.pages:
            return
        self.pages.add(page)
        # Issue #14: 不再暴露 __mcp_control 绑定（页内控制条已移除）
        cdp = await self.context.new_cdp_session(page)
        self.cdp_sessions[page] = cdp
        await cdp.send("Network.enable")
        await cdp.send("Network.setCacheDisabled", {"cacheDisabled": True})
        await cdp.send("Runtime.enable")
        await cdp.send("Target.setAutoAttach", {"autoAttach": True, "flatten": True, "waitForDebuggerOnStart": False})
        cdp.on("Network.requestWillBeSent", lambda event: asyncio.create_task(self.on_request(event, cdp)))
        # Issue #1: M117+ 的 Cookie/Sec-* 合成头只在 ExtraInfo 事件里，必须一并订阅。
        cdp.on("Network.requestWillBeSentExtraInfo", lambda event: asyncio.create_task(self.on_request_extra_info(event, cdp)))
        cdp.on("Network.responseReceived", lambda event: asyncio.create_task(self.on_response(event, cdp)))
        cdp.on("Network.loadingFinished", lambda event: asyncio.create_task(self.on_finished(event, cdp)))
        cdp.on("Network.loadingFailed", lambda event: asyncio.create_task(self.emit({"type": "loading_failed", **event})))
        cdp.on("Network.webSocketCreated", lambda event: asyncio.create_task(self.emit({"type": "websocket", **event})))

    @staticmethod
    def _redacted_headers(headers: dict[str, Any] | None) -> dict[str, str]:
        """合并后的头必须统一走 redact_headers——Cookie 脱敏成 ``name=***``，
        analyzer 正是靠它提取 cookie_names 判定站点鉴权。"""
        return redact_headers(headers or {})

    async def on_request(self, event: dict[str, Any], cdp: Any) -> None:
        if self.status != "capturing":
            return
        self.last_activity = time.monotonic()
        request = event.get("request", {})
        body = request.get("postData")
        redacted_body, token_paths, shape_meta = redact_payload(body)
        request_id = event.get("requestId", "")
        # Issue #1: 合并 requestWillBeSent 与（通常先到的）ExtraInfo 里的头。
        extra = self._take_pending_extra(request_id)
        extra_headers = (extra or {}).get("headers", {}) if isinstance(extra, dict) else {}
        record = {
            "type": "request", "ts": utc_now(), "requestId": request_id,
            "url": request.get("url"), "method": request.get("method"),
            "headers": self._redacted_headers(_merge_headers(request.get("headers", {}), extra_headers)),
            "postData": redacted_body,
            "resourceType": event.get("type"), "auth_candidate": is_auth_candidate(request.get("url", ""), body),
            "token_paths": token_paths,
            "redaction_meta": shape_meta,
        }
        # ExtraInfo 后到时会原地补丁这条记录，writer 需要拿到同一对象引用。
        self.request_targets[request_id] = cdp
        self.request_meta[request_id] = {"url": request.get("url", ""), "resourceType": event.get("type")}
        self.emitted_requests[request_id] = record
        await self.emit(record)
        if event.get("hasUserGesture") and request.get("url", "").startswith("http"):
            self.endpoint_count += 1

    def _take_pending_extra(self, request_id: str) -> dict[str, Any] | None:
        """取走并清理暂存的 ExtraInfo（附带过期清理，防止无配对的请求泄漏）。"""
        self._prune_pending_extra()
        entry = self.pending_extra.pop(request_id, None)
        return entry[1] if entry else None

    def _prune_pending_extra(self) -> None:
        now = time.monotonic()
        for key in [k for k, (ts, _) in self.pending_extra.items() if now - ts > _PENDING_EXTRA_TTL]:
            del self.pending_extra[key]
        # 极端情况下（ExtraInfo 永远等不到 requestWillBeSent）按 FIFO 丢弃最旧的。
        while len(self.pending_extra) > _MAX_PENDING_EXTRA:
            del self.pending_extra[next(iter(self.pending_extra))]

    async def on_request_extra_info(self, event: dict[str, Any], cdp: Any) -> None:
        """Chromium M117+ 的 Cookie/Sec-* 等浏览器合成头只在此事件中出现。

        时序：ExtraInfo 通常早于 requestWillBeSent 到达，此时暂存待配对；
        若 requestWillBeSent 已经发出记录（ExtraInfo 后到的少数情况），
        直接对已入队/已落盘的 request 记录做**原地补丁**并补发一条
        ``headers_patch`` 事件——writer 按引用读取，故两种时序都能覆盖。
        """
        if self.status != "capturing":
            return
        request_id = event.get("requestId", "")
        headers = event.get("headers", {}) or {}
        if not request_id:
            return
        record = self.emitted_requests.get(request_id)
        if record is None:
            self.pending_extra[request_id] = (time.monotonic(), event)
            self._prune_pending_extra()
            return
        merged = self._redacted_headers(_merge_headers(record.get("headers"), headers))
        if merged == record.get("headers"):
            return  # 无新增（如纯重定向重发），不必产生噪音事件
        record["headers"] = merged
        await self.emit({"type": "headers_patch", "ts": utc_now(), "requestId": request_id,
                         "headers": merged, "reason": "requestWillBeSentExtraInfo_late"})

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
            else:
                decoded = body.encode("utf-8")
                size = len(body.encode("utf-8"))
            meta = self.request_meta.get(request_id, {})
            if meta.get("resourceType") in {"Script", "Document"} and decoded:
                scripts_dir = self.directory / "scripts"
                scripts_dir.mkdir(parents=True, exist_ok=True)
                script_path = scripts_dir / f"{request_id.replace(':', '_')}.js"
                script_path.write_bytes(decoded[: 2 * 1024 * 1024])
            # Issue #2: 超限时**完全不写入 body**，只保留元数据（size / 截断标记）。
            # 修复前是「截断后照写」，每轮仍向 capture.jsonl 灌入 response_limit 字节。
            if size > self.response_limit:
                await self.emit({"type": "response_body", "requestId": request_id, "body": None,
                                 "body_truncated": True, "body_dropped": True,
                                 "size": size, "base64Encoded": encoded})
            else:
                await self.emit({"type": "response_body", "requestId": request_id, "body": body,
                                 "body_truncated": False, "body_dropped": False,
                                 "size": size, "base64Encoded": encoded})
        except Exception as exc:
            await self.emit({"type": "response_body", "requestId": request_id, "body_unavailable_reason": type(exc).__name__})
        finally:
            # 请求结束：释放 Issue #1 的配对缓存，避免长会话内存泄漏。
            self.emitted_requests.pop(request_id, None)
            self.pending_extra.pop(request_id, None)

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

    # Issue #14: 页内控制条已移除，control() / _broadcast_state() 一并删除。
    # 认证完成只由**显式确认**决定：confirm_login_ready()（Agent 问过用户后调用）。
    # _login_monitor() 只把登录旁证写进 auth_evidence 供上报，不驱动状态流转。
    # 采集结束由「用户关闭浏览器」自动触发（见 _on_browser_closed）。

    async def pause(self, reason: str) -> None:
        if self.status != "capturing":
            return
        self.status = "paused"
        self.pause_reason = reason

    async def resume(self) -> None:
        if self.status != "paused":
            return
        self.status = "capturing"
        self.pause_reason = None
        self.last_activity = time.monotonic()

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
        return {"session_id": self.session_id, "url": self.url, "status": self.status, "stop_reason": self.stop_reason, "pause_reason": self.pause_reason, "endpoint_count": self.endpoint_count, "created_at": utc_now(), "auth_state_path": self.auth_state_path, "auth_evidence": self.auth_evidence}