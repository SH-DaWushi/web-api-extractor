"""Playwright/CDP network capture with immediate redaction and JSONL flushes."""

from __future__ import annotations

import asyncio
import base64
import json
import mimetypes
import time
from pathlib import Path
from typing import Any

from . import dialog
from .config import dropped_response_bodies_hint
from .domain import same_site
from .proxy_env import (
    DEFAULT_PROXY_MODE,
    auto_fallback_notice,
    both_modes_failed_detail,
    browser_proxy_args,
    fallback_proxy_mode,
    proxy_failure_hint,
    proxy_failure_kind,
)
from .redaction import is_auth_candidate, redact_headers, redact_payload
from .storage import SessionStore, utc_now


# Chromium M117+ 把 Cookie/Sec-* 等「浏览器合成头」从 requestWillBeSent 移到
# requestWillBeSentExtraInfo。两个事件共用 requestId，ExtraInfo 通常先到。
# 未配对的 ExtraInfo 缓存上限与存活时长（防止长会话内存膨胀）。
_MAX_PENDING_EXTRA = 2048
_PENDING_EXTRA_TTL = 300.0

# Fix 2: emitted_requests（requestId -> 已落盘的 request 记录）此前**只在 on_finished
# 的 finally 里清理**。被中断 / 永不结束的请求（用户取消、中途导航、页面关闭）不会
# 走到 on_finished，那条记录（头 + 已脱敏的体）就一直留到会话结束——这是本文件最后
# 一份无界 dict。这里**复用 pending_extra 的同一套机制**（TTL + 硬容量 + 在同一批
# 路径上 prune），不另造一套。
#
# TTL 必须**明显长于正常请求寿命**：记录要活到 on_finished 与可能晚到的 ExtraInfo
# 用得上为止。实测正常 XHR 从 requestWillBeSent 到 loadingFinished 通常在 30 秒内，
# 慢上传/大下载也就几分钟；取 600 秒（10 分钟）比最长真实请求还长一个数量级，
# 而两小时 5 万请求的会话里，被中断的记录最多停留 10 分钟即被回收。
_MAX_EMITTED_REQUESTS = 4096
_EMITTED_REQUEST_TTL = 600.0

# S21：跨进程 iframe（OOPIF）的网络事件**不会**出现在主页面会话上，必须为它单独挂
# 一个 CDP 会话（见 ``CaptureSession.attach_frame_if_needed`` 的 docstring）。
# frameattached 时 iframe 往往还在父进程里（挂不上），提交导航后才变成 OOPIF；而它的
# 第一批子请求几乎与提交同时发生——所以只做**有界**重试，尽量赶在那批请求之前挂上。
# 真机实测（Chromium）：frameattached/framenavigated 约在 +31ms，`Target.attachedToTarget`
# 在 +62ms，所以能挂上会话的最早时机就在这个量级；间隔取 20ms 让挂载尽快发生。
_OOPIF_ATTACH_ATTEMPTS = 25
_OOPIF_ATTACH_INTERVAL = 0.02

# ``Network.webSocketCreated`` 给出的 url 要留到帧事件用（帧事件自己不带 url）。
# 与 pending_extra 同一套路子：硬容量 + FIFO，长会话不会无界增长。
_MAX_WS_URLS = 512


def _frame_key(frame: Any) -> str:
    """frame 的稳定标识：跨导航不变、同 target 的两个 frame 也互不相同。

    取 Playwright 内部的 frame guid（``frame@<frameId>``，真机验证过它在同一个
    frame 的多次导航之间保持稳定）。取不到时返回空串，调用方据此跳过——**不能**
    退回 ``id(frame)``：id 会在对象回收后被复用，那会导致「以为已挂过」而静默漏抓。
    """
    impl = getattr(frame, "_impl_obj", None)
    guid = getattr(impl, "_guid", None)
    return str(guid) if guid else ""


def _merge_headers(base: dict[str, Any] | None, extra: dict[str, Any] | None) -> dict[str, Any]:
    """合并两批头，大小写不敏感；ExtraInfo（Cookie/Sec-* 的权威来源）优先。"""
    merged: dict[str, tuple[str, Any]] = {}
    for source in (base, extra):
        for name, value in (source or {}).items():
            merged[name.lower()] = (name, value)
    return {name: value for name, value in merged.values()}


class BrowserNavigationError(RuntimeError):
    """首个页面导航失败。``proxy_hint`` 非空时说明「更像代理问题」及其可行动建议。

    单独一个类型，是为了让**调用侧**（``server.py`` 的 start_capture）不必靠字符串
    匹配就能拿到代理提示，同时把原始异常链原样保留（``from exc``）。

    ``failure_kind`` 是 ``proxy_failure_kind()`` 的结论（``proxy`` / ``possible`` /
    ``None``），**显式带着**而不是让调用方再从 message 里猜：message 里同时含原始错误
    文本与我们自己拼的诊断文案，从拼接结果反推分类容易出岔子。
    """

    def __init__(self, message: str, *, proxy_hint: str | None = None,
                 failure_kind: str | None = None) -> None:
        super().__init__(message)
        self.proxy_hint = proxy_hint
        self.failure_kind = failure_kind


class CaptureSession:
    _CONFIRM_PROMPT = (
        "已在浏览器里完成登录？\n\n"
        "是 = 开始记录抓包\n"
        "否 = 还没登好（浏览器保持打开）"
    )

    def __init__(self, session_id: str, url: str, store: SessionStore, response_limit: int,
                 idle_timeout: int, auth_state_path: str | None = None,
                 proxy_mode: str = DEFAULT_PROXY_MODE,
                 response_limit_explicit: bool = False) -> None:
        self.session_id = session_id
        self.url = url
        self.store = store
        self.response_limit = response_limit
        # 这个上限是**调用方显式指定**的（``start_capture(response_limit_bytes=…)``）还是
        # 沿用 Settings / 环境变量的默认值。只有显式指定时才把它写进会话元数据 —— 让
        # get_capture_status / analyze_traffic 的提示语说「当前上限」时用的是**这次抓包
        # 真正生效**的那个值，而不是全局默认值；默认路径的元数据形状则一字不变。
        self.response_limit_explicit = response_limit_explicit
        self.idle_timeout = idle_timeout
        self.auth_state_path = auth_state_path
        # 抓包浏览器的代理模式：**默认 auto**——从直连开始（不加这条，Chromium 会静默
        # 跟随系统代理，非回环主机的请求被代理吃掉后只表现为难归因的
        # net::ERR_EMPTY_RESPONSE），首个页面若以代理类错误失败，就自动改用系统代理
        # 重试一次（见 start()）。direct / system 是严格的手动取值，失败不回退。
        self.proxy_mode = proxy_mode
        # 自动回退**成功**后才有值：{"from": ..., "to": ..., "message": ...}。
        # 调用侧（server.py）据此在响应里明确告知「已自动改用系统代理重试」。
        self.proxy_fallback: dict[str, Any] | None = None
        # 正在换浏览器（自动回退）。期间：① 旧浏览器被我们关掉**不算**「用户关了浏览器」；
        # ② 旧浏览器在途的事件不得再写进 capture.jsonl（见 _discard_browser / emit）。
        self._switching_proxy = False
        self.status = "authenticating" if not auth_state_path else "capturing"
        self.auth_ready = bool(auth_state_path)
        # 仅上报：目标域上是否出现名字像凭据的 Cookie。**不驱动状态流转**——
        # 何时开始记录只由显式确认决定（confirm_login_ready）。
        self.auth_evidence = False
        # 确认对话框是否正在显示：用于拒绝重复弹出。
        self.dialog_open = False
        self.stop_reason: str | None = None
        self.pause_reason: str | None = None
        self.endpoint_count = 0
        # S20：响应体因超过体积上限被**整条丢弃**的次数。只计数（不含内容），
        # 供会话元数据如实上报「这次抓包丢过响应体，所以某些接口没有响应结构」。
        self.dropped_response_bodies = 0
        self.started_at = time.monotonic()
        self.last_activity = self.started_at
        self.browser: Any = None
        self.context: Any = None
        self.pages: set[Any] = set()
        self.cdp_sessions: dict[Any, Any] = {}
        # S21：CDP 会话元数据（key 是会话对象）。tag 是「会话维度命名空间」：
        # **主页面会话的 tag 是空串** —— 于是它的事件里 requestId 与修复前逐字节一致，
        # 既有的配对逻辑、headers_patch、重定向 hop 全都不受影响；子会话才有前缀。
        # 这里强引用会话对象是**故意的**：子会话必须活着，它的事件订阅才会继续回调
        # （弱引用会被 GC 回收 → 静默不再抓包）。
        self.cdp_meta: dict[Any, dict[str, Any]] = {}
        # 已经单独挂过会话的 OOPIF frame（guid）。同一次导航会触发多次 attach 尝试，
        # 重复挂会让同一批事件被抓两遍（串数据）。
        self.attached_frames: set[str] = set()
        # 正在挂（还没挂完）的 frame。frameattached 与 framenavigated 会**并发**走到
        # 挂载流程里，中间有 await——不先抢占登记就会给同一个 frame 挂出两个会话，
        # 同一批请求被记两遍（真机实测踩到过：sub1/sub2 同 target、同 requestId）。
        self.attaching_frames: set[str] = set()
        # websocket requestId（会话维度键）-> (monotonic, url)，供帧事件补全来源 url。
        self.ws_urls: dict[str, tuple[float, str]] = {}
        self._session_seq = 0
        # requestId -> 该请求响应体的诊断信息（url / resourceType），on_finished 用后即清。
        # 注：此前还有一个 request_targets（requestId -> cdp 会话），只写不读，
        # 会把每个 CDP 会话对象长期钉在内存里 —— 长会话下是实打实的泄漏，已删除。
        self.request_meta: dict[str, dict[str, Any]] = {}
        # 写盘失败原因；一旦有值，说明本会话落盘的数据不完整（见 _writer）。
        self.write_error: str | None = None
        # requestId -> (monotonic, 已写入 capture.jsonl 的 request 事件)；ExtraInfo
        # 后到时原地补丁。带时间戳是为了能按 TTL 回收**永不结束**的请求（Fix 2）。
        self.emitted_requests: dict[str, tuple[float, dict[str, Any]]] = {}
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
        # S22：writer 已经**从队列取出、但还没落盘**的那批事件。原先是 _writer 的
        # 局部变量，外部无从得知，于是「暂停时把已抓到的数据落盘」这件事根本做不到。
        # 提到实例上之后，_flush_now() 与 writer 共用同一个缓冲，既不会漏也不会重复。
        self._batch: list[dict[str, Any]] = []
        self.flush_lock = asyncio.Lock()
        # S22：已经以「未配对」形式落盘过的 ExtraInfo requestId，避免每次暂停都重写同一条。
        self._flushed_extra: set[str] = set()
        # 本次暂停的时间戳与元数据落盘失败原因（只在异常时有值）。
        self.paused_at: str | None = None
        self.metadata_error: str | None = None

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
        try:
            await self._open_browser_and_first_page(self.proxy_mode, state)
        except BrowserNavigationError as exc:
            # 自动回退（R3）：**默认从直连开始**，首个页面若以代理类形态失败，就换系统
            # 代理重试**一次**。触发条件是「错误码像代理问题」——`proxy`（几乎可断定）
            # 与 `possible`（可能，如 ERR_EMPTY_RESPONSE / ERR_CONNECTION_TIMED_OUT）都算；
            # 认不出的失败（内核缺失等）**不**回退，那只会白等一个 goto 的超时。
            retry_mode = fallback_proxy_mode(self.proxy_mode)
            if retry_mode is None or exc.failure_kind is None:
                raise
            await self._retry_with_mode(retry_mode, state, first_error=exc)

    async def _open_browser_and_first_page(self, mode: str, state: Any) -> None:
        """按 ``mode`` 起浏览器、建 context、挂 CDP、打开首个页面。

        ``mode`` 是**本次尝试**用的模式，不一定等于 ``self.proxy_mode``：自动回退期间
        它就是回退目标，只有成功之后才写回 ``self.proxy_mode``（于是诊断里报的
        「当前模式」始终是真正生效的那个）。
        """
        # 代理**必须显式决定**：不带任何参数时 Chromium 静默跟随系统代理，非回环主机的
        # 请求被代理吃掉后只回报 net::ERR_EMPTY_RESPONSE（极难归因）。auto / direct 都用
        # --no-proxy-server 从直连开始，差别只在失败后是否回退（见 start()）。
        self.browser = await self.playwright.chromium.launch(
            headless=False, args=browser_proxy_args(mode))
        # Issue #14: 不再向目标页面注入任何脚本（原页内控制条已移除）。
        # 减少侵入、避免被目标站检测，也让 CSP/iframe 场景不再有失效面。
        # 同上：抓包目标常是自签名证书的内网设备，不放开校验则第一个 goto 就失败。
        # no_viewport=True：Playwright 默认给固定 1280x720 的 viewport，用户拖窗口时
        # viewport 不跟随，页面不重排（响应式站点还会渲染成另一种布局，影响抓到的内容）。
        # 设为 True 后 viewport 跟随真实窗口，和普通浏览器一致。
        self.context = await self.browser.new_context(storage_state=state, ignore_https_errors=True,
                                              no_viewport=True)
        # Issue #13: 用户直接关闭浏览器时自动收尾。
        # 此前无此监听——会话会卡在 capturing、元数据不落盘、list_sessions 看不到它。
        # 回调**绑定这一台**浏览器：自动回退会关掉上一台，那次关闭不是「用户关了浏览器」。
        browser = self.browser
        browser.on("disconnected", lambda *_: asyncio.create_task(
            self._on_browser_closed(closed_browser=browser)))
        self.context.on("page", lambda page: asyncio.create_task(self.attach_page(page)))
        page = await self.context.new_page()
        await self.attach_page(page)
        try:
            await page.goto(self.url, wait_until="domcontentloaded", timeout=30000)
        except Exception as exc:
            # 首个页面导航失败时就给出**可行动**的诊断，而不是只把 net::ERR_EMPTY_RESPONSE
            # 原样抛出去（那正是代理把请求吃掉时的形态，归因极难）。
            kind = proxy_failure_kind(str(exc))
            hint = proxy_failure_hint(str(exc), mode=mode)
            detail = f"{type(exc).__name__}: {exc}"
            if hint:
                detail = f"{detail}\n{hint}"
            raise BrowserNavigationError(detail, proxy_hint=hint, failure_kind=kind) from exc

    async def _retry_with_mode(self, mode: str, state: Any, *, first_error: Exception) -> None:
        """换代理模式**重建**浏览器并重试**一次**（自动回退的唯一入口）。

        为什么必须重建：``--no-proxy-server`` 是**进程级**启动参数，已经在跑的浏览器
        没法在中途改代理。所以先把旧浏览器收干净（不留半开窗口 / 多余 node 进程），再用
        新参数起一台。

        失败语义**不变**：两次都失败就照旧失败，只是诊断里会写清「两种模式都试过了、
        各自怎么失败的、接下来查什么」（``both_modes_failed_detail``）——不吞异常，
        也不把它变成成功。
        """
        first_mode = self.proxy_mode
        await self._discard_browser()
        try:
            await self._open_browser_and_first_page(mode, state)
        except BrowserNavigationError as second_error:
            raise BrowserNavigationError(
                both_modes_failed_detail(first_mode, mode, first_error, second_error),
                proxy_hint=proxy_failure_hint(str(second_error), mode=mode),
                failure_kind=second_error.failure_kind,
            ) from second_error
        # 成功：记下**真正生效**的模式与回退事实，供调用侧明确告知使用者。
        self.proxy_mode = mode
        self.proxy_fallback = {
            "from": first_mode,
            "to": mode,
            "message": auto_fallback_notice(first_mode, mode),
        }

    async def _discard_browser(self) -> None:
        """把当前浏览器 / context 收干净，且**不**触发「用户关了浏览器」的收尾。

        自动回退要在中途换一台浏览器，中间会关掉旧的那台。三件事必须做对：

        1. **关旧浏览器会触发 ``disconnected``** —— 那会被 ``_on_browser_closed`` 当成
           「用户关了窗口」而把整个会话收尾掉。这里先把 ``self.browser`` 置空，回调里
           因「关掉的不是当前这台」直接返回；
        2. **旧浏览器的在途事件不得写进 capture.jsonl**：它们属于被放弃的那一次尝试，
           而 CDP 的 requestId 只在**同一个浏览器实例**内有意义——混进重试后的记录里，
           ``headers_patch`` / 响应体配对会串到别的请求上。``_switching_proxy`` 为真期间
           ``emit()`` 直接丢弃（各 handler 的入口检查在 await 之前，拦不住已派发的任务，
           所以闸门放在唯一出口上）；
        3. **不留半开窗口 / 多余进程**：close 失败也继续往下走（状态在 finally 里复位），
           否则重试会起第二台浏览器而第一台还挂着。
        """
        self._switching_proxy = True
        try:
            browser, self.browser = self.browser, None
            self.context = None
            # 会话/页面维度的引用登记表整体清空：它们都指向已死的那台浏览器。
            self.pages.clear()
            self.cdp_sessions.clear()
            self.cdp_meta.clear()
            self.attached_frames.clear()
            self.attaching_frames.clear()
            self.ws_urls.clear()
            if browser is not None:
                try:
                    await browser.close()
                except Exception:                          # noqa: BLE001 — 关不掉也要继续重试
                    pass
        finally:
            self._switching_proxy = False

    def mark_auth_ready(self) -> None:
        self.auth_ready = True
        if self.status == "authenticating":
            self.status = "capturing"
            self.pause_reason = None

    async def _enter_capturing(self) -> None:
        """登录完成：开始记录。"""
        self.mark_auth_ready()
        self.last_activity = time.monotonic()

    async def _on_browser_closed(self, closed_browser: Any = None) -> None:
        """Issue #13: 用户关闭浏览器 → 自动收尾，保留已抓数据。

        此前无此处理：会话卡在 capturing、元数据不落盘、list_sessions 看不到它，
        用户会以为整轮采集白干（实际 capture.jsonl 是逐条落盘、数据完整的）。

        ``closed_browser``：``disconnected`` 事件带回来的那台浏览器。自动回退时我们
        **主动**关掉上一台，事件同样会到达这里——传进来的不是当前这台就说明那是回退
        过程中的清理，不是用户关了窗口，直接返回（否则整个会话会被自己收尾掉）。
        """
        if closed_browser is not None and closed_browser is not getattr(self, "browser", None):
            return
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

    async def request_confirm_dialog(self) -> dict[str, Any]:
        """按需弹出系统确认对话框，用户点「是」才开始记录。

        与 ``confirm_login_ready`` 等价，只是把「问用户」这一步交给系统对话框，
        供 Agent 不便在对话里询问时使用（例如用户要求用弹窗）。语义与登录环节
        ``LoginManager.request_confirm_dialog`` 保持一致：

        * 只在调用方明确请求时弹出；
        * 「否」不丢弃——会话保持 ``authenticating``，可再次请求弹出；
        * 已不在等待登录态的会话直接拒绝，不弹出必然变成死物的对话框。
        """
        if self.status != "authenticating":
            return {"success": False, "error": "not_authenticating", "status": self.status,
                    "message": "会话已不在等待登录态，不会弹出会变成死物的对话框。"}
        if self.dialog_open:
            return {"success": False, "error": "dialog_already_open", "status": self.status}

        self.dialog_open = True
        try:
            answer = await dialog.run_blocking(self._ask_native)
        finally:
            self.dialog_open = False

        if answer is None:
            return {"success": False, "error": "dialog_unavailable", "status": self.status,
                    "message": "无法显示系统对话框，请在对话里直接向用户确认后调用 confirm_login_ready。"}
        if not answer:
            return {"success": True, "confirmed": False, "status": self.status,
                    "message": "用户表示还没登录完成；浏览器保持打开，可稍后再次请求确认。"}
        # 对话框开着的时候用户可能直接关掉了浏览器（_on_browser_closed 已收尾），
        # 此时不能把已结束的会话翻回去继续记录。
        if self.status != "authenticating":
            return {"success": False, "error": "session_no_longer_authenticating",
                    "status": self.status, "stop_reason": self.stop_reason}
        await self._enter_capturing()
        return {"success": True, "confirmed": True, "session_id": self.session_id,
                "status": self.status}

    def _ask_native(self) -> bool | None:
        """弹出阻塞式确认对话框（与登录环节共用 dialog 模块的实现）。"""
        return dialog.ask_yes_no(self._CONFIRM_PROMPT, dialog.DEFAULT_TITLE)

    async def attach_page(self, page: Any) -> None:
        if page in self.pages:
            return
        self.pages.add(page)
        # Issue #14: 不再暴露 __mcp_control 绑定（页内控制条已移除）
        cdp = await self.context.new_cdp_session(page)
        self.cdp_sessions[page] = cdp
        # tag 为空串 = 主页面会话：事件里的 requestId 保持原样（见 __init__ 的注释）。
        self.cdp_meta[cdp] = {"tag": "", "kind": "page", "target": {"kind": "page"}}
        await cdp.send("Network.enable")
        await cdp.send("Network.setCacheDisabled", {"cacheDisabled": True})
        await cdp.send("Runtime.enable")
        # S21：这一条**留不住跨进程 iframe 的事件**——它只让我们看见
        # Target.attachedToTarget 本身，子会话的网络事件会被 Playwright 丢掉
        # （原因见 attach_frame_if_needed）。保留它是因为它零成本，且一旦
        # Playwright 放开子会话，我们在这上面补订阅即可。
        await cdp.send("Target.setAutoAttach", {"autoAttach": True, "flatten": True, "waitForDebuggerOnStart": False})
        self._subscribe_network(cdp)
        # S21：OOPIF 与主页面在**不同 target** 里，它的网络事件不会出现在上面的
        # 会话里，必须按 frame 单独挂（见 attach_frame_if_needed）。
        page.on("frameattached", lambda frame: asyncio.create_task(
            self.attach_frame_if_needed(frame, retry=True)))
        page.on("framenavigated", lambda frame: asyncio.create_task(
            self.attach_frame_if_needed(frame)))

    def _subscribe_network(self, cdp: Any) -> None:
        """把网络相关事件订阅挂到某个 CDP 会话上（主页面会话与 OOPIF 子会话共用一套）。

        子会话与主会话用**同一个** handler，所以 ``on_request`` 里那套配对逻辑只有
        一份；会话之间的隔离靠 ``_session_key`` 的前缀，而不是靠重复实现。
        """
        cdp.on("Network.requestWillBeSent", lambda event: asyncio.create_task(self.on_request(event, cdp)))
        # Issue #1: M117+ 的 Cookie/Sec-* 合成头只在 ExtraInfo 事件里，必须一并订阅。
        cdp.on("Network.requestWillBeSentExtraInfo", lambda event: asyncio.create_task(self.on_request_extra_info(event, cdp)))
        cdp.on("Network.responseReceived", lambda event: asyncio.create_task(self.on_response(event, cdp)))
        cdp.on("Network.loadingFinished", lambda event: asyncio.create_task(self.on_finished(event, cdp)))
        # S22：这两个事件原先**只**靠 emit() 里的状态判断拦截（emit 现在不再承担
        # 「要不要记录」的判定，见其 docstring），所以入口必须自己判断「现在是否在
        # 记录」，否则暂停/停止时它们会继续往 capture.jsonl 里写。
        cdp.on("Network.loadingFailed", lambda event: asyncio.create_task(self.on_loading_failed(event, cdp)))
        cdp.on("Network.webSocketCreated", lambda event: asyncio.create_task(self.on_websocket_created(event, cdp)))
        # S21：WebSocket 的**帧**（握手之外的真正内容）此前从未订阅——真机实测
        # webSocketFrameSent/Received 是会到达页面会话的，只是没人接。
        cdp.on("Network.webSocketFrameSent", lambda event: asyncio.create_task(
            self.on_websocket_frame(event, cdp, "sent")))
        cdp.on("Network.webSocketFrameReceived", lambda event: asyncio.create_task(
            self.on_websocket_frame(event, cdp, "received")))
        cdp.on("Network.webSocketFrameError", lambda event: asyncio.create_task(
            self.on_websocket_frame_error(event, cdp)))

    async def attach_frame_if_needed(self, frame: Any, retry: bool = False) -> None:
        """S21：给**跨进程 iframe（OOPIF）**单独挂一个 CDP 会话。

        为什么主页面会话抓不到 OOPIF：
          * OOPIF 在**另一个 target**（另一个渲染进程）里，它的 Network 事件只发给
            「挂在那个 target 上的会话」；
          * 我们在页面会话上调的 ``Target.setAutoAttach(flatten=True)`` 只让我们收到
            ``Target.attachedToTarget``（真机实测确认收到，targetInfo.type=iframe），
            但子会话后续的事件**在客户端侧根本到不了我们手里**：Playwright 的
            CRConnection 按 ``message.sessionId`` 派发，子会话的 sessionId 没有对应的
            CRSession 就被**静默丢弃**；而客户端可见的事件 payload 里根本没有
            sessionId（``CDPSession._on_event`` 只转发 method/params）。所以「靠
            setAutoAttach 把子会话接进来」这条路在 Playwright 的公开 API 上走不通。
          * 真机实测（Chromium，`--site-per-process`，跨站 iframe）：iframe 内部的
            fetch 在页面会话里**完全不出现**；iframe 自己那次导航请求会出现，因为它
            由父框架发起、走父会话——所以「只漏一部分」正是最容易被忽略的那种漏。

        走得通的路是 ``BrowserContext.new_cdp_session(frame)``：它对 OOPIF frame 会
        为新 target 建一个真正的 CDP 会话（内部 ``Target.attachToTarget`` →
        ``createChildSession``，于是事件能派发到客户端），而对同进程 iframe 直接抛
        "This frame does not have a separate CDP session"——这个异常正好可以当判据：
        抛错就说明它已经被父会话覆盖，无需另挂。

        去重按 frame guid（``framenavigated`` 每次导航都会触发；重复挂 = 同一批事件
        抓两遍）。去重必须**抢占式**：frameattached 与 framenavigated 两条路径会并发
        进入本函数，中间有 await，只在最后才登记的话两次调用都会挂上（真机实测踩到）。
        主框架显式跳过：它已经由 ``attach_page`` 挂的会话覆盖，再挂一次会把它的每个
        请求都记两遍。
        """
        if self.status in {"stopped", "failed", "stopping"}:
            return
        key = _frame_key(frame)
        if not key or key in self.attached_frames or key in self.attaching_frames:
            return
        page = getattr(frame, "page", None)
        if page is None:
            return
        main_frame = getattr(page, "main_frame", None)
        if frame is main_frame or (main_frame is not None and key == _frame_key(main_frame)):
            return
        self.attaching_frames.add(key)                     # 抢占：并发的那条路径就此退出
        try:
            attempts = _OOPIF_ATTACH_ATTEMPTS if retry else 1
            for attempt in range(attempts):
                if self.status in {"stopped", "failed", "stopping"} or not getattr(self, "context", None):
                    return
                try:
                    cdp = await self.context.new_cdp_session(frame)
                except Exception:
                    # 同进程 iframe（或同目标里第二个 frame）：父会话已经覆盖它了。
                    # 重试是因为 frameattached 时它往往还在父进程里，提交之后才变 OOPIF。
                    if attempt + 1 < attempts:
                        await asyncio.sleep(_OOPIF_ATTACH_INTERVAL)
                        continue
                    return
                self._session_seq += 1
                tag = f"sub{self._session_seq}"
                try:
                    frame_url = frame.url
                except Exception:                          # noqa: BLE001 — frame 可能已经没了
                    frame_url = None
                self.attached_frames.add(key)
                self.cdp_meta[cdp] = {
                    "tag": tag, "kind": "frame",
                    "target": {"kind": "frame", "frame": key, "url": frame_url},
                }
                try:
                    await cdp.send("Network.enable")
                    await cdp.send("Network.setCacheDisabled", {"cacheDisabled": True})
                except Exception:                          # noqa: BLE001 — 会话可能刚失效
                    return
                # 子会话只订阅 Network：OOPIF 里再套 OOPIF 会由本函数按 frame 各自处理，
                # 不需要在子会话上再 setAutoAttach；Runtime.enable 也会平白多收一堆调用。
                self._subscribe_network(cdp)
                return
        finally:
            self.attaching_frames.discard(key)

    @staticmethod
    def _redacted_headers(headers: dict[str, Any] | None) -> dict[str, str]:
        """合并后的头必须统一走 redact_headers——Cookie 脱敏成 ``name=***``，
        analyzer 正是靠它提取 cookie_names 判定站点鉴权。"""
        return redact_headers(headers or {})

    # ---- S21：会话维度的 requestId ---------------------------------------- #
    def _tag_for(self, cdp: Any) -> str:
        """该 CDP 会话的命名空间标签；主页面会话（以及未知/None 会话）是空串。"""
        meta = self.cdp_meta.get(cdp) if cdp is not None else None
        return (meta or {}).get("tag", "")

    def _session_key(self, cdp: Any, request_id: str) -> str:
        """把 CDP 的 requestId 映射成**会话维度**的键。

        CDP 的 requestId 只在它自己那个会话里唯一：主页面会话与每个 OOPIF 子会话
        各有一套编号（真机实测：目标之间互不知情）。直接混用会让
        ``emitted_requests`` / ``pending_extra`` / ``request_meta`` 彼此串数据——
        ExtraInfo 补到别的请求头上、响应体挂到别的请求上、headers_patch 打错人。
        所以子会话统一加 ``<tag>:`` 前缀；**主页面会话 tag 为空，键与修复前完全
        一致**（既有的配对、重定向 hop、落盘 requestId 都不变）。
        """
        tag = self._tag_for(cdp)
        if not tag or not request_id:
            return request_id
        return f"{tag}:{request_id}"

    def _session_fields(self, cdp: Any) -> dict[str, Any]:
        """子会话事件要带上来源，否则事后分不清是哪个 target/frame 发的。

        主页面会话**不加**任何字段：它的记录形状与修复前逐字节一致。
        """
        meta = self.cdp_meta.get(cdp) if cdp is not None else None
        if not meta or not meta.get("tag"):
            return {}
        return {"cdp_session": meta["tag"], "source_target": dict(meta.get("target") or {})}

    async def on_request(self, event: dict[str, Any], cdp: Any) -> None:
        if self.status != "capturing":
            return
        self.last_activity = time.monotonic()
        request = event.get("request", {})
        body = request.get("postData")
        # 请求体此前**没有任何上限**：目标站上一个 500MB 上传会让 redact_payload
        # 处理整串、capture.jsonl 涨 500MB，随后 analyze_traffic 整文件读进内存。
        # 这里与响应体共用同一套语义：超限则完全不记录体，只留大小与标记。
        body_size = len(body.encode("utf-8", "replace")) if isinstance(body, str) else 0
        if body_size > self.response_limit:
            redacted_body, token_paths, shape_meta = None, [], {}
            body_dropped = True
        else:
            redacted_body, token_paths, shape_meta = redact_payload(body)
            body_dropped = False
        # S21：会话维度的键——子会话（OOPIF）加前缀，主会话保持原样。
        request_id = self._session_key(cdp, event.get("requestId", ""))
        # Issue #1: 合并 requestWillBeSent 与（通常先到的）ExtraInfo 里的头。
        extra = self._take_pending_extra(request_id)
        extra_headers = (extra or {}).get("headers", {}) if isinstance(extra, dict) else {}
        record = {
            "type": "request", "ts": utc_now(), "requestId": request_id,
            "url": request.get("url"), "method": request.get("method"),
            "headers": self._redacted_headers(_merge_headers(request.get("headers", {}), extra_headers)),
            "postData": redacted_body,
            "postData_size": body_size, "body_dropped": body_dropped,
            "resourceType": event.get("type"),
            # 超大体的启发式只看前缀，避免为判定去扫描整段大字符串
            "auth_candidate": is_auth_candidate(
                request.get("url", ""), body[:4096] if isinstance(body, str) else body),
            "token_paths": token_paths,
            "redaction_meta": shape_meta,
        }
        record.update(self._session_fields(cdp))
        self.request_meta[request_id] = {"url": request.get("url", ""), "resourceType": event.get("type")}
        self.emitted_requests[request_id] = (time.monotonic(), record)
        # 与 pending_extra 相同的回收路径：每次新增都先 prune，长会话不会无界增长。
        self._prune_emitted_requests()
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
        # S22：_flushed_extra 跟着同一套回收走，永远是 pending_extra 的子集，不会无界增长。
        self._flushed_extra.intersection_update(self.pending_extra)

    def _prune_emitted_requests(self) -> None:
        """回收**永不结束**的请求留下的记录（Fix 2）。

        正常路径由 ``on_finished`` 的 finally 负责清理；这里兜住的是「请求被中止、
        用户导航走、页面关闭」——它们永远不会触发 loadingFinished，记录会一直驻留。
        逐出顺序：先按 TTL，再按容量（FIFO 丢最旧），与 ``_prune_pending_extra`` 一致。
        """
        now = time.monotonic()
        for key in [k for k, (ts, _) in self.emitted_requests.items()
                    if now - ts > _EMITTED_REQUEST_TTL]:
            del self.emitted_requests[key]
        while len(self.emitted_requests) > _MAX_EMITTED_REQUESTS:
            del self.emitted_requests[next(iter(self.emitted_requests))]

    async def on_request_extra_info(self, event: dict[str, Any], cdp: Any) -> None:
        """Chromium M117+ 的 Cookie/Sec-* 等浏览器合成头只在此事件中出现。

        时序：ExtraInfo 通常早于 requestWillBeSent 到达，此时暂存待配对；
        若 requestWillBeSent 已经发出记录（ExtraInfo 后到的少数情况），
        直接对已入队/已落盘的 request 记录做**原地补丁**并补发一条
        ``headers_patch`` 事件——writer 按引用读取，故两种时序都能覆盖。
        """
        if self.status != "capturing":
            return
        request_id = self._session_key(cdp, event.get("requestId", ""))
        headers = event.get("headers", {}) or {}
        if not request_id:
            return
        entry = self.emitted_requests.get(request_id)
        if entry is None:
            self.pending_extra[request_id] = (time.monotonic(), event)
            self._prune_pending_extra()
            self._prune_emitted_requests()
            return
        record = entry[1]
        merged = self._redacted_headers(_merge_headers(record.get("headers"), headers))
        if merged == record.get("headers"):
            return  # 无新增（如纯重定向重发），不必产生噪音事件
        record["headers"] = merged
        await self.emit({"type": "headers_patch", "ts": utc_now(), "requestId": request_id,
                         "headers": merged, "reason": "requestWillBeSentExtraInfo_late",
                         **self._session_fields(cdp)})

    async def on_response(self, event: dict[str, Any], cdp: Any = None) -> None:
        if self.status != "capturing":
            return
        response = event.get("response", {})
        await self.emit({
            "type": "response", "ts": utc_now(),
            "requestId": self._session_key(cdp, event.get("requestId")),
            "status": response.get("status"), "url": response.get("url"),
            "headers": redact_headers(response.get("headers", {})),
            "mimeType": response.get("mimeType"), "resourceType": event.get("type"),
            **self._session_fields(cdp),
        })

    async def on_finished(self, event: dict[str, Any], cdp: Any = None) -> None:
        # S21：必须用与 on_request 相同的会话维度键，否则子会话的响应体会挂到
        # 主会话同名 requestId 的记录上（串数据）。
        request_id = self._session_key(cdp, event.get("requestId"))
        try:
            # 状态判断必须放在 try 内：否则中途 paused/stopping 时直接 return，
            # 下面的 finally 不执行，配对缓存永不清理。
            if self.status != "capturing":
                return
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
                self.dropped_response_bodies += 1
                await self.emit({"type": "response_body", "requestId": request_id, "body": None,
                                 "body_truncated": True, "body_dropped": True,
                                 "size": size, "base64Encoded": encoded,
                                 **self._session_fields(cdp)})
            else:
                await self.emit({"type": "response_body", "requestId": request_id, "body": body,
                                 "body_truncated": False, "body_dropped": False,
                                 "size": size, "base64Encoded": encoded,
                                 **self._session_fields(cdp)})
        except Exception as exc:
            await self.emit({"type": "response_body", "requestId": request_id,
                             "body_unavailable_reason": type(exc).__name__,
                             **self._session_fields(cdp)})
        finally:
            # 请求结束：释放 Issue #1 的配对缓存，避免长会话内存泄漏。
            # request_meta 此前**从不清理**：两小时 5 万请求就是 5 万条常驻字典。
            # 正常结束由这里兜底；被中断/永不结束的请求由 _prune_emitted_requests
            # 按 TTL + 容量回收（Fix 2）——两者是互补的，都要在。
            self.emitted_requests.pop(request_id, None)
            self.pending_extra.pop(request_id, None)
            self.request_meta.pop(request_id, None)

    async def on_loading_failed(self, event: dict[str, Any], cdp: Any = None) -> None:
        if self.status != "capturing":
            return
        payload = dict(event)
        if payload.get("requestId"):
            # 只在原本就带 requestId 时改写它，主会话的事件形状与修复前一致。
            payload["requestId"] = self._session_key(cdp, payload["requestId"])
        await self.emit({"type": "loading_failed", **payload, **self._session_fields(cdp)})

    async def on_websocket_created(self, event: dict[str, Any], cdp: Any = None) -> None:
        if self.status != "capturing":
            return
        payload = dict(event)
        raw_id = payload.get("requestId")
        if raw_id:
            payload["requestId"] = self._session_key(cdp, raw_id)
            # 帧事件不带 url；先在这里记下来（有界 + FIFO，长会话不会涨）。
            self._remember_ws_url(payload["requestId"], payload.get("url"))
        await self.emit({"type": "websocket", **payload, **self._session_fields(cdp)})

    def _remember_ws_url(self, request_id: str, url: Any) -> None:
        self.ws_urls[request_id] = (time.monotonic(), url or "")
        while len(self.ws_urls) > _MAX_WS_URLS:
            del self.ws_urls[next(iter(self.ws_urls))]

    async def on_websocket_frame(self, event: dict[str, Any], cdp: Any = None,
                                 direction: str = "sent") -> None:
        """S21：WebSocket 帧（握手之外的真正内容）。

        此前**只**订阅了 ``webSocketCreated``：握手请求可能抓得到，帧内容全丢。
        真机实测（Chromium 109+）：``webSocketFrameSent/Received`` 会正常到达页面
        会话，只是从来没人接。

        体量语义与响应体**完全一致**（``response_limit``）：超限就**完全不写体**，
        只留 ``payload_size`` 与 ``payload_dropped``；二进制帧按 base64 解码后的
        长度算。脱敏沿用 ``redact_payload``（与请求体同一个入口，JSON/表单里的凭据
        会被遮成 ``***``，形态元数据照旧保留），不另造一套。
        """
        if self.status != "capturing":
            return
        response = event.get("response") or {}
        request_id = self._session_key(cdp, event.get("requestId") or "")
        opcode = response.get("opcode")
        payload = response.get("payloadData")
        payload_size = self._frame_payload_size(payload, opcode)
        if payload_size > self.response_limit:
            redacted, token_paths, shape_meta = None, [], {}
            dropped = True
        else:
            redacted, token_paths, shape_meta = redact_payload(payload)
            dropped = False
        await self.emit({
            "type": "websocket_frame", "ts": utc_now(), "requestId": request_id,
            "direction": direction, "opcode": opcode, "mask": response.get("mask"),
            "payload": redacted, "payload_size": payload_size, "payload_dropped": dropped,
            # 帧事件本身不带 url，靠 webSocketCreated 记下的（可能已过期/未见到）。
            "url": self.ws_urls.get(request_id, (None, None))[1],
            "token_paths": token_paths, "redaction_meta": shape_meta,
            **self._session_fields(cdp),
        })

    @staticmethod
    def _frame_payload_size(payload: Any, opcode: Any) -> int:
        """帧体字节数。二进制帧（opcode 2）在 CDP 里是 base64，先解码再算。"""
        if not isinstance(payload, str):
            return 0
        if opcode == 2:
            try:
                return len(base64.b64decode(payload, validate=False))
            except Exception:                              # noqa: BLE001 — 非法 base64 就按原文算
                pass
        return len(payload.encode("utf-8", "replace"))

    async def on_websocket_frame_error(self, event: dict[str, Any], cdp: Any = None) -> None:
        """帧发送/接收出错（连接被重置等）也要留痕，否则只能看到「帧突然没了」。"""
        if self.status != "capturing":
            return
        await self.emit({"type": "websocket_frame_error", "ts": utc_now(),
                         "requestId": self._session_key(cdp, event.get("requestId") or ""),
                         "error_message": event.get("errorMessage"),
                         **self._session_fields(cdp)})

    @property
    def _recording(self) -> bool:
        """「已经抓到的事件还可以落盘」的阶段：capturing / paused / stopping。

        为什么不是只有 ``capturing``（S22）：``paused`` 与 ``stopping`` 是**在途**
        状态——某个 handler 在暂停**之前**就已通过入口检查、数据（例如
        ``Network.getResponseBody`` 抓回来的响应体）已经在内存里，只差一次 emit。
        这些数据是在超时/停止之前抓到的，丢掉就是静默数据丢失。**新的**流量仍由各
        handler 入口的 ``status != "capturing"`` 挡住，暂停语义（不再记录新流量）不变；
        真正结束（stopped / failed）后不再接受任何事件。
        """
        return self.status in {"capturing", "paused", "stopping"}

    async def emit(self, event: dict[str, Any]) -> None:
        """把事件送进写盘队列。

        「要不要记录这条事件」由调用方（各 CDP handler）的入口检查决定，这里只管
        会话是不是已经彻底结束——理由见 ``_recording``。

        ``_switching_proxy`` 期间**一律丢弃**：那是自动回退正在换浏览器，此刻到达的
        事件都属于被放弃的那一次尝试（requestId 不跨浏览器实例），写下去只会污染
        重试后的记录。各 handler 的入口检查在 await 之前，拦不住已派发的任务，所以
        闸门必须放在这个唯一出口上。
        """
        if self._recording and not self._switching_proxy:
            await self.event_queue.put(event)

    def _write_batch(self) -> bool:
        """把 ``self._batch`` 落盘并清空；失败返回 False（原因写进 write_error）。"""
        if not self._batch:
            return True
        try:
            with self.capture_path.open("a", encoding="utf-8") as stream:
                for event in self._batch:
                    stream.write(json.dumps(event, ensure_ascii=False) + "\n")
                stream.flush()
        except Exception as exc:
            # 此前没有 try：一次 OSError（磁盘满）/编码错误就让 writer 任务死掉，
            # 而 stop() 会 await 这个任务并把异常抛回调用方 —— 会话永久卡在
            # stopping，浏览器与 node 驱动再也关不掉，数据也停在半路。
            self.write_error = f"{type(exc).__name__}: {exc}"
            self.status = "failed"
            self._batch.clear()
            # 丢积压：磁盘写不进去，重试无意义，留着只会让队列无界增长。
            while not self.event_queue.empty():
                try:
                    self.event_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
            return False
        self._batch.clear()
        return True

    async def _flush_now(self) -> None:
        """把**已经抓到、还没落盘**的事件立刻写进 capture.jsonl（S22）。

        两个来源：写盘队列里排队的，以及 writer 已经取出、正握在 ``self._batch``
        里的。与 writer 共用同一把锁和同一个批缓冲，所以既不会乱序也不会重复写。
        写失败时 ``_write_batch`` 会把 ``write_error`` / ``status=failed`` 落下来，
        不会静默。
        """
        async with self.flush_lock:
            sentinel = False
            while True:
                try:
                    item = self.event_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                if item is None:
                    # stop() 的收尾哨兵：它不是事件，绝不能当数据写进 capture.jsonl。
                    sentinel = True
                    continue
                self._batch.append(item)
            if sentinel:
                # 放回队尾：writer（若还活着）靠它决定何时收工；排到真实事件之后，
                # 也保证「哨兵之后才到的在途事件」仍被算作待写数据。
                self.event_queue.put_nowait(None)
            self._write_batch()

    async def _flush_unpaired_extra(self, reason: str) -> None:
        """把「等不到配对」的 ExtraInfo 落盘（S22）。

        ``pending_extra`` 里存的是从浏览器**真实抓到**的头（Cookie / Sec-* 的权威
        来源），只差配对的 ``requestWillBeSent``。此前它们只活在内存里，会话一停就
        无声消失。现在暂停/停止时原样写进 capture.jsonl：

          * 配对缓存**保留**——恢复后晚到的 requestWillBeSent 仍能拿到这些头，
            抓包结果不变；
          * 已落盘过的 requestId 不重复写（``_flushed_extra``，随配对缓存一起回收）；
          * 事件类型是新增的 ``request_extra_info_unpaired``：analyzer 只认
            request / response / response_body / headers_patch，多出来的类型会被
            忽略，既有分析结果不受影响。
        """
        pending = [rid for rid in self.pending_extra if rid not in self._flushed_extra]
        if not pending:
            return
        async with self.flush_lock:
            for request_id in pending:
                entry = self.pending_extra.get(request_id)
                headers = redact_headers(((entry[1] if entry else None) or {}).get("headers") or {})
                self._batch.append({
                    "type": "request_extra_info_unpaired",
                    "ts": utc_now(),
                    "requestId": request_id,
                    "headers": headers,
                    "reason": reason,
                    "note": "已抓到请求头但未等到配对的 requestWillBeSent；先落盘，避免暂停/停止时丢失。",
                })
                self._flushed_extra.add(request_id)
            self._write_batch()

    async def _writer(self) -> None:
        while True:
            # 整个「取事件 / maybe 落盘」都在锁内：_flush_now() 才能与 writer 互斥，
            # 又共用 self._batch，保证 capture.jsonl 里的事件顺序与产生顺序一致。
            async with self.flush_lock:
                try:
                    item = await asyncio.wait_for(self.event_queue.get(), timeout=1)
                except asyncio.TimeoutError:
                    item = None
                if item is not None:
                    self._batch.append(item)
                if self._batch and (len(self._batch) >= 50 or item is None):
                    if not self._write_batch():
                        return
                if item is None and self.status == "stopping" and self.event_queue.empty():
                    return

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
        """暂停记录（空闲超时等）。**不是丢弃点**（S22）。

        触发时依次做三件事：

        1. 把已经抓到、还没落盘的事件（写盘队列 + writer 手里那批）立刻落盘；
        2. 把「等不到配对」的 ExtraInfo 也落盘（它此前只存在内存里，会话结束时无声消失）；
        3. 把这次转换写进会话元数据（status / pause_reason / paused_at /
           status_history 的 reason / captured_bytes + 一句可读提示）。

        第 3 步此前完全没有：``pause`` 不落盘，``list_sessions`` 读到的仍是
        ``capturing``，Agent 只有恰好同进程调 ``get_capture_status`` 才看得到，
        服务一重启连「为什么停的」都无从得知——转换是静默的。

        语义不变：暂停仍不记录新流量（各 handler 入口仍要求 status == capturing），
        空闲超时时长也不动（``Settings.idle_timeout_seconds``）。
        """
        if self.status != "capturing":
            return
        self.status = "paused"
        self.pause_reason = reason
        self.paused_at = utc_now()
        await self._flush_now()
        await self._flush_unpaired_extra(reason)
        self._persist_pause(reason)

    async def resume(self) -> None:
        if self.status != "paused":
            return
        self.status = "capturing"
        self.pause_reason = None
        self.paused_at = None
        self.last_activity = time.monotonic()

    def _persist_pause(self, reason: str) -> None:
        """把「已暂停」写进会话元数据（S22：转换必须可见，不能静默）。

        **合并**磁盘上已有的元数据再写，不整体覆盖：``start_capture`` 写下的
        ``status_history`` / ``requested_session_id`` 等字段必须留住（``stop()`` /
        ``_on_browser_closed()`` 那边是整体覆盖的口径，这里不能照抄）。写失败也不抛，
        但会记进 ``metadata_error`` 并随 metadata() 上报——不能静默。
        """
        try:
            metadata = self.store.read_metadata(self.session_id) or {}
            metadata.update({
                "session_id": self.session_id,
                "url": self.url,
                "status": self.status,
                "pause_reason": self.pause_reason,
                "paused_at": self.paused_at,
                "captured_bytes": self._captured_bytes(),
            })
            metadata.setdefault("status_history", []).append(
                {"status": self.status, "ts": self.paused_at or utc_now(), "reason": reason})
            self.store.write_metadata(self.session_id, metadata)
        except Exception as exc:                           # noqa: BLE001 — 见 docstring
            self.metadata_error = f"{type(exc).__name__}: {exc}"

    async def stop(self, reason: str = "agent_requested") -> dict[str, Any]:
        async with self.stop_lock:
            if self.status in {"stopped", "failed"}:
                return self.metadata()
            self.status = "stopping"
            self.stop_reason = reason
            # S22：暂停过又直接结束的会话，其「已抓到但还没落盘」的事件与未配对
            # ExtraInfo 必须在关浏览器之前落地（否则 stop 之后就再也拿不到了）。
            await self._flush_now()
            await self._flush_unpaired_extra(reason)
            await self.event_queue.put(None)
            if self.writer_task:
                await self.writer_task
            if self.browser:
                await self.browser.close()
            if getattr(self, "playwright", None):
                await self.playwright.stop()
            # 收尾：writer 退出、关浏览器期间都仍可能有在途 handler 落进队列
            # （见 _recording），落最后一次盘再宣告结束。此后 status=stopped，
            # emit 不再接受任何事件。
            await self._flush_now()
            self.status = "stopped"
            self.store.write_metadata(self.session_id, self.metadata())
            return self.metadata()

    def _captured_bytes(self) -> int:
        """本会话已落盘的抓包体积（元数据上报用；store 缺失时退化为 0）。"""
        try:
            return self.capture_path.stat().st_size if self.capture_path.exists() else 0
        except (OSError, AttributeError):
            return 0

    def metadata(self) -> dict[str, Any]:
        meta = {"session_id": self.session_id, "url": self.url, "status": self.status, "stop_reason": self.stop_reason, "pause_reason": self.pause_reason, "endpoint_count": self.endpoint_count, "created_at": utc_now(), "auth_state_path": self.auth_state_path, "auth_evidence": self.auth_evidence}
        # 只在真出过写盘失败时带这个键，正常会话的元数据形状保持不变。
        if self.write_error:
            meta["write_error"] = self.write_error
        if self.metadata_error:
            meta["metadata_error"] = self.metadata_error
        if self.proxy_fallback:
            # 自动回退过就留痕：事后看 list_sessions / get_capture_status 也能知道
            # 这次抓包实际走的是系统代理，而不是（名义上的）直连。
            meta["proxy_fallback"] = dict(self.proxy_fallback)
        if self.status == "paused":
            # S22：暂停这件事必须在摘要里看得见（含原因与「数据还在」的证据），
            # 否则 Agent 只看到 status=paused，无从知道为什么、也不知道数据有没有丢。
            captured = self._captured_bytes()
            meta["paused_at"] = self.paused_at
            meta["captured_bytes"] = captured
            meta["pause_hint"] = (
                f"会话因 {self.pause_reason} 暂停（原因见 pause_reason，"
                f"状态历史见 status_history）。已抓到的数据均已落盘，共 {captured / 1024:.1f} KB，"
                "没有丢失：可 resume_capture 继续记录，或 stop_capture 结束后调用 analyze_traffic 分析。"
            )
        if self.dropped_response_bodies:
            # S20：丢过响应体这件事必须在元数据里可见（否则只有翻 capture.jsonl 才知道），
            # 且要给出可行动的补救办法（调大上限重抓），而不是让使用者自己看日志判断。
            meta["dropped_response_bodies"] = self.dropped_response_bodies
            meta["dropped_response_bodies_hint"] = dropped_response_bodies_hint(
                self.dropped_response_bodies, self.response_limit)
        if self.response_limit_explicit:
            # 只有调用方显式传了上限才记 —— 默认路径的元数据形状保持不变（等价于改动前）。
            # 记它的用处：analyze_traffic 是**无状态**的（只读磁盘上的 capture.jsonl），
            # 没有这个字段就只能拿全局默认值去生成「当前上限」那句话，显式调大过上限的
            # 会话会看到一句数值错误、也就无法照做的提示。
            meta["response_limit_bytes"] = self.response_limit
        return meta