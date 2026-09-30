# -*- coding: utf-8 -*-
"""抓包浏览器的代理开关：默认**自动**（先直连、失败回退系统代理），失败要能归因。

根因：`capture.py` 启动 Chromium 时**不做任何代理处理**，默默跟系统代理走。非回环
主机的请求被系统代理吃掉后只表现为 ``net::ERR_EMPTY_RESPONSE`` —— 这个报错形态极难
归因（真机实测：加 ``--no-proxy-server`` 才通）。

产品口径（两轮演进后的当前状态）：
  * **默认 `auto`**：从直连（等价 ``--no-proxy-server``）开始，首个页面若以代理类
    形态失败，**自动改用系统代理重试一次**，并在响应里明确告知 —— 「不设任何环境
    变量的用户也应该能成功」是本项的验收点（对不懂 HTTP 的用户，设环境变量不存在）；
  * `direct` / `system` 保留给想手动控制的人，都是**严格**取值，失败不回退。

本文件断言五件事：
  1. 默认（`auto`）launch args 含直连标志；`system` 时不含；
  2. 代理类失败**自动回退一次**并告知；非代理类失败、显式 direct/system **不回退**；
  3. 两次都失败时诊断里说清试过哪两种模式；
  4. 代理形态的失败给出**明确诊断**（抓包侧 + 调用侧都带上可行动信息）；
  5. 非法设置值给**明确错误**（点名变量与坏值），而不是崩或静默退化。

导入 `server.py` 会跑 `Settings.from_environment()` + `ensure_directories()` +
`recover_orphans()`，故先把数据目录指到临时目录再导入，绝不碰本机 `~/.webapiextractor`。
"""
from __future__ import annotations

import asyncio
import contextlib
import importlib
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from webapi_extractor.capture import BrowserNavigationError, CaptureSession
from webapi_extractor.config import Settings
from webapi_extractor.proxy_env import (
    BUILTIN_DIRECT_ARG,
    PROXY_MODE_ENV,
    auto_fallback_notice,
    browser_proxy_args,
    fallback_proxy_mode,
    proxy_failure_hint,
    proxy_failure_kind,
)
from webapi_extractor.storage import SessionStore

URL = "https://oa.example.com/"


# --------------------------------------------------------------------------- #
# 设置项：默认值、解析、非法值报错
# --------------------------------------------------------------------------- #
class TestProxyModeSetting:
    def test_default_is_auto_and_starts_direct(self, monkeypatch):
        """默认 `auto`：**先直连**，但允许失败后自动回退（不设环境变量也应能成功）。"""
        monkeypatch.delenv(PROXY_MODE_ENV, raising=False)
        settings = Settings.from_environment()
        assert settings.proxy_mode == "auto"
        assert BUILTIN_DIRECT_ARG in settings.browser_proxy_args, \
            "auto 也必须从直连开始（否则又回到静默跟随系统代理的老路）"
        assert fallback_proxy_mode("auto") == "system", "auto 失败后必须能回退到系统代理"

    def test_manual_modes_never_fall_back(self):
        """显式 direct / system 是**严格**取值：偷偷改成另一种等于违抗用户的设置。"""
        assert fallback_proxy_mode("direct") is None
        assert fallback_proxy_mode("system") is None

    def test_system_mode_parsed(self, monkeypatch):
        monkeypatch.setenv(PROXY_MODE_ENV, "  System ")          # 容忍空白与大小写
        settings = Settings.from_environment()
        assert settings.proxy_mode == "system"
        assert settings.browser_proxy_args == []

    def test_invalid_value_names_variable_and_bad_value(self, monkeypatch):
        monkeypatch.setenv(PROXY_MODE_ENV, "always")
        with pytest.raises(ValueError) as exc:
            Settings.from_environment()
        message = str(exc.value)
        assert PROXY_MODE_ENV in message, "报错必须点名是哪个变量写错了"
        assert "always" in message, "报错必须带上坏值"
        assert "direct" in message and "system" in message, "报错必须给出合法取值"
        assert "auto" in message, "报错必须给出**默认**取值"

    def test_browser_proxy_args_only_recognizes_system(self):
        assert browser_proxy_args("auto") == [BUILTIN_DIRECT_ARG]
        assert browser_proxy_args("direct") == [BUILTIN_DIRECT_ARG]
        assert browser_proxy_args("system") == []

    def test_fallback_notice_names_both_modes(self):
        """回退成功必须**说出来**，且两个模式都要点名（否则用户无从知道背后换过代理）。"""
        notice = auto_fallback_notice("auto", "system")
        assert "自动" in notice and "系统代理" in notice
        assert "重试" in notice


# --------------------------------------------------------------------------- #
# launch args 真的按设置走（用假 playwright 截住 launch 的实参）
# --------------------------------------------------------------------------- #
class _Boom(RuntimeError):
    """在 launch 处中断 start()，只为看一眼实参。"""


class _RecordingChromium:
    def __init__(self, record: list[dict]) -> None:
        self._record = record

    async def launch(self, **kwargs):
        self._record.append(kwargs)
        raise _Boom("stop after launch")


class _FakePlaywright:
    def __init__(self, record: list[dict]) -> None:
        self.chromium = _RecordingChromium(record)

    async def stop(self) -> None:
        pass


def _fake_async_playwright(record: list[dict]):
    class _Starter:
        async def start(self):
            return _FakePlaywright(record)

    def factory():
        return _Starter()

    return factory


async def _launch_kwargs(tmp_path: Path, proxy_mode: str) -> dict:
    record: list[dict] = []
    session = CaptureSession("s-proxy-args", URL, SessionStore(tmp_path), 262144, 300,
                             auth_state_path=str(tmp_path / "nope.json"),
                             proxy_mode=proxy_mode)
    with patch("playwright.async_api.async_playwright", _fake_async_playwright(record)):
        with pytest.raises(_Boom):
            await session.start()
    # start() 在 launch 之前就起了后台任务；异常路径下由调用方收尾（这里手动收掉，
    # 免得留下空转的 task 影响后续用例）。
    for name in ("writer_task", "idle_task", "login_task"):
        task = getattr(session, name, None)
        if task is not None:
            task.cancel()
            with contextlib.suppress(BaseException):     # 含 asyncio.CancelledError
                await task
    assert record, "未能截到 chromium.launch 的实参，测试本身失效"
    return record[0]


class TestLaunchArgsFollowTheSetting:
    async def test_default_launch_is_direct(self, tmp_path):
        kwargs = await _launch_kwargs(tmp_path, "auto")
        assert BUILTIN_DIRECT_ARG in (kwargs.get("args") or []), \
            "默认必须直连（否则 Chromium 会静默跟随系统代理）"

    async def test_system_mode_launch_has_no_direct_flag(self, tmp_path):
        kwargs = await _launch_kwargs(tmp_path, "system")
        assert BUILTIN_DIRECT_ARG not in (kwargs.get("args") or []), \
            "切回系统代理后不得再带直连标志"

    def test_session_defaults_to_auto_without_explicit_mode(self, tmp_path):
        """不传 proxy_mode 的既有构造点（测试、旧调用方）也默认 `auto`：先直连、可回退。"""
        session = CaptureSession("s-default", URL, SessionStore(tmp_path), 262144, 300)
        assert session.proxy_mode == "auto"
        assert session.proxy_fallback is None, "没发生回退时不得谎报回退过"


# --------------------------------------------------------------------------- #
# 代理类失败的识别与诊断文本
# --------------------------------------------------------------------------- #
class TestProxyFailureDiagnosis:
    def test_empty_response_is_flagged_as_possible_proxy(self):
        """真机踩到的形态：ERR_EMPTY_RESPONSE 极难归因 → 必须被认出来。"""
        assert proxy_failure_kind("Page.goto: net::ERR_EMPTY_RESPONSE at " + URL) == "possible"

    def test_proxy_connection_failed_is_certain(self):
        assert proxy_failure_kind("net::ERR_PROXY_CONNECTION_FAILED") == "proxy"

    def test_connection_timed_out_is_recognized(self):
        """真机实测踩到的第二种形态：``net::ERR_CONNECTION_TIMED_OUT``。

        只认 ``ERR_TIMED_OUT`` 是不够的 —— 前者并不包含后者（``...TION_TIMED_OUT``），
        真机导航失败时 hint 会是 None（本用例即为此回归而写）。
        """
        assert proxy_failure_kind(
            "Error: Page.goto: net::ERR_CONNECTION_TIMED_OUT at https://www.google.com/") \
            == "possible"

    def test_unrelated_failure_is_not_blamed_on_a_proxy(self):
        """认不出的失败**不**给代理提示 —— 否则会把目标站故障误导成代理问题。"""
        assert proxy_failure_kind("Executable doesn't exist at C:/ms-playwright/chrome.exe") is None
        assert proxy_failure_hint("Executable doesn't exist at C:/ms-playwright/chrome.exe") is None

    def test_hint_is_actionable(self):
        hint = proxy_failure_hint("net::ERR_EMPTY_RESPONSE", mode="direct")
        assert hint is not None
        assert "代理" in hint
        assert PROXY_MODE_ENV in hint, "要告诉使用者改哪个设置"
        assert "direct" in hint and "system" in hint, "要给出两个可切换的取值"
        assert "直连" in hint

    def test_hint_reports_the_current_mode(self):
        assert "跟随系统代理" in proxy_failure_hint("net::ERR_PROXY_CONNECTION_FAILED",
                                                    mode="system")


# --------------------------------------------------------------------------- #
# 调用侧：start_capture 的响应必须带可行动诊断
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def web(tmp_path_factory):
    data_root = tmp_path_factory.mktemp("data")
    previous = os.environ.get("WEB_API_EXTRACTOR_DATA")
    os.environ["WEB_API_EXTRACTOR_DATA"] = str(data_root)
    try:
        module = importlib.import_module("webapi_extractor.server")
    finally:
        if previous is None:
            os.environ.pop("WEB_API_EXTRACTOR_DATA", None)
        else:
            os.environ["WEB_API_EXTRACTOR_DATA"] = previous
    return module


@pytest.fixture()
def sessions_dir(web, tmp_path, monkeypatch):
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    monkeypatch.setattr(web.store, "sessions_dir", sessions)
    yield sessions
    web.capture_sessions.clear()


class TestCallerSideDiagnosis:
    async def test_navigation_error_carries_hint_into_the_response(
            self, web, sessions_dir, monkeypatch):
        hint = proxy_failure_hint("net::ERR_EMPTY_RESPONSE", mode=web.settings.proxy_mode)

        async def _fail(self):
            raise BrowserNavigationError(f"Error: Page.goto: net::ERR_EMPTY_RESPONSE at {URL}",
                                         proxy_hint=hint)

        monkeypatch.setattr(web.CaptureSession, "start", _fail)

        result = await web.start_capture(URL, session_id="s-proxy")

        assert result["success"] is False
        assert result["error"] == "capture_start_failed"
        assert result["proxy_hint"] == hint
        assert "代理" in result["message"], "使用者要能在 message 里看到可行动提示"
        assert PROXY_MODE_ENV in result["message"]
        assert "登录" not in result["message"]

    async def test_plain_exception_with_proxy_error_code_still_diagnosed(
            self, web, sessions_dir, monkeypatch):
        """抓包侧没分类的异常（如 launch 阶段）也要能按错误码现推一份诊断。"""
        async def _fail(self):
            raise RuntimeError("Page.goto: net::ERR_PROXY_CONNECTION_FAILED at " + URL)

        monkeypatch.setattr(web.CaptureSession, "start", _fail)

        result = await web.start_capture(URL, session_id="s-proxy-code")

        assert result["success"] is False
        assert "代理" in result.get("proxy_hint", "")

    async def test_non_proxy_failure_adds_no_proxy_hint(self, web, sessions_dir, monkeypatch):
        async def _fail(self):
            raise RuntimeError("Executable doesn't exist at C:/ms-playwright/chrome.exe")

        monkeypatch.setattr(web.CaptureSession, "start", _fail)

        result = await web.start_capture(URL, session_id="s-plain")

        assert result["success"] is False
        assert "proxy_hint" not in result
        assert "代理" not in result["message"]
        assert "Executable doesn't exist" in result["detail"]


# --------------------------------------------------------------------------- #
# R3：代理**自动回退**（先直连 → 代理类失败 → 自动改用系统代理重试一次）
#
# 用一套最小假 Playwright 走完整的 start()：真正的关键点是**生命周期**——
# 换模式必须重建浏览器（--no-proxy-server 是进程级参数），且重建不能把会话收尾掉、
# 不能留下半开窗口、不能把上一次尝试的事件混进来。
# --------------------------------------------------------------------------- #
class _FakeCdp:
    def __init__(self, sink: dict) -> None:
        self._sink = sink

    async def send(self, method, params=None):
        self._sink.setdefault("cdp_send", []).append(method)
        return {}

    def on(self, name, handler):
        pass


class _FakePage:
    def __init__(self, sink: dict, goto_script: list) -> None:
        self._sink = sink
        self._goto_script = goto_script

    def on(self, name, handler):
        self._sink.setdefault("page_events", []).append(name)

    async def goto(self, url, **kwargs):
        self._sink["gotos"].append(url)
        if self._goto_script:
            error = self._goto_script.pop(0)
            if error is not None:
                raise error
        return None


class _FakeContext:
    def __init__(self, sink: dict, goto_script: list) -> None:
        self._sink = sink
        self._goto_script = goto_script

    def on(self, name, handler):
        self._sink.setdefault("context_events", []).append(name)

    async def new_page(self):
        self._sink["pages"] += 1
        return _FakePage(self._sink, self._goto_script)

    async def new_cdp_session(self, page):
        self._sink["cdp_sessions"] += 1
        return _FakeCdp(self._sink)

    async def cookies(self):
        return []


class _FakeBrowser:
    def __init__(self, sink: dict, goto_script: list, args: list) -> None:
        self._sink = sink
        self._goto_script = goto_script
        self.args = args
        self.closed = False
        self._handlers: list = []

    def on(self, name, handler):
        if name == "disconnected":
            self._handlers.append(handler)

    async def new_context(self, **kwargs):
        self._sink["contexts"] += 1
        return _FakeContext(self._sink, self._goto_script)

    async def close(self):
        self.closed = True
        self._sink["closed_args"].append(self.args)
        # 真实 Playwright 关浏览器会派发 disconnected —— 假浏览器必须照做，
        # 否则「回退时主动关掉的那台不该把会话收尾掉」这条根本没被测到。
        for handler in self._handlers:
            handler(self)


class _FakeChromium:
    def __init__(self, sink: dict, goto_script: list) -> None:
        self._sink = sink
        self._goto_script = goto_script

    async def launch(self, **kwargs):
        args = list(kwargs.get("args") or [])
        self._sink["launch_args"].append(args)
        browser = _FakeBrowser(self._sink, self._goto_script, args)
        self._sink["browsers"].append(browser)
        return browser


class _FakePlaywright2:
    def __init__(self, sink: dict, goto_script: list) -> None:
        self.chromium = _FakeChromium(sink, goto_script)

    async def stop(self):
        pass


def _fake_playwright2(sink: dict, goto_script: list):
    class _Starter:
        async def start(self):
            return _FakePlaywright2(sink, goto_script)

    return lambda: _Starter()


async def _run_start(tmp_path: Path, *, proxy_mode: str, goto_script: list,
                     auth_state: bool = False) -> tuple[CaptureSession, dict, Exception | None]:
    """跑一次完整的 ``start()``，返回 ``(session, sink, 抛出的异常或 None)``。

    ``auth_state=False`` 时用不存在的 auth_state 路径 → 状态是 authenticating，
    这样「第一次尝试是否被误当成在记录」这类问题不会掩盖真正的行为。
    """
    sink: dict = {"launch_args": [], "browsers": [], "closed_args": [], "gotos": [],
                  "pages": 0, "contexts": 0, "cdp_sessions": 0}
    state_path = tmp_path / "state.json"
    if auth_state:
        state_path.write_text("{}", encoding="utf-8")
    session = CaptureSession("s-fallback", URL, SessionStore(tmp_path), 262144, 300,
                             auth_state_path=str(state_path), proxy_mode=proxy_mode)
    error: Exception | None = None
    with patch("playwright.async_api.async_playwright", _fake_playwright2(sink, goto_script)):
        try:
            await session.start()
        except Exception as exc:                           # 失败路径也要能看状态
            error = exc
    return session, sink, error


async def _shutdown(session: CaptureSession) -> None:
    """收掉 start() 起的后台任务（别把它们留到下一个用例的事件循环里）。"""
    for name in ("writer_task", "idle_task", "login_task"):
        task = getattr(session, name, None)
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(BaseException):      # 含 asyncio.CancelledError
                await task


EMPTY_RESPONSE = RuntimeError("Error: Page.goto: net::ERR_EMPTY_RESPONSE at " + URL)
MISSING_KERNEL = RuntimeError("Executable doesn't exist at C:/ms-playwright/chrome.exe")


class TestAutoFallback:
    async def test_proxy_shaped_failure_falls_back_to_system_proxy(self, tmp_path):
        """核心：直连以代理类形态失败 → **自动**改用系统代理重试一次并成功。"""
        session, sink, error = await _run_start(tmp_path, proxy_mode="auto",
                                               goto_script=[EMPTY_RESPONSE, None])
        try:
            assert error is None, f"回退后应当成功，却仍失败：{error}"
            # (1) 真的换了模式：第一次带直连标志、第二次不带（= 跟随系统代理）
            assert len(sink["launch_args"]) == 2, "必须**只**回退一次"
            assert BUILTIN_DIRECT_ARG in sink["launch_args"][0]
            assert BUILTIN_DIRECT_ARG not in sink["launch_args"][1]
            # (2) 真正生效的模式被写回，且回退事实被记下来
            assert session.proxy_mode == "system"
            assert session.proxy_fallback["from"] == "auto"
            assert session.proxy_fallback["to"] == "system"
            assert "自动改用" in session.proxy_fallback["message"]
            assert "系统代理" in session.proxy_fallback["message"]
            # (3) 不留半开窗口 / 多余进程：旧的那台**被关掉**，当前那台还开着
            assert sink["browsers"][0].closed is True
            assert sink["browsers"][1].closed is False
            assert session.browser is sink["browsers"][1]
            # (4) 回退不能把会话收尾掉（旧浏览器 disconnected 事件同样会到 _on_browser_closed）
            await asyncio.sleep(0)
            assert session.status == "authenticating", \
                "回退时关掉旧浏览器被误当成「用户关了浏览器」，会话被自己收尾了"
            # (5) 不产生重复事件：登记表里只有重试后的那一份
            assert len(session.pages) == 1
            assert len(session.cdp_meta) == 1
            assert session.event_queue.empty()
            assert sink["pages"] == 2, "重试确实重建了页面"
        finally:
            await _shutdown(session)

    async def test_fallback_keeps_the_same_background_tasks(self, tmp_path):
        """生命周期：回退不另起 writer / login monitor（否则会有一堆任务抢着落盘）。"""
        session, _sink, error = await _run_start(tmp_path, proxy_mode="auto",
                                                 goto_script=[EMPTY_RESPONSE, None])
        try:
            assert error is None
            assert session.writer_task is not None
            assert session.login_task is not None
            writer, login = id(session.writer_task), id(session.login_task)
            await session._discard_browser()
            assert (id(session.writer_task), id(session.login_task)) == (writer, login)
        finally:
            await _shutdown(session)

    async def test_direct_success_does_not_retry_at_all(self, tmp_path):
        """直连就成功的场景**不得**多余重试（否则每次抓包都白开一次浏览器）。"""
        session, sink, error = await _run_start(tmp_path, proxy_mode="auto", goto_script=[None])
        try:
            assert error is None
            assert len(sink["launch_args"]) == 1
            assert sink["gotos"] == [URL], "只应导航一次"
            assert session.proxy_mode == "auto"
            assert session.proxy_fallback is None
            assert session.browser is sink["browsers"][0]
            assert sink["browsers"][0].closed is False
        finally:
            await _shutdown(session)

    async def test_explicit_direct_never_falls_back(self, tmp_path):
        """显式 `direct` 是手动控制：代理类失败也**不**偷偷改走系统代理。"""
        session, sink, error = await _run_start(tmp_path, proxy_mode="direct",
                                                goto_script=[EMPTY_RESPONSE])
        try:
            assert isinstance(error, BrowserNavigationError)
            assert len(sink["launch_args"]) == 1, "direct 模式不该回退"
            assert session.proxy_mode == "direct"
            assert session.proxy_fallback is None
        finally:
            await _shutdown(session)

    async def test_explicit_system_has_nothing_to_fall_back_to(self, tmp_path):
        session, sink, error = await _run_start(tmp_path, proxy_mode="system",
                                                goto_script=[EMPTY_RESPONSE])
        try:
            assert isinstance(error, BrowserNavigationError)
            assert len(sink["launch_args"]) == 1
            assert BUILTIN_DIRECT_ARG not in sink["launch_args"][0]
            assert session.proxy_mode == "system"
        finally:
            await _shutdown(session)

    async def test_non_proxy_failure_is_not_retried(self, tmp_path):
        """内核缺失之类的失败与代理无关：回退只会白等一个 goto 超时，不试。"""
        session, sink, error = await _run_start(tmp_path, proxy_mode="auto",
                                                goto_script=[MISSING_KERNEL])
        try:
            assert isinstance(error, BrowserNavigationError)
            assert error.failure_kind is None
            assert len(sink["launch_args"]) == 1
            assert session.proxy_fallback is None
        finally:
            await _shutdown(session)

    async def test_both_modes_failed_diagnosis_names_both_and_keeps_failing(self, tmp_path):
        """两次都失败 → 照旧失败，但诊断要说清试过哪两种模式、建议什么。"""
        session, sink, error = await _run_start(tmp_path, proxy_mode="auto",
                                                goto_script=[EMPTY_RESPONSE, EMPTY_RESPONSE])
        try:
            assert isinstance(error, BrowserNavigationError), "两次都失败必须照旧失败"
            assert len(sink["launch_args"]) == 2
            message = str(error)
            assert "ERR_EMPTY_RESPONSE" in message
            assert message.count("·") >= 2, f"两种模式各自的失败都要列出来：{message}"
            assert "直连" in message and "跟随系统代理" in message
            assert "不会反复重试" in message
            assert "普通浏览器" in message, "要给出可行动的排查建议"
            assert error.failure_kind == "possible"
        finally:
            await _shutdown(session)

    async def test_both_modes_failed_closes_every_browser(self, tmp_path):
        """两次都失败也不许留半开窗口（失败路径同样要收干净）。"""
        session, sink, error = await _run_start(tmp_path, proxy_mode="auto",
                                                goto_script=[EMPTY_RESPONSE, EMPTY_RESPONSE])
        try:
            assert isinstance(error, BrowserNavigationError)
            # 第一台由 _discard_browser 关掉；第二台留给调用侧（server._release_failed_capture
            # 在 status=failed 之后关）—— 这里模拟调用侧的收尾，确认也关得掉。
            session.status = "failed"
            await session.browser.close()
            await session.playwright.stop()
            assert [b.closed for b in sink["browsers"]] == [True, True]
        finally:
            await _shutdown(session)

    async def test_events_from_the_abandoned_attempt_are_not_recorded(self, tmp_path):
        """回退期间旧浏览器的在途事件不得落进 capture.jsonl（requestId 不跨实例）。"""
        session, _sink, error = await _run_start(tmp_path, proxy_mode="auto",
                                                 goto_script=[None], auth_state=True)
        try:
            assert error is None
            assert session.status == "capturing", "有 auth_state 时直接进入记录态"
            session._switching_proxy = True
            await session.emit({"type": "request", "requestId": "r-old"})
            assert session.event_queue.empty(), "换浏览器期间的事件必须被丢掉"
            session._switching_proxy = False
            await session.emit({"type": "request", "requestId": "r-new"})
            assert session.event_queue.qsize() == 1
        finally:
            await _shutdown(session)

    async def test_foreign_browser_close_does_not_end_the_session(self, tmp_path):
        """_on_browser_closed 只认**当前**那台：别的浏览器断开不算用户关了窗口。"""
        session, sink, error = await _run_start(tmp_path, proxy_mode="auto",
                                                goto_script=[None], auth_state=True)
        try:
            assert error is None
            await session._on_browser_closed(closed_browser=object())
            assert session.status == "capturing", "无关浏览器断开不该收尾"
            await session._on_browser_closed(closed_browser=sink["browsers"][0])
            assert session.status == "stopped", "当前那台断开仍必须自动收尾"
        finally:
            await _shutdown(session)


class TestCallerSideAutoFallbackNotice:
    async def test_response_tells_the_user_about_the_fallback(
            self, web, sessions_dir, monkeypatch):
        """自动回退**成功**时，start_capture 必须说出来（结构化字段 + 人话都要有）。"""
        async def _start(self):
            self.proxy_fallback = {
                "from": "auto", "to": "system",
                "message": auto_fallback_notice("auto", "system"),
            }

        monkeypatch.setattr(web.CaptureSession, "start", _start)

        result = await web.start_capture(URL, session_id="s-fallback-notice")

        assert result["status"] == "authenticating"
        assert result["proxy_fallback"] == {"from": "auto", "to": "system"}
        assert "自动改用" in result["message"]
        assert "系统代理" in result["message"]

    async def test_no_fallback_field_when_nothing_happened(
            self, web, sessions_dir, monkeypatch):
        """没回退就不许出现这个字段 —— 否则调用方会以为代理被换过。"""
        async def _start(self):
            pass

        monkeypatch.setattr(web.CaptureSession, "start", _start)

        result = await web.start_capture(URL, session_id="s-no-fallback")

        assert "proxy_fallback" not in result
        assert "自动改用" not in result["message"]
