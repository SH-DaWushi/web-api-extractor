# -*- coding: utf-8 -*-
"""登录完成必须由用户确认——不得自动判定。

修复前的两个症状是同一个设计缺陷的两半：

1. **Agent 自己往下跑**：`auth.py::_run()` 与 `capture.py::_login_monitor()` 是
   两份各自独立的判定实现。Issue #20 只给 `auth.py` 加了 Cookie 基线比对，
   `capture.py` 那份从未同步——它只要目标域出现名字含 token/session/sid/auth 的
   Cookie 就放行，而登录页**自己就会设** JSESSIONID / PHPSESSID。
   于是 `start_capture` 后约 6 秒（用户还在输密码）会话就翻成 capturing，
   Agent 轮询到 capturing 便以为可以往下走。

2. **确认框闲置无用**：`_spawn_native_confirm()` 在浏览器**刚打开**时就弹
   （用户还没登录，多半点「否」），且只处理「是」；点「否」不改变任何状态、
   对话框**再也不会出现**。

本文件锁住修复后的契约：
    * 有凭据旁证也不自动放行（auth 与 capture 两侧都测）；
    * 只有显式确认才翻转状态；
    * 对话框按需弹出、「否」不丢弃且可重复弹出、非等待态拒绝弹出。
"""
from __future__ import annotations

import asyncio
import ast
import inspect
import textwrap
from pathlib import Path

import pytest

from webapi_extractor.auth import LoginManager, LoginSession
from webapi_extractor.capture import CaptureSession

URL = "https://oa.example.com/login/login.jsp"
HOST = "oa.example.com"
SESSION_ID = "login_test"

# 登录页自己就会设的会话 Cookie —— 修复前正是它触发了自动放行。
PRE_AUTH = [
    {"name": "JSESSIONID", "value": "BBB222", "domain": HOST, "path": "/"},
    {"name": "PHPSESSID", "value": "AAA111", "domain": HOST, "path": "/"},
]


class _FakeContext:
    def __init__(self, cookies):
        self._cookies = cookies

    async def cookies(self):
        return self._cookies


# --------------------------------------------------------------------------- #
# 1. auth.py：旁证不驱动状态，只有确认才放行
# --------------------------------------------------------------------------- #
@pytest.fixture
def manager():
    return LoginManager(Path("."))


def _waiting_session(manager) -> LoginSession:
    record = LoginSession(SESSION_ID, URL, 300, Path("."))
    manager.sessions[SESSION_ID] = record
    return record


class TestEvidenceDoesNotCompleteTheLogin:
    async def test_evidence_alone_leaves_session_waiting(self, manager):
        """核心回归：即使观察到凭据旁证，状态也必须停在 waiting。"""
        record = _waiting_session(manager)
        record.auth_evidence = True  # 模拟 _run 的观察结果

        result = manager.status(SESSION_ID)

        assert result["status"] == "waiting", "旁证不得自动放行"
        assert result["auth_evidence"] is True, "旁证仍应上报给 Agent"

    def test_run_never_sets_completed(self):
        """结构性守卫：_run() 里不得出现任何把状态置为 completed 的赋值。

        完成只能来自 confirm() 或 request_confirm_dialog()（显式确认）。
        """
        source = inspect.getsource(LoginManager._run)
        assert 'record.status = "completed"' not in source
        assert "record.auth_evidence = " in source, "旁证应被记录（供上报）"

    def test_run_never_pops_the_dialog_on_its_own(self):
        """对话框只能在调用方请求时弹出，不能由 _run() 自行弹出。"""
        source = inspect.getsource(LoginManager._run)
        assert "_ask_native" not in source
        assert "request_confirm_dialog" not in source
        assert not hasattr(LoginManager, "_spawn_native_confirm"), "旧的一次性弹窗应已移除"

    async def test_open_promises_no_automatic_completion(self, manager, monkeypatch):
        """open() 的提示必须让 Agent 等用户确认，而不是声称会自动判定。"""

        async def _noop(self, record):  # 不真发浏览器，只验证返回值
            return None

        monkeypatch.setattr(LoginManager, "_run", _noop)
        result = await manager.open(URL)
        await asyncio.sleep(0)  # 让 create_task 起的任务收尾，避免悬空任务告警

        assert result["status"] == "waiting"
        assert "confirm_login" in result["message"]
        assert "自动放行" in result["message"], "必须明确说明不会自动放行"


class TestConfirmFlipsTheStatus:
    def test_confirm_completes_a_waiting_session(self, manager):
        _waiting_session(manager)

        result = manager.confirm(SESSION_ID)

        assert result["success"] is True
        assert result["status"] == "completed"
        assert manager.status(SESSION_ID)["status"] == "completed"

    def test_confirm_warns_when_no_credential_evidence(self, manager):
        """用户说登录好了却没观察到凭据 → 存下的登录态可能是未认证的，必须提示。"""
        _waiting_session(manager)

        result = manager.confirm(SESSION_ID)

        assert result.get("warning") == "no_credential_evidence"
        assert "message" in result

    def test_confirm_is_quiet_when_evidence_present(self, manager):
        record = _waiting_session(manager)
        record.auth_evidence = True

        assert "warning" not in manager.confirm(SESSION_ID)

    def test_confirm_rejects_a_finished_session(self, manager):
        record = _waiting_session(manager)
        record.status = "timeout_failed"

        result = manager.confirm(SESSION_ID)

        assert result["success"] is False
        assert result["error"] == "not_waiting"


# --------------------------------------------------------------------------- #
# 2. 确认对话框：按需、可重复、「否」不丢弃
# --------------------------------------------------------------------------- #
class TestConfirmDialog:
    def _no_dialog(self, monkeypatch, answer):
        calls = []

        def _fake(self):
            calls.append(1)
            return answer

        monkeypatch.setattr(LoginManager, "_ask_native", _fake)
        return calls

    def test_yes_completes_the_session(self, manager, monkeypatch):
        _waiting_session(manager)
        self._no_dialog(monkeypatch, True)

        result = asyncio.run(manager.request_confirm_dialog(SESSION_ID))

        assert result["success"] is True
        assert result["confirmed"] is True
        assert manager.status(SESSION_ID)["status"] == "completed"

    def test_no_keeps_waiting_and_clears_the_dialog_flag(self, manager, monkeypatch):
        """「否」不得被丢弃：会话继续等待，且允许再次请求弹出。"""
        _waiting_session(manager)
        self._no_dialog(monkeypatch, False)

        result = asyncio.run(manager.request_confirm_dialog(SESSION_ID))

        assert result["success"] is True
        assert result["confirmed"] is False
        status = manager.status(SESSION_ID)
        assert status["status"] == "waiting", "点「否」后必须还在等待"
        assert status["dialog_open"] is False, "必须复位，否则对话框再也弹不出来"

    def test_dialog_can_be_requested_again_after_a_no(self, manager, monkeypatch):
        """可重复弹出：先「否」，再「是」。"""
        _waiting_session(manager)

        self._no_dialog(monkeypatch, False)
        assert asyncio.run(manager.request_confirm_dialog(SESSION_ID))["confirmed"] is False

        self._no_dialog(monkeypatch, True)
        assert asyncio.run(manager.request_confirm_dialog(SESSION_ID))["confirmed"] is True
        assert manager.status(SESSION_ID)["status"] == "completed"

    def test_refuses_to_pop_a_dialog_for_a_finished_session(self, manager, monkeypatch):
        """会话已结束还弹窗 → 必然变成死物，直接拒绝，且不要真的弹。"""
        record = _waiting_session(manager)
        record.status = "timeout_failed"
        calls = self._no_dialog(monkeypatch, True)

        result = asyncio.run(manager.request_confirm_dialog(SESSION_ID))

        assert result["success"] is False
        assert result["error"] == "not_waiting"
        assert calls == [], "已结束的会话不应弹出对话框"

    def test_refuses_when_a_dialog_is_already_open(self, manager, monkeypatch):
        record = _waiting_session(manager)
        record.dialog_open = True
        calls = self._no_dialog(monkeypatch, True)

        result = asyncio.run(manager.request_confirm_dialog(SESSION_ID))

        assert result["success"] is False
        assert result["error"] == "dialog_already_open"
        assert calls == []

    def test_dialog_unavailable_keeps_waiting_and_stays_reusable(self, manager, monkeypatch):
        """无图形环境（返回 None）→ 不改变状态，也不许把标志位卡住。"""
        _waiting_session(manager)
        self._no_dialog(monkeypatch, None)

        result = asyncio.run(manager.request_confirm_dialog(SESSION_ID))

        assert result["success"] is False
        assert result["error"] == "dialog_unavailable"
        status = manager.status(SESSION_ID)
        assert status["status"] == "waiting"
        assert status["dialog_open"] is False

    def test_unknown_session_is_rejected(self, manager):
        result = asyncio.run(manager.request_confirm_dialog("login_nope"))

        assert result["success"] is False
        assert result["error"] == "login_session_not_found"


# --------------------------------------------------------------------------- #
# 3. capture.py：登录页的会话 Cookie 不再自动开抓
# --------------------------------------------------------------------------- #
class _StopMonitor(Exception):
    """哨兵：用来跳出 _login_monitor 的轮询循环。

    循环条件是 `while self.status == "authenticating"`，所以不能靠改 status 来退出
    ——那正是被测对象要断言的状态。`await asyncio.sleep(1)` 不在任何 try 里，
    从这里抛出会直接穿出协程。
    """


class _CountingSleep:
    """替换 capture 模块里的 `asyncio.sleep`：立即返回，计满 limit 次后抛哨兵。

    原实现是「证据连续稳定 5 秒就放行」，所以轮询 200 次（≙ 原节奏下 200 秒）
    远超旧阈值——若还有任何自动放行的代码路径，这里必然会翻。
    """

    def __init__(self, limit=200):
        self.limit = limit
        self.calls = 0

    async def __call__(self, _seconds):
        self.calls += 1
        if self.calls >= self.limit:
            raise _StopMonitor
        await asyncio.sleep(0)  # 真实睡眠，避免饿死事件循环


class _AsyncioShim:
    """只替 `capture` 模块提供 `sleep`。

    故意不 monkeypatch 全局 `asyncio.sleep`：那会连测试自己的 `await asyncio.sleep(0)`
    一起换掉，直接自递归。
    """

    def __init__(self, sleeper):
        self.sleep = sleeper


class _TimeShim:
    """假时钟：每次读 `monotonic()` 前进 1 秒。

    没有它这个测试就没有判别力——sleep 桩立刻返回，真实耗时≈0，
    而旧实现的放行条件是「证据连续稳定 **5 秒**」，在旧代码上照样不会触发，
    测试会假通过。有了假时钟，旧实现会在几次轮询内就翻，新实现永远不翻。
    """

    def __init__(self, step=1.0):
        self.step = step
        self.now = 0.0

    def monotonic(self):
        self.now += self.step
        return self.now


class TestCaptureDoesNotAutoStart:
    async def _run_monitor(self, monkeypatch, cookies):
        """跑 _login_monitor，返回 (session, enter_capturing 调用次数, 轮询计数器)。"""
        import webapi_extractor.capture as capture_module

        session = CaptureSession("probe", URL, store=None, response_limit=1, idle_timeout=9999)
        session.context = _FakeContext(cookies)
        flips = []
        real_enter = CaptureSession._enter_capturing

        async def _record_flip():
            # 记录调用的同时仍走真实实现，这样「被调用过」与「状态翻转」都能观察到。
            flips.append(1)
            await real_enter(session)

        monkeypatch.setattr(session, "_enter_capturing", _record_flip)
        sleeper = _CountingSleep()
        monkeypatch.setattr(capture_module, "asyncio", _AsyncioShim(sleeper))
        monkeypatch.setattr(capture_module, "time", _TimeShim())

        try:
            await session._login_monitor()
        except _StopMonitor:
            pass  # 跑满预定轮询次数后主动跳出
        return session, flips, sleeper

    async def test_login_page_cookies_do_not_start_capture(self, monkeypatch):
        """核心回归：登录页自设的会话 Cookie 不得让会话自动翻成 capturing。"""
        session, flips, sleeper = await self._run_monitor(monkeypatch, PRE_AUTH)

        assert sleeper.calls >= 200, "应跑满设定的轮询次数"
        assert flips == [], "绝不能自动开始记录"
        assert session.status == "authenticating", "必须停在 authenticating，等用户确认"
        assert session.auth_evidence is True, "旁证仍应上报（供 Agent 提示用户确认）"

    async def test_a_new_token_cookie_does_not_start_capture_either(self, monkeypatch):
        """即便是登录后才出现的 token Cookie，也只作旁证，不自动放行。"""
        cookies = PRE_AUTH + [{"name": "loginToken", "value": "tok-1", "domain": HOST, "path": "/"}]

        session, flips, _ = await self._run_monitor(monkeypatch, cookies)

        assert flips == []
        assert session.status == "authenticating"
        assert session.auth_evidence is True

    def test_monitor_source_never_calls_enter_capturing(self):
        """结构性守卫：监视器里不得出现自动放行调用。

        按 AST 取属性名来判断，而不是对源码做子串匹配——docstring 里为了说明
        历史会提到 `_enter_capturing()`，那是叙述，不是调用。
        """
        tree = ast.parse(textwrap.dedent(inspect.getsource(CaptureSession._login_monitor)))
        attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}

        assert "_enter_capturing" not in attributes
        assert "mark_auth_ready" not in attributes

    async def test_explicit_confirmation_is_what_starts_capture(self, monkeypatch):
        """显式确认（confirm_login_ready 走的就是这个）才允许开始记录。"""
        session, _, _ = await self._run_monitor(monkeypatch, PRE_AUTH)
        assert session.status == "authenticating", "确认之前必须一直停在 authenticating"

        await session._enter_capturing()  # 用户确认的时刻

        assert session.status == "capturing"

    async def test_metadata_reports_evidence(self, monkeypatch):
        session, _, _ = await self._run_monitor(monkeypatch, PRE_AUTH)

        assert session.metadata()["auth_evidence"] is True
