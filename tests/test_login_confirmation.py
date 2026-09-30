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
import json
import textwrap
from pathlib import Path

import pytest

import scry_mcp_gen.auth as auth_module
from scry_mcp_gen import win_crypto
from scry_mcp_gen.auth import (
    LoginManager,
    LoginSession,
    http_login,
    read_auth_state_secrets,
)
from scry_mcp_gen.capture import CaptureSession

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
        import scry_mcp_gen.capture as capture_module

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


# --------------------------------------------------------------------------- #
# 4. 抓包环节的弹窗兜底：与 confirm_login_ready 等价，语义与登录环节一致
# --------------------------------------------------------------------------- #
def _capture(status: str = "authenticating") -> CaptureSession:
    session = CaptureSession("probe", URL, store=None, response_limit=1, idle_timeout=9999)
    session.status = status
    return session


def _patch_capture_dialog(monkeypatch, answer):
    """替换 CaptureSession._ask_native，返回调用记录（用于断言「没弹」）。"""
    calls = []

    def _fake(self):
        calls.append(1)
        return answer

    monkeypatch.setattr(CaptureSession, "_ask_native", _fake)
    return calls


class TestCaptureConfirmDialog:
    async def test_yes_starts_capturing(self, monkeypatch):
        session = _capture()
        _patch_capture_dialog(monkeypatch, True)

        result = await session.request_confirm_dialog()

        assert result["success"] is True
        assert result["confirmed"] is True
        assert session.status == "capturing"

    async def test_no_keeps_authenticating_and_is_reusable(self, monkeypatch):
        """「否」不丢弃：停在 authenticating，且可以再次请求弹出。"""
        session = _capture()
        _patch_capture_dialog(monkeypatch, False)

        first = await session.request_confirm_dialog()

        assert first["confirmed"] is False
        assert session.status == "authenticating"
        assert session.dialog_open is False, "必须复位，否则对话框再也弹不出来"

        _patch_capture_dialog(monkeypatch, True)
        second = await session.request_confirm_dialog()
        assert second["confirmed"] is True
        assert session.status == "capturing"

    async def test_refuses_when_not_authenticating(self, monkeypatch):
        session = _capture(status="capturing")
        calls = _patch_capture_dialog(monkeypatch, True)

        result = await session.request_confirm_dialog()

        assert result["success"] is False
        assert result["error"] == "not_authenticating"
        assert calls == [], "不该弹出必然变成死物的对话框"

    async def test_refuses_when_dialog_already_open(self, monkeypatch):
        session = _capture()
        session.dialog_open = True
        calls = _patch_capture_dialog(monkeypatch, True)

        result = await session.request_confirm_dialog()

        assert result["error"] == "dialog_already_open"
        assert calls == []

    async def test_dialog_unavailable_keeps_waiting_and_stays_reusable(self, monkeypatch):
        session = _capture()
        _patch_capture_dialog(monkeypatch, None)

        result = await session.request_confirm_dialog()

        assert result["error"] == "dialog_unavailable"
        assert session.status == "authenticating"
        assert session.dialog_open is False

    async def test_browser_closed_while_dialog_open_is_not_resurrected(self, monkeypatch):
        """对话框开着时用户直接关掉浏览器 → 不能把已收尾的会话翻回去记录。"""
        session = _capture()

        def _close_then_yes(self):
            session.status = "stopped"  # 模拟 _on_browser_closed 已收尾
            return True

        monkeypatch.setattr(CaptureSession, "_ask_native", _close_then_yes)

        result = await session.request_confirm_dialog()

        assert result["success"] is False
        assert result["error"] == "session_no_longer_authenticating"
        assert session.status == "stopped"


# --------------------------------------------------------------------------- #
# 5. 两份实现不得再次分叉
# --------------------------------------------------------------------------- #
class TestDialogIsShared:
    """登录与抓包必须共用 `dialog` 模块。

    上一轮的教训正在于此：`auth.py` 与 `capture.py` 各写了一份登录判定，
    Issue #20 只修了其中一份，另一份长期静默跑偏。平台相关的对话框代码同理，
    不许再复制第二份。
    """

    def test_both_sides_use_the_same_module(self):
        import scry_mcp_gen.auth as auth_module
        import scry_mcp_gen.capture as capture_module

        assert auth_module.dialog is capture_module.dialog

    def test_platform_code_lives_only_in_the_dialog_module(self):
        for cls in (LoginManager, CaptureSession):
            source = inspect.getsource(cls)
            assert "MessageBoxW" not in source, f"{cls.__name__} 不应内嵌平台实现"
            assert "tkinter" not in source, f"{cls.__name__} 不应内嵌平台实现"

    async def test_ask_yes_no_async_returns_the_thread_result(self, monkeypatch):
        from scry_mcp_gen import dialog

        monkeypatch.setattr(dialog, "ask_yes_no", lambda prompt, title=None: True)

        assert await dialog.ask_yes_no_async("x") is True

    async def test_run_blocking_does_not_block_the_event_loop(self):
        """阻塞函数必须跑在 daemon 线程上，事件循环要能继续调度。"""
        import time as _time

        from scry_mcp_gen import dialog

        ticks: list[int] = []

        async def ticker():
            for _ in range(3):
                await asyncio.sleep(0.02)
                ticks.append(1)

        task = asyncio.create_task(ticker())
        result = await dialog.run_blocking(lambda: (_time.sleep(0.08), "done")[1])
        await task

        assert result == "done"
        assert len(ticks) == 3, "阻塞期间事件循环被卡住了"


# --------------------------------------------------------------------------- #
# 6. 凭据落盘：DPAPI 密文（secrets_enc），不再写明文 password
# --------------------------------------------------------------------------- #
LOGIN_URL = "https://oa.example.com/api/login"
ACCOUNT = "alice"
PASSWORD = "Sup3r-Secret-Pw!"


class _FakeCookie:
    def __init__(self, name, value):
        self.name, self.value = name, value
        self.domain, self.path = HOST, "/"
        self.secure, self.expires = True, -1


class _FakeResponse:
    """`http_login` 只用到 status_code / url / text / json()。"""

    def __init__(self):
        self.status_code = 200
        self.url = LOGIN_URL
        self.text = ""  # 没有表单 → 不走表单分支

    def json(self):
        raise ValueError("not json")  # 与「响应不是 JSON」的真实情形一致


class _FakeHttpxClient:
    """POST **之后**服务端才下发凭据类 Cookie（loginToken）—— 真实登录成功的样子。

    修复前 loginToken 是**预置**在罐子里的（构造时就有），于是它落在 `http_login` 开头
    的 Cookie 基线内。那种写法只在「Cookie 罐非空就算登录成功」的旧判据下成立 ——
    而**登录页自己**就会下发 JSESSIONID，同一套判据会把失败的登录误判成 `post_ok`
    （详见 tests/test_login_mode.py 里新增的回归用例）。改成由 POST 下发，
    这个 fixture 描述的才是真实的成功路径。
    """

    def __init__(self, *args, **kwargs):
        self.jar: list = []          # 空罐起步：http_login 每次都新建 client
        self.cookies = type("_Jar", (), {"jar": self.jar})()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def get(self, *args, **kwargs):
        return _FakeResponse()

    async def post(self, *args, **kwargs):
        self.jar.append(_FakeCookie("loginToken", "tok-1"))   # 登录成功才下发
        return _FakeResponse()


@pytest.fixture
def login_env(monkeypatch, tmp_path):
    """把网络换成假客户端，并隔离模块级的内存凭据表（避免用例互相污染）。"""
    monkeypatch.setattr(auth_module.httpx, "AsyncClient", _FakeHttpxClient)
    monkeypatch.setattr(auth_module, "_MEMORY_SECRETS", {})
    state_dir = tmp_path / "auth_states"
    return state_dir


def _run_login(state_dir) -> tuple[dict, Path]:
    result = asyncio.run(http_login(LOGIN_URL, ACCOUNT, PASSWORD, state_dir))
    return result, Path(result["auth_state_path"])


def _legacy_state_file(state_dir: Path) -> Path:
    """旧版本写下的登录态：账号密码在明文 `secrets` 对象里。"""
    path = state_dir / "oa_example_com.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "site_key": "oa_example_com",
        "created_at": "2026-09-29T00:00:00+00:00",
        "secrets": {"username": ACCOUNT, "password": PASSWORD},
        "cookies": [{"name": "loginToken", "value": "tok-1", "domain": HOST, "path": "/"}],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


requires_dpapi = pytest.mark.skipif(not win_crypto.available(), reason="本机 DPAPI 不可用，跳过加密落盘用例")


class TestCredentialsAreEncryptedAtRest:
    """`http_login` 存下的账号密码必须是 DPAPI 密文，且能读回来。"""

    @requires_dpapi
    def test_password_never_appears_in_the_state_file(self, login_env):
        result, path = _run_login(login_env)
        raw = path.read_bytes()

        assert PASSWORD.encode("utf-8") not in raw, "密码明文落盘了"
        assert b'"username": "' + ACCOUNT.encode("utf-8") + b'"' not in raw, "账号仍是明文"
        assert b'"secrets"' not in raw, "旧的明文 secrets 字段仍在"
        assert b'"secrets_enc"' in raw, "应有 DPAPI 密文字段"
        assert result["secrets_persisted"] is True

    def test_storage_state_contract_is_unchanged(self, login_env):
        """同一个文件还要喂给 Playwright 当 storage_state，结构不能变。"""
        _, path = _run_login(login_env)
        state = json.loads(path.read_text(encoding="utf-8"))

        assert state["cookies"][0]["name"] == "loginToken"
        assert state["cookies"][0]["value"] == "tok-1"
        assert state["cookies_raw"] == {"loginToken": "tok-1"}
        assert state["site_key"] == path.stem, "_site_key 命名不变"

    @requires_dpapi
    def test_encrypted_secrets_round_trip(self, login_env):
        """加密只是手段：读回来必须与原始凭据逐字相同（本机可解）。"""
        _, path = _run_login(login_env)

        assert read_auth_state_secrets(path) == {"username": ACCOUNT, "password": PASSWORD}

    def test_legacy_plaintext_secrets_are_still_readable(self, login_env):
        """旧文件（明文 secrets）必须继续能读——升级不该让用户丢失凭据。"""
        path = _legacy_state_file(login_env)

        assert read_auth_state_secrets(path) == {"username": ACCOUNT, "password": PASSWORD}

    @requires_dpapi
    def test_legacy_plaintext_is_migrated_on_read(self, login_env):
        """读到旧文件时顺手迁移：密文落盘、明文从磁盘上消失，其余字段不动。"""
        path = _legacy_state_file(login_env)
        assert read_auth_state_secrets(path) == {"username": ACCOUNT, "password": PASSWORD}

        raw = path.read_bytes()
        assert PASSWORD.encode("utf-8") not in raw, "迁移后仍留有明文密码"
        assert b'"secrets":' not in raw, "迁移后仍留有明文 secrets 字段"
        state = json.loads(raw.decode("utf-8"))
        assert state["cookies"][0]["value"] == "tok-1", "迁移不得丢 Cookie"
        assert "secrets_enc" in state
        # 二次读走密文路径，仍然对得上
        assert read_auth_state_secrets(path) == {"username": ACCOUNT, "password": PASSWORD}

    def test_missing_or_broken_file_reads_as_none(self, login_env):
        """读不到 ≠ 崩掉：缺文件、坏 JSON 都只返回 None。"""
        assert read_auth_state_secrets(login_env / "nope.json") is None
        broken = login_env / "oa_example_com.json"
        broken.parent.mkdir(parents=True, exist_ok=True)
        broken.write_text("{not json", encoding="utf-8")
        assert read_auth_state_secrets(broken) is None

    def test_dpapi_unavailable_does_not_write_plaintext(self, login_env, monkeypatch):
        """DPAPI 不可用：宁可不保存，也不明文落盘；且必须如实告知。"""
        monkeypatch.setattr(win_crypto, "available", lambda: False)

        result, path = _run_login(login_env)
        raw = path.read_bytes()

        assert PASSWORD.encode("utf-8") not in raw, "降级路径写出了明文密码"
        assert b'"secrets' not in raw, "不该有 secrets / secrets_enc 任何字段"
        assert result["success"] is True, "Cookie 已拿到，登录本身不该被判失败"
        assert result["secrets_persisted"] is False
        assert result["warning"] == "secrets_not_persisted", "必须把「没保存」明确回报给调用方"
        assert "message" in result
        # 能力保留在内存里（本次会话仍可用），只是没落盘
        assert read_auth_state_secrets(path) == {"username": ACCOUNT, "password": PASSWORD}

    def test_encryption_failure_does_not_write_plaintext(self, login_env, monkeypatch):
        """加密报错（而非平台不可用）：同样不得明文落盘。"""
        monkeypatch.setattr(win_crypto, "available", lambda: True)

        def _boom(_data):
            raise win_crypto.DPAPIError("模拟加密失败")

        monkeypatch.setattr(win_crypto, "protect", _boom)

        result, path = _run_login(login_env)
        raw = path.read_bytes()

        assert PASSWORD.encode("utf-8") not in raw
        assert b'"secrets' not in raw
        assert result["secrets_persisted"] is False
        assert result["warning"] == "secrets_not_persisted"
        assert "DPAPIError" in result["message"], "原因要写清楚，便于排查"

    def test_http_login_source_has_no_plaintext_secrets_write(self):
        """结构性守卫：`http_login` 里不得再出现写入明文凭据的赋值。"""
        source = inspect.getsource(http_login) + inspect.getsource(auth_module._store_secrets)
        assert '"secrets": {"username": username, "password": password}' not in source
        assert auth_module._SECRETS_ENC_FIELD in source
