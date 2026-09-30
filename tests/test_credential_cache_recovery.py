# -*- coding: utf-8 -*-
"""「一次输入」与「缓存解不开」的出路 —— 全部面向**完全不懂 HTTP 的用户**。

产品口径：生成的服务是给「不会 Coding、不看日志」的人用的，所以凭据这一环必须
做到两件事：

1. **一次输入**：无参数调用 `login()` 时在**本机弹窗**问一次账号 + 掩码密码，
   口令不进对话、不进日志、不进任何返回值；弹不出窗口（无图形环境）才降级为
   「在对话里告诉我账号密码」。不新增工具，`login` 仍是同一个工具。
2. **解不开要说人话**：`cred_cache.bin` 存在但解不开（换电脑 / 换 Windows 用户）
   与「还没登录过」是两件出路完全不同的事，必须能区分，并直接给出那句照做就行
   的话 ——「删掉项目里的 `cred_cache.bin`，再登录一次」。

本文件同时守住一条**逐字节护栏**：把缓存的诊断逻辑放进 `auth_login` 条件分支，
没有登录接口的产物不受影响（金标准另外 10 条良性语料逐字节不变）。
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import pytest

from scry_mcp_gen import auth as auth_module
from scry_mcp_gen import win_crypto
from scry_mcp_gen.auth import (
    LoginManager,
    _merge_encrypted_secrets,
    _preserve_encrypted_secrets,
    _site_key,
    read_auth_state_secrets,
)
from scry_mcp_gen.generator import render_server

HOST = "portal.example.com"
ACCOUNT = "alice"
PASSWORD = "s3cret-Pa55"
LOGIN_PATH = "/api/login"


# --------------------------------------------------------------------------- #
# 生成物：夹具
# --------------------------------------------------------------------------- #
def _registry(auth_login: bool = True) -> dict:
    registry = {
        "site_name": "portal",
        "registry_version": 1,
        "hosts": {HOST: {"scheme": "Cookie", "cookie_names": ["JSESSIONID"]}},
        "endpoints": [{
            "tool_name": "get_todo", "method": "GET", "host": HOST,
            "path": "/api/todo", "description": "待办",
            "status": "active", "auth_required": True,
        }],
    }
    if auth_login:
        registry["auth_login"] = {
            "method": "POST", "host": HOST, "path": LOGIN_PATH,
            "account_field": "username", "password_field": "password",
            "token_path": ["data", "token"], "query_params": {},
        }
    return registry


def _server_source(auth_login: bool = True) -> str:
    return render_server(_registry(auth_login))["server.py"]


def _load_generated(tmp_path: Path, auth_login: bool = True) -> dict:
    """把生成物当模块执行，得到真实的函数对象（不连网、不起服务）。

    `__file__` 指向临时目录，于是生成物自己的 `_HERE`（缓存、error.log、.env 的
    落点）都在 tmp_path 里 —— 既不会碰到仓库的 `.env`，也让「缓存解不开」可以用
    「往 cred_cache.bin 里写一段垃圾」真实复现，而不是 monkeypatch 掉判据。
    """
    source = _server_source(auth_login)
    namespace: dict = {"__name__": "generated_server",
                       "__file__": str(tmp_path / "server.py")}
    exec(compile(source, "server.py", "exec"), namespace)  # noqa: S102 —— 生成物本就是被测对象
    return namespace


def _make_cache_unreadable(tmp_path: Path) -> Path:
    """写一个「在、但解不开」的 cred_cache.bin（换电脑/换用户后的真实形态）。"""
    path = tmp_path / "cred_cache.bin"
    path.write_text("not-a-valid-dpapi-blob", encoding="ascii")
    return path


def _clear_env(monkeypatch) -> None:
    monkeypatch.delenv("PORTAL_ACCOUNT", raising=False)
    monkeypatch.delenv("PORTAL_PASSWORD", raising=False)
    monkeypatch.delenv("PORTAL_TOKEN", raising=False)


# --------------------------------------------------------------------------- #
# 生成物：缓存状态可区分
# --------------------------------------------------------------------------- #
class TestCacheStateIsDistinguishable:
    """`_cache_probe` 必须把「文件不在」与「文件在却解不开」分开。"""

    def test_probe_reports_missing_for_absent_file(self, tmp_path):
        ns = _load_generated(tmp_path)
        assert ns["_cache_probe"](tmp_path / "nope.bin") == "missing"

    def test_probe_reports_unreadable_for_garbage(self, tmp_path):
        _make_cache_unreadable(tmp_path)
        ns = _load_generated(tmp_path)
        assert ns["_cache_probe"](tmp_path / "cred_cache.bin") == "unreadable"

    def test_probe_never_raises_on_binary_junk(self, tmp_path):
        (tmp_path / "cred_cache.bin").write_bytes(b"\x00\x01\x02\xff")
        ns = _load_generated(tmp_path)
        assert ns["_cache_probe"](tmp_path / "cred_cache.bin") == "unreadable"

    def test_cache_load_still_swallows_errors(self, tmp_path):
        """既有约定不变：`_cache_load` 读不到照样返回 None，不抛异常。"""
        _make_cache_unreadable(tmp_path)
        ns = _load_generated(tmp_path)
        assert ns["_cache_load"](tmp_path / "cred_cache.bin") is None


# --------------------------------------------------------------------------- #
# 生成物：无参 login() 弹窗问一次
# --------------------------------------------------------------------------- #
class TestLoginAsksOnceWithAMaskedDialog:
    def test_dialog_masks_the_password(self, tmp_path):
        source = _server_source()
        assert "show='*'" in source, "密码框必须掩码"
        # 掩码输入 + 只走内存：口令不得写进日志/审计/返回体。
        assert "_ask_credentials_native" in source
        assert "daemon=True" in source, "弹窗必须跑在守护线程上，用户不作答也不能拖住退出"

    def test_no_argument_login_uses_the_dialog(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        ns = _load_generated(tmp_path)
        seen: dict = {}

        async def _fake_do_login(account, password):
            seen["account"], seen["password"] = account, password
            return {"success": True, "account": "a***",
                    "token_cache": "saved", "credential_cache": "saved"}

        ns["_do_login"] = _fake_do_login

        async def _fake_run_native(function):
            seen["asked"] = function
            return (ACCOUNT, PASSWORD)

        ns["_run_native"] = _fake_run_native
        result = asyncio.run(ns["login"]())

        assert seen.get("asked") is ns["_ask_credentials_native"], "无参 login() 必须先弹窗问一次"
        assert seen["account"] == ACCOUNT
        assert result["success"] is True
        assert PASSWORD not in json.dumps(result, ensure_ascii=False), "返回体绝不能出现口令"

    def test_dialog_is_not_popped_when_credentials_are_given(self, tmp_path, monkeypatch):
        """带了参就别弹窗 —— 弹窗打断用户，能不问就不问。"""
        _clear_env(monkeypatch)
        ns = _load_generated(tmp_path)
        calls: list = []

        async def _fake_do_login(account, password):
            return {"success": True, "account": "a***"}

        async def _fake_run_native(function):  # pragma: no cover —— 不该被调用
            calls.append(function)
            return (ACCOUNT, PASSWORD)

        ns["_do_login"] = _fake_do_login
        ns["_run_native"] = _fake_run_native
        asyncio.run(ns["login"](ACCOUNT, PASSWORD))

        assert calls == []

    def test_cached_credentials_skip_the_dialog(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        ns = _load_generated(tmp_path)
        calls: list = []
        ns["_cached_credentials"] = lambda: (ACCOUNT, PASSWORD)

        async def _fake_do_login(account, password):
            return {"success": True, "account": "a***"}

        async def _fake_run_native(function):  # pragma: no cover —— 不该被调用
            calls.append(function)
            return (ACCOUNT, PASSWORD)

        ns["_do_login"] = _fake_do_login
        ns["_run_native"] = _fake_run_native
        asyncio.run(ns["login"]())

        assert calls == [], "已有可用缓存时不该再问用户"

    def test_dialog_returns_none_without_tkinter(self, tmp_path, monkeypatch):
        """无图形环境（没装 tkinter）→ 返回 None，由调用方降级为「在对话里问」。"""
        ns = _load_generated(tmp_path)
        monkeypatch.setitem(__import__("sys").modules, "tkinter", None)

        assert ns["_ask_credentials_native"]() is None

    def test_docstring_tells_the_agent_to_ask_first(self, tmp_path):
        ns = _load_generated(tmp_path)
        doc = ns["login"].__doc__ or ""
        assert "弹窗" in doc or "输入窗口" in doc
        assert "征得用户同意" in doc, "弹窗会打断用户，必须先问"
        assert "missing_credentials" in doc, "弹不出窗口时的降级路径要写清楚"

    def test_tool_count_is_unchanged(self, tmp_path):
        """绝不能为了「一次输入」新增工具。"""
        source = _server_source()
        assert source.count("@mcp.tool()") == 5  # 1 业务 + login + auth_status + 2 诊断


# --------------------------------------------------------------------------- #
# 生成物：解不开 → 说人话（删 cred_cache.bin 再登一次）
# --------------------------------------------------------------------------- #
class TestUnreadableCacheGivesAnActionableWayOut:
    RESET = "删掉项目里的"

    def test_unreadable_cache_names_the_reset_path(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        _make_cache_unreadable(tmp_path)
        ns = _load_generated(tmp_path)

        async def _fake_run_native(function):
            return None  # 弹不出窗口（无图形环境）

        ns["_run_native"] = _fake_run_native
        result = asyncio.run(ns["login"]())

        assert result["success"] is False
        assert result["error"] == "missing_credentials"
        assert result["credentials_cache_state"] == "unreadable"
        assert "cred_cache.bin" in result["message"]
        assert self.RESET in result["message"] and "登录一次" in result["message"]

    def test_missing_cache_says_how_to_fall_back_to_chat(self, tmp_path, monkeypatch):
        """没缓存 ≠ 解不开：这时不该吓唬用户「删文件」，只说怎么继续。"""
        _clear_env(monkeypatch)
        ns = _load_generated(tmp_path)

        async def _fake_run_native(function):
            return None

        ns["_run_native"] = _fake_run_native
        result = asyncio.run(ns["login"]())

        assert result["credentials_cache_state"] == "missing"
        assert self.RESET not in result["message"]
        assert "对话" in result["message"], "降级路径必须是「在对话里告诉我账号密码」"

    def test_auth_status_reports_the_state_and_hint(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        _make_cache_unreadable(tmp_path)
        (tmp_path / "token_cache.bin").write_text("junk", encoding="ascii")
        ns = _load_generated(tmp_path)

        info = asyncio.run(ns["auth_status"]())

        assert info["credentials_cache_state"] == "unreadable"
        assert info["credentials_cached_encrypted"] is False
        assert info["token_cache_state"] == "unreadable"
        assert "cred_cache.bin" in info["credentials_cache_hint"]
        assert self.RESET in info["credentials_cache_hint"]
        # 无 token 时依旧如实回答「没验证」，不谎称 verified。
        assert info["verified"] is None

    def test_auth_status_is_quiet_on_a_healthy_missing_cache(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        ns = _load_generated(tmp_path)

        info = asyncio.run(ns["auth_status"]())

        assert info["credentials_cache_state"] == "missing"
        assert "credentials_cache_hint" not in info

    def test_401_error_carries_the_same_way_out(self, tmp_path):
        ns = _load_generated(tmp_path)
        source = _server_source()
        assert "hint += _login_recovery_hint()" in source, "401 报错里也要给出下一步"

        _make_cache_unreadable(tmp_path)
        hint = ns["_login_recovery_hint"]()
        assert "cred_cache.bin" in hint
        assert self.RESET in hint and "登录一次" in hint

    def test_401_hint_talks_about_a_changed_password_too(self, tmp_path):
        """缓存好好的但登录还是失败 → 多半是口令被改；这时出路是「重新登录一次」。"""
        ns = _load_generated(tmp_path)
        hint = ns["_login_recovery_hint"]()

        assert "login()" in hint
        assert "cred_cache.bin" not in hint

    def test_recovery_code_is_absent_without_a_login_endpoint(self, tmp_path):
        """逐字节护栏：没有登录接口的产物里不该有这套诊断代码。"""
        source = _server_source(auth_login=False)
        assert "_cache_probe" not in source
        assert "_login_recovery_hint" not in source
        assert "_ask_credentials_native" not in source
        assert "hint += _login_recovery_hint()" not in source


# --------------------------------------------------------------------------- #
# 生成物：.env 明文只提示、绝不代改
# --------------------------------------------------------------------------- #
class TestPlaintextEnvIsOnlyACompatibilityPath:
    def test_notice_is_emitted_once_login_succeeds(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PORTAL_ACCOUNT", ACCOUNT)
        monkeypatch.setenv("PORTAL_PASSWORD", PASSWORD)
        ns = _load_generated(tmp_path)

        async def _fake_do_login(account, password):
            assert account == ACCOUNT and password == PASSWORD, "仍要能读 .env（兼容通道）"
            return {"success": True, "account": "a***"}

        ns["_do_login"] = _fake_do_login
        result = asyncio.run(ns["login"]())

        assert result["success"] is True
        notice = result["plaintext_env_notice"]
        assert "PORTAL_ACCOUNT" in notice and "PORTAL_PASSWORD" in notice
        assert "删掉" in notice
        assert notice in result["message"], "提示必须可见（非阻塞，但要说出来）"

    def test_the_env_file_is_never_written(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PORTAL_ACCOUNT", ACCOUNT)
        monkeypatch.setenv("PORTAL_PASSWORD", PASSWORD)
        ns = _load_generated(tmp_path)

        async def _fake_do_login(account, password):
            return {"success": True, "account": "a***"}

        ns["_do_login"] = _fake_do_login
        asyncio.run(ns["login"]())

        assert not (tmp_path / ".env").exists(), "绝不代改（更不代建）用户的 .env"
        assert ".env" not in render_server(_registry()), "生成器不写真实 .env，只写 .env.example"

    def test_no_notice_without_plaintext_env(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        ns = _load_generated(tmp_path)

        async def _fake_do_login(account, password):
            return {"success": True, "account": "a***"}

        ns["_do_login"] = _fake_do_login
        result = asyncio.run(ns["login"](ACCOUNT, PASSWORD))

        assert "plaintext_env_notice" not in result

    def test_env_example_no_longer_recommends_plaintext(self):
        files = render_server(_registry())
        env_example = files[".env.example"]
        # 账号密码那一段必须写明「推荐留空」+ 明文是兼容/应急通道，不能再自称推荐。
        block = env_example[env_example.index("# 账号密码登录"):]
        block = block[:block.index("_ACCOUNT=")]
        assert "推荐" in block and "留空" in block
        assert "兼容" in block and "明文" in block
        assert not re.search(r"^# 账号密码登录（推荐：?(在|填)", block, re.M)

        readme = files["README.md"]
        assert "环境变量**（推荐）" not in readme
        assert "环境变量（推荐）" not in readme
        assert re.search(r"调用一次 `login\(\)`", readme)
        assert "删掉项目里的" in readme and "cred_cache.bin" in readme


# --------------------------------------------------------------------------- #
# 技能侧：open_browser_login 不再抹掉加密凭据（残留②）
# --------------------------------------------------------------------------- #
class _FakePage:
    def __init__(self, url: str) -> None:
        self.url = url

    async def goto(self, *args, **kwargs) -> None:
        return None

    async def wait_for_timeout(self, *args, **kwargs) -> None:
        return None


class _FakeContext:
    """只实现 `_run` 用到的四个口子：cookies / new_page / storage_state / 关闭。"""

    def __init__(self, url: str, sink: dict) -> None:
        self._url = url
        self._sink = sink
        self._page = _FakePage(url)

    async def cookies(self) -> list:
        return [{"name": "loginToken", "value": "tok-1",
                 "domain": HOST, "path": "/"}]

    async def new_page(self) -> _FakePage:
        return self._page

    async def storage_state(self, path: str | None = None) -> None:
        """复刻 Playwright 的真实行为：**整体覆盖**文件，只写 cookies / origins。"""
        self._sink["path"] = path
        Path(path).write_text(json.dumps({
            "cookies": [{"name": "loginToken", "value": "tok-1",
                         "domain": HOST, "path": "/"}],
            "origins": [],
        }, ensure_ascii=False), encoding="utf-8")


class _FakeBrowser:
    def __init__(self, url: str, sink: dict) -> None:
        self._url, self._sink = url, sink

    async def new_context(self, **kwargs) -> _FakeContext:
        return _FakeContext(self._url, self._sink)

    async def close(self) -> None:
        return None


class _FakeChromium:
    def __init__(self, url: str, sink: dict) -> None:
        self._url, self._sink = url, sink

    async def launch(self, **kwargs) -> _FakeBrowser:
        return _FakeBrowser(self._url, self._sink)


class _FakePlaywright:
    def __init__(self, url: str, sink: dict) -> None:
        self._url, self._sink = url, sink

    async def __aenter__(self) -> _FakePlaywright:
        return self

    async def __aexit__(self, *exc) -> bool:
        return False

    @property
    def chromium(self) -> _FakeChromium:
        return _FakeChromium(self._url, self._sink)


def _install_fake_playwright(monkeypatch, url: str) -> dict:
    sink: dict = {}
    monkeypatch.setattr("playwright.async_api.async_playwright",
                        lambda: _FakePlaywright(url, sink))
    return sink


requires_dpapi = pytest.mark.skipif(
    not win_crypto.available(), reason="本机 DPAPI 不可用，跳过加密凭据用例")


@requires_dpapi
def test_browser_login_keeps_encrypted_credentials(monkeypatch, tmp_path):
    """真实驱动 `LoginManager._run`：storage_state 覆盖后，secrets_enc 必须还在。

    修复前是「浏览器走一遍 → `http_login` 存的加密凭据被整体覆盖抹掉」，用户下次
    想复用账号密码还得重输 —— 这就是文档里承认过的残留②。
    """
    url = f"https://{HOST}/"
    state_dir = tmp_path / "auth_states"
    state_dir.mkdir()
    state_path = state_dir / f"{_site_key(url)}.json"
    # 先由 http_login 写入加密凭据（只造那一份字段，不必真发登录请求）。
    state_path.write_text(json.dumps({
        "site_key": state_path.stem,
        "created_at": "2026-09-30T00:00:00+00:00",
        "secrets_enc": auth_module._encrypt_secrets(ACCOUNT, PASSWORD),
        "cookies": [{"name": "loginToken", "value": "old", "domain": HOST, "path": "/"}],
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    _install_fake_playwright(monkeypatch, url)
    manager = LoginManager(state_dir)

    async def _drive() -> None:
        opened = await manager.open(url, timeout_seconds=30)
        record = manager.sessions[opened["login_session_id"]]
        for _ in range(200):  # 等 _run 把浏览器/上下文备好
            if record.context is not None:
                break
            await asyncio.sleep(0.01)
        manager.confirm(opened["login_session_id"])
        await asyncio.wait_for(record.task, timeout=10)

    asyncio.run(_drive())

    raw = state_path.read_bytes()
    assert b'"cookies"' in raw, "登录态仍要按 storage_state 契约落盘"
    state = json.loads(raw.decode("utf-8"))
    assert "secrets_enc" in state, "浏览器登录不得抹掉 http_login 存的加密凭据"
    assert read_auth_state_secrets(state_path) == {"username": ACCOUNT,
                                                   "password": PASSWORD}
    assert PASSWORD.encode("utf-8") not in raw, "合并回去的仍必须是密文"


class TestMergeHelpers:
    def test_preserve_returns_only_the_ciphertext(self, tmp_path):
        path = tmp_path / "s.json"
        path.write_text(json.dumps({"secrets_enc": "BLOB", "cookies": []}), encoding="utf-8")

        assert _preserve_encrypted_secrets(path) == {"secrets_enc": "BLOB"}

    def test_preserve_is_empty_for_missing_or_broken_files(self, tmp_path):
        assert _preserve_encrypted_secrets(tmp_path / "nope.json") == {}
        broken = tmp_path / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        assert _preserve_encrypted_secrets(broken) == {}

    def test_merge_restores_the_ciphertext(self, tmp_path):
        path = tmp_path / "s.json"
        path.write_text(json.dumps({"cookies": [{"name": "a"}]}), encoding="utf-8")

        assert _merge_encrypted_secrets(path, {"secrets_enc": "BLOB"}) is True
        state = json.loads(path.read_text(encoding="utf-8"))
        assert state["secrets_enc"] == "BLOB"
        assert state["cookies"] == [{"name": "a"}], "合并不得丢 Cookie"

    def test_merge_never_overwrites_a_newer_ciphertext(self, tmp_path):
        path = tmp_path / "s.json"
        path.write_text(json.dumps({"secrets_enc": "NEW"}), encoding="utf-8")

        assert _merge_encrypted_secrets(path, {"secrets_enc": "OLD"}) is False
        assert json.loads(path.read_text(encoding="utf-8"))["secrets_enc"] == "NEW"

    def test_merge_on_missing_file_is_a_no_op(self, tmp_path):
        assert _merge_encrypted_secrets(tmp_path / "nope.json", {"secrets_enc": "X"}) is False

    def test_reader_is_documented_as_migration_only(self):
        """没有生产调用点就不虚构：定位必须写成「迁移 / 排查工具」。"""
        doc = read_auth_state_secrets.__doc__ or ""
        assert "迁移" in doc
        assert "生产路径" in doc and "不调用" in doc


def test_repo_tool_count_is_still_21():
    """硬护栏：工具数不得因「一次输入」而变。"""
    source = (Path(__file__).resolve().parents[1]
              / "scry_mcp_gen" / "server.py").read_text(encoding="utf-8")
    assert source.count("@mcp.tool()") == 21


def test_generated_server_compiles_with_the_new_branches(tmp_path):
    source = _server_source()
    compile(source, "server.py", "exec")
    assert "await _do_login" in source or "_do_login(acct, pwd" in source
    assert source.count("@mcp.tool()") == 5
    # 弹窗/缓存诊断的代码同样不得引入注入面（工具函数体内不含 __import__/eval/exec）
    assert "__import__(" not in source
