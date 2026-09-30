# -*- coding: utf-8 -*-
"""README「鉴权说明」必须如实反映 Cookie 鉴权。

纯 Cookie 鉴权站点的 registry 里 `hosts[host].scheme` 为 **None**（凭据走
`cookie_names` + 运行时 `.env` 的 `<PREFIX>_COOKIE_<HOST>`），而端点
`auth_required` 为 true。若 README 直接按 `scheme or '无（公开接口）'` 渲染，
就会把**需要登录态**的站点写成公开接口 —— 实测某 OA 系统的**全部端点**都是如此，
`.env.example` 写着要填 Cookie，README 却说「无（公开接口）」，
两份文档互相矛盾，未来对接方会据此漏配 Cookie 而全部 401。
"""
from __future__ import annotations

import ast
import base64
import os
import re

from scry_mcp_gen.generator import render_server

COOKIE_HOST = "oa.example.com"

# 真机（Citrix ADC / NetScaler）实测：一次会话要带上这**五个** Cookie 才认登录。
# 只有 SESSID 命中「凭据命名特征」，其余四个都是站点自定义名 —— 按特征过滤
# 会把它们全部丢掉，于是生成物只填 SESSID，服务端回
# `{"errorcode":1026,"message":"Not logged in"}` 且**不告诉你缺哪一个**。
DEMO_DEVICE_COOKIES = ["SESSID", "startupapp", "is_cisco_platform",
                       "NITRO_SK", "rdx_pagination_size"]


def _registry(hosts: dict, auth_required: bool = True) -> dict:
    return {
        "site_name": "portal",
        "registry_version": 1,
        "hosts": hosts,
        "endpoints": [{
            "tool_name": "get_api_system_status",
            "method": "GET",
            "host": COOKIE_HOST,
            "path": "/api/system/status",
            "auth_required": auth_required,
            "status": "active",
        }],
    }


def _readme(registry: dict) -> str:
    return render_server(registry)["README.md"]


def _server(registry: dict) -> str:
    return render_server(registry)["server.py"]


def _credential_cookies_line(registry: dict) -> str:
    """取生成物里 `CREDENTIAL_COOKIES = {...}` 那一整行。"""
    line = next(l for l in _server(registry).splitlines()
                if l.startswith("CREDENTIAL_COOKIES = "))
    return line


def _run_auth_block(registry: dict) -> dict:
    """把生成物里的鉴权函数与该 host 的 `CREDENTIAL_COOKIES` 一起 exec 出来。

    只取 `_HK` / `_cookie_values` / `_auth_headers` 三个函数签名需要的 stdlib
    （os/re/base64），不 import fastmcp —— 于是「生成物实际会发什么 Cookie」
    可以在测试里直接断言，无需起服务。
    """
    source = _server(registry)
    tree = ast.parse(source)
    wanted = {"_HK", "_cookie_values", "_auth_headers"}
    segments = [ast.get_source_segment(source, node) for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name in wanted]
    literal = next(line for line in source.splitlines()
                   if line.startswith("CREDENTIAL_COOKIES = "))
    # S13 起 `_auth_headers(host, tool=None)` 会读 `AUTH_SCHEME`（端点级）与
    # `HOST_AUTH_SCHEME`（域名级兜底）两张表；这里给空表，等价于「没有端点级记录」，
    # 走主机级 / Cookie 兜底这条路 —— 正是本类用例要断言的整罐 Cookie 行为。
    namespace = {"os": os, "re": re, "base64": base64,
                 "RUNTIME_TOKEN": "", "TOKEN": "", "AUTH_SCHEME": {},
                 "HOST_AUTH_SCHEME": {}, "_current_token": lambda: ""}
    exec(compile("\n".join(segments) + "\n" + literal, "<generated>", "exec"),
         namespace)
    return namespace


class TestObservedCookieNamesAreKept:
    """**观测到就保留**：只允许剔除已知埋点，不认识的名字一律不能丢。

    生成物只发一个 Cookie 时服务端不会指出缺谁（NITRO 只回 1026 Not logged in），
    所以「少发」是不可诊断的硬故障；「多发」最坏是服务端忽略多余的 Cookie。
    """

    def _device_registry(self, names: list[str]) -> dict:
        return _registry({COOKIE_HOST: {"scheme": None, "cookie_names": names}})

    def test_demo_device_all_five_names_reach_credential_cookies(self):
        registry = self._device_registry(DEMO_DEVICE_COOKIES)
        assert _credential_cookies_line(registry) == (
            "CREDENTIAL_COOKIES = {'oa.example.com': ['SESSID', 'startupapp', "
            "'is_cisco_platform', 'NITRO_SK', 'rdx_pagination_size']}")

    def test_all_five_names_survive_into_env_example(self):
        env = render_server(self._device_registry(DEMO_DEVICE_COOKIES))[".env.example"]
        assert (f"# {COOKIE_HOST} 需要的 Cookie: "
                "SESSID, startupapp, is_cisco_platform, NITRO_SK, rdx_pagination_size"
                ) in env

    def test_readme_lists_all_five_names(self):
        readme = _readme(self._device_registry(DEMO_DEVICE_COOKIES))
        assert (f"- `{COOKIE_HOST}`：Cookie（SESSID, startupapp, is_cisco_platform, "
                "NITRO_SK, rdx_pagination_size）") in readme

    def test_only_provably_tracking_cookies_are_dropped(self):
        """唯一允许被删的是**已知埋点名单**，其余（包括不认识的）全留。"""
        registry = self._device_registry(["SESSID", "_ga", "ai_session", "unknown_thing"])
        assert _credential_cookies_line(registry) == (
            "CREDENTIAL_COOKIES = {'oa.example.com': ['SESSID', 'unknown_thing']}")

    def test_name_order_is_the_observed_order(self):
        """保序：生成物里的顺序与抓包观测顺序一致，便于和抓包对照。"""
        registry = self._device_registry(["b_cookie", "a_cookie"])
        assert _credential_cookies_line(registry) == (
            "CREDENTIAL_COOKIES = {'oa.example.com': ['b_cookie', 'a_cookie']}")

    def test_generated_auth_headers_send_the_whole_jar(self, monkeypatch):
        """名单进了 `CREDENTIAL_COOKIES` 还不够 —— 要证明运行期**真的整罐发出**。

        源 bug 的终点是 `{"errorcode":1026,"message":"Not logged in"}`：
        修好之后，按 README 填一整串 Cookie，生成的 `_auth_headers` 必须原样带上
        全部五个名字（`_cookie_values`/`_auth_headers` 的既有行为未改）。
        """
        namespace = _run_auth_block(self._device_registry(DEMO_DEVICE_COOKIES))
        monkeypatch.setenv("PORTAL_COOKIE_OA_EXAMPLE_COM",
                           "SESSID=1; startupapp=nsconf; is_cisco_platform=0;"
                           " NITRO_SK=deadbeef; rdx_pagination_size=10")

        headers = namespace["_auth_headers"](COOKIE_HOST)

        assert headers["Cookie"] == ("SESSID=1; startupapp=nsconf; "
                                     "is_cisco_platform=0; NITRO_SK=deadbeef; "
                                     "rdx_pagination_size=10")


class TestCookieOnlyHost:
    """scheme 为空但配了凭据 Cookie —— 是 Cookie 鉴权，不是公开接口。"""

    HOSTS = {COOKIE_HOST: {"scheme": None,
                           "cookie_names": ["SERVERID", "JSESSIONID", "loginToken"]}}

    def test_not_reported_as_public(self):
        readme = _readme(_registry(self.HOSTS))
        assert "无（公开接口）" not in readme

    def test_reported_as_cookie(self):
        readme = _readme(_registry(self.HOSTS))
        assert f"- `{COOKIE_HOST}`：Cookie（" in readme

    def test_lists_observed_cookie_names(self):
        """列出**全部**观测到的名字（`SERVERID` 不含凭据特征，但它照样要发）。"""
        readme = _readme(_registry(self.HOSTS))
        assert "JSESSIONID" in readme and "loginToken" in readme
        # 名单来自同一份 `cookie_names`，不再按命名特征二次过滤（见 Fix 1）。
        assert "SERVERID" in readme

    def test_points_at_cookie_env_var(self):
        """要给出可操作配置项，而不是只描述现象（具体键名见 .env.example）。"""
        readme = _readme(_registry(self.HOSTS))
        assert "PORTAL_COOKIE_" in readme
        assert "auth_states/" in readme

    def test_no_bogus_token_line(self):
        """纯 Cookie 站点不应让人去填 token（.env.example 里根本没这项）。"""
        readme = _readme(_registry(self.HOSTS))
        assert "`PORTAL_TOKEN`" not in readme


class TestTrulyPublicHost:
    def test_still_reported_as_public(self):
        hosts = {COOKIE_HOST: {"scheme": None, "cookie_names": []}}
        readme = _readme(_registry(hosts, auth_required=False))
        assert "无（公开接口）" in readme
        assert "`PORTAL_TOKEN`" in readme


class TestAuthRequiredWithoutSchemeOrCookie:
    def test_flags_for_manual_review(self):
        """既无 scheme 又无 Cookie 却要求鉴权：不能谎称公开，要提示人工核对。"""
        hosts = {COOKIE_HOST: {"scheme": None, "cookie_names": []}}
        readme = _readme(_registry(hosts, auth_required=True))
        assert "无（公开接口）" not in readme
        assert "需要鉴权" in readme


class TestBearerHost:
    def test_bearer_keeps_token_line(self):
        hosts = {"api.example.com": {"scheme": "Bearer", "cookie_names": []}}
        registry = _registry(hosts)
        registry["endpoints"][0]["host"] = "api.example.com"
        readme = _readme(registry)
        assert "- `api.example.com`：Bearer" in readme
        assert "`PORTAL_TOKEN`" in readme


AUTH_HOST = "portal.example.com"


def _auth_registry(verify: dict | None) -> dict:
    """带账号密码登录配置的 registry；verify 为 None 表示抓包没记录校验接口。

    analyzer 把校验接口**嵌套**存成 `auth_login["verify"] = {"host", "path"}`（见
    `analyzer.py::detect_auth_login`）—— 这里刻意用同一形状，锁住「嵌套 → 生成物摊平」。
    """
    login = {
        "method": "POST", "host": AUTH_HOST, "path": "/api/login",
        "account_field": "username", "password_field": "password",
        "token_path": ["data", "token"], "query_params": {},
    }
    if verify is not None:
        login["verify"] = verify
    registry = _registry({AUTH_HOST: {"scheme": "Bearer", "cookie_names": []}})
    registry["endpoints"][0]["host"] = AUTH_HOST
    registry["auth_login"] = login
    return registry


def _load_auth_server(tmp_path, monkeypatch, registry: dict, responses: list,
                      token: str = "tok-from-test"):
    """把生成的 server.py 当模块加载，用假 httpx 顶替依赖，直接调用 auth_status()。

    auth_status() 的校验探针会真发 `_request` —— 用假的 AsyncClient 记录调用即可
    断言「探针到底有没有发、发去哪」，全程不碰网络。
    """
    import importlib.util
    import sys
    import types

    calls: list = []

    class _Resp:
        def __init__(self, status: int):
            self.status_code = status
            self.content = b"{}"
            self.text = "{}"

        def json(self):
            return {}

        def raise_for_status(self):
            return None

    class FakeAsyncClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def request(self, method, path, **kwargs):
            calls.append({"method": method, "path": path, **kwargs})
            return _Resp(responses.pop(0) if responses else 200)

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.AsyncClient = FakeAsyncClient
    fake_httpx.HTTPError = type("HTTPError", (Exception,), {})
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    class FakeFastMCP:
        def __init__(self, name):
            self.name = name

        def tool(self, *args, **kwargs):
            return lambda fn: fn

        def run(self):
            pass

    fake_fastmcp = types.ModuleType("fastmcp")
    fake_fastmcp.FastMCP = FakeFastMCP
    monkeypatch.setitem(sys.modules, "fastmcp", fake_fastmcp)

    target = tmp_path / "server.py"
    target.write_text(_server(registry), encoding="utf-8")
    spec = importlib.util.spec_from_file_location("gen_auth_status_server", target)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.RUNTIME_TOKEN = token
    return module, calls


class TestAuthStatusVerifiesOnlyWhenPossible:
    """`auth_status()` 的 `verified` 必须如实：有校验接口才探、没有就不承诺。

    修复前的生成物里 `_AUTH_LOGIN_CFG` 是 analyzer 的**原始** auth_login dict，
    校验接口嵌在 `cfg["verify"]` 下，而 auth_status() 读的是 `cfg["verify_host"]` /
    `cfg["verify_path"]` —— 键名对不上，guard 永远短路，`_request(...)` 探针成了死代码，
    `verified` 恒为 None，与 README / docs 承诺的「校验会话」矛盾。
    """

    def test_config_carries_flattened_verify_keys(self):
        """嵌套的 verify 必须摊平成探针读得到的两个顶层键（否则探针永不运行）。"""
        server = _server(_auth_registry({"host": AUTH_HOST, "path": "/api/profile"}))
        cfg_line = next(l for l in server.splitlines() if l.startswith("_AUTH_LOGIN_CFG = "))
        assert "'verify_host': 'portal.example.com'" in cfg_line
        assert "'verify_path': '/api/profile'" in cfg_line

    def test_probe_runs_when_capture_recorded_a_verify_endpoint(self, tmp_path, monkeypatch):
        import asyncio

        registry = _auth_registry({"host": AUTH_HOST, "path": "/api/profile"})
        module, calls = _load_auth_server(tmp_path, monkeypatch, registry, [200])

        info = asyncio.run(module.auth_status())

        assert info["verified"] is True
        assert info["verify_detail"] == "ok"
        # 探针真的发了，且发给抓包记录的 host/path（修复前这里是 []）。
        assert [(c["method"], c["path"]) for c in calls] == [("GET", "/api/profile")]

    def test_probe_reports_failure_when_verify_endpoint_returns_401(self, tmp_path, monkeypatch):
        """探针本身失败要如实报 false，而不是吞掉异常假装 ok。"""
        import asyncio

        class _Failing:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def request(self, *args, **kwargs):
                raise RuntimeError("boom")

        registry = _auth_registry({"host": AUTH_HOST, "path": "/api/profile"})
        module, _ = _load_auth_server(tmp_path, monkeypatch, registry, [200])
        module.httpx.AsyncClient = lambda **kw: _Failing()  # type: ignore[attr-defined]

        info = asyncio.run(module.auth_status())

        assert info["verified"] is False
        assert "boom" in info["verify_detail"]

    def test_honest_when_no_verify_endpoint_was_captured(self, tmp_path, monkeypatch):
        """抓包没记录校验接口 → verified=None + 人话解释，且**不发**探针。"""
        import asyncio

        module, calls = _load_auth_server(
            tmp_path, monkeypatch, _auth_registry(None), [200])

        info = asyncio.run(module.auth_status())

        assert info["verified"] is None
        assert "没有记录可用于校验的接口" in info["verify_detail"]
        assert calls == []          # 不谎称已验证，也不打无谓的探针

    def test_not_verified_without_token(self, tmp_path, monkeypatch):
        """无 token 时同样不能声称「已验证」。"""
        import asyncio

        monkeypatch.delenv("PORTAL_TOKEN", raising=False)
        registry = _auth_registry({"host": AUTH_HOST, "path": "/api/profile"})
        module, calls = _load_auth_server(tmp_path, monkeypatch, registry, [200], token="")

        info = asyncio.run(module.auth_status())

        assert info["has_token"] is False
        assert info["verified"] is None
        assert calls == []

    def test_readme_does_not_promise_verification_without_verify_endpoint(self):
        """README 不能承诺生成物做不到的校验。"""
        readme = _readme(_auth_registry(None))
        assert "没有记录可用于校验的接口" in readme
        assert "与是否有效" not in readme          # 修复前的不实承诺
        assert "确认 token 是否仍有效" not in readme

    def test_readme_names_the_recorded_verify_endpoint(self):
        """抓到校验接口时，README 要写明探针打哪个地址。"""
        readme = _readme(_auth_registry({"host": AUTH_HOST, "path": "/api/profile"}))
        assert "/api/profile" in readme
        assert "确认 token 是否仍有效" in readme
