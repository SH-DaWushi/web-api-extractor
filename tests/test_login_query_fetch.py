# -*- coding: utf-8 -*-
"""R2 —— 登录 query 参数「自动取用」：先调来源接口、取出字段、再用于登录。

用户口径：只把「疑似来源」写进摘要**不算做** —— 对不懂 HTTP 的使用者，一条
「值疑似来自前序响应」的线索他无法行动。因此当且仅当**五条时序闸门全中**时，
生成的服务要**自己**去把值取回来：

  1. 候选来源唯一；
  2. 来源是公共、无鉴权的 GET（请求不携带 Authorization / Cookie）；
  3. 来源接口自身不需要任何参数；
  4. 来源既不是登录端点、也不是校验端点；
  5. 来源请求早于登录，且响应是完整 JSON。

任一不中 → 不发射取用代码，**也不标必填**（参数带默认值 None，运行时按
「调用入参 → .env → 原生弹窗询问 → 明确报错点名」取值链处理），并在 docstring 里说明。

三条硬性质：
  * 取用代码**绝不走 `_request()`**（它 401 会触发自动重登录 → 递归）；
  * 运行时取不到值 → **明确报错 + 建议重新抓包**，不静默失败、不硬着头皮登录；
  * 插值只经 `json.dumps` / `repr`，生成物永远 `compile()` 通过、无注入。
"""
from __future__ import annotations

import ast
import asyncio
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

from scry_mcp_gen.generator import render_server

HOST = "portal.example.com"
LOGIN_PATH = "/api/login"
SOURCE_PATH = "/api/config"
SOURCE_URL = f"https://{HOST}{SOURCE_PATH}"
TOKEN_VALUE = "FRESHTOK123456"
PWN = '__import__("os").system("echo PWNED")'


def _endpoint() -> dict:
    return {
        "endpoint_id": "ep_001", "tool_name": "get_todo", "method": "GET",
        "host": HOST, "path": "/api/todo", "path_params": [],
        "query_params": {}, "request_body_params": {}, "status": "active",
        "auth_required": True, "description": "待办",
    }


def _fetch_entry(url: str = SOURCE_URL, field: str = "$.data.csrf",
                 tokens: list | None = None) -> dict:
    """分析器在五条闸门全中时写下的那条记录（取用计划 + 说明）。"""
    return {
        "name": "csrf", "class": "suspected_response",
        "suspected_source": {"method": "GET", "host": HOST, "path": SOURCE_PATH,
                             "response_field": field},
        "reason": None, "needs_confirmation": True,
        "note": ("该参数的值在抓包时取自前序响应 GET " + HOST + SOURCE_PATH
                 + "：生成的服务会在登录前**自动**调用该接口取值，无需你填写"),
        "fetch": {"name": "csrf", "method": "GET", "url": url,
                  "field": tokens if tokens is not None else ["data", "csrf"],
                  "field_display": field},
        "fetch_block": None,
    }


def _registry(provenance: dict | None = None, params: dict | None = None) -> dict:
    login = {
        "method": "POST", "host": HOST, "path": LOGIN_PATH,
        "account_field": "username", "password_field": "password",
        "token_path": ["data", "token"],
        "query_params": params if params is not None else {"csrf": [TOKEN_VALUE]},
    }
    if provenance is not None:
        login["query_param_provenance"] = provenance
    return {
        "site_name": "portal", "registry_version": 1,
        "hosts": {HOST: {"scheme": "Bearer", "cookie_names": []}},
        "endpoints": [_endpoint()], "auth_login": login,
    }


def _server(registry: dict) -> str:
    return render_server(registry)["server.py"]


# --------------------------------------------------------------------------- #
# 生成物静态性质
# --------------------------------------------------------------------------- #
class TestGeneratedFetchCode:
    def test_fetch_helper_never_calls_the_request_helper(self):
        """`_request` 会 401 自动重登录 —— 取用路径走它就是递归。必须独立 httpx 调用。"""
        tree = ast.parse(_server(_registry({"csrf": _fetch_entry()})))
        helper = next(n for n in tree.body
                      if isinstance(n, ast.AsyncFunctionDef)
                      and n.name == "_fetch_login_query_values")
        for node in ast.walk(helper):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id != "_request", "取用代码不得走 _request（会递归重登录）"

    def test_fetched_param_does_not_join_the_login_signature(self):
        """使用者不该为它填任何东西 —— 所以它**不能**变成工具入参（否则 LLM 会去问人）。"""
        src = _server(_registry({"csrf": _fetch_entry()}))
        line = next(l for l in src.splitlines() if l.startswith("async def login("))
        assert line == ("async def login(account: str | None = None, "
                        "password: str | None = None) -> dict:")
        assert "csrf" not in line
        doc = src.split("async def login(")[1].split('"""')[1]
        assert "自动获取" in doc and "无需传参" in doc

    def test_plan_carries_no_captured_value(self):
        src = _server(_registry({"csrf": _fetch_entry()}))
        assert TOKEN_VALUE not in src
        assert SOURCE_PATH in src                     # 来源地址是取用代码的一部分
        cfg = next(l for l in src.splitlines() if l.startswith("_AUTH_LOGIN_CFG = "))
        assert "query_param_provenance" not in cfg    # 分析侧元数据不原样进生成物
        assert "login_query_fetch" in cfg

    def test_no_fetch_plan_means_byte_identical_to_old_output(self):
        """没有取用计划（老 registry）时不发射任何取用代码：签名与产物形态不变。"""
        src = _server(_registry())
        assert "_LOGIN_FETCH" not in src
        assert "_fetch_login_query_values" not in src
        assert "login_query_fetch" not in src

    @pytest.mark.parametrize("name", ["class", "params", "account", "login_query", "confirm"])
    def test_param_name_collisions_and_keywords_are_safe(self, name):
        """参数名是关键字 / 撞上生成器自己的注入名 → 取用型不进签名，只当数据用。"""
        src = _server(_registry({name: dict(_fetch_entry(), name=name)}))
        compile(src, "server.py", "exec")
        line = next(l for l in src.splitlines() if l.startswith("async def login("))
        assert line.endswith("password: str | None = None) -> dict:"), line

    @pytest.mark.parametrize("hostile", [
        f'/api/cfg") ; {PWN} ; _d = ("',
        '/api/{csrf}/' + PWN,
        "/api/" + PWN,
        '/api/x#" + PWN + "\n',
    ])
    def test_hostile_source_url_is_data_not_code(self, hostile):
        """来源路径来自抓包：含引号 / 花括号 / `__import__` 也只能是字符串。"""
        src = _server(_registry({"csrf": _fetch_entry(url=f"https://{HOST}{hostile}")}))
        compile(src, "server.py", "exec")
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Call):
                fn = node.func
                assert not (isinstance(fn, ast.Name) and fn.id == "__import__")
                assert not (isinstance(fn, ast.Attribute) and fn.attr == "system")

    def test_hostile_field_path_and_tokens_are_data(self):
        src = _server(_registry({"csrf": _fetch_entry(
            field='$.a"b{}' + PWN, tokens=["a\"b{}", 0, PWN])}))
        compile(src, "server.py", "exec")


class TestDegradesToRuntimeValueChain:
    """闸门没全中 → 不发射取用代码、**也不标必填**：参数带默认值 None，运行时按
    **调用入参 → .env → 原生弹窗 → 明确报错点名** 取值。

    旧契约是「降级为必填」—— 那会让参数绑定阶段就
    `TypeError: login() missing 1 required keyword-only argument`，函数体进不去，
    弹窗拿账号密码那条路在这类站点上完全走不到。本次按用户口径推翻。
    """

    @pytest.mark.parametrize("entry", [
        # 来源需要鉴权 / 需要参数 / 不是 GET / 字段定位不到 —— 分析器只写 fetch_block
        {"name": "csrf", "class": "suspected_response",
         "suspected_source": {"method": "GET", "host": HOST, "path": SOURCE_PATH},
         "reason": None, "needs_confirmation": True,
         "note": "疑似来自前序响应 GET portal.example.com/api/config；无法自动取用"
                 "（来源请求带了鉴权头或 Cookie，不是公共接口），该参数仍必须由调用方提供",
         "fetch": None, "fetch_block": "source_request_carries_auth"},
        # 循环来源（来源就是登录端点）也必须降级，**不是**生成 fetch
        {"name": "csrf", "class": "suspected_response",
         "suspected_source": {"method": "GET", "host": HOST, "path": LOGIN_PATH},
         "reason": None, "needs_confirmation": True,
         "note": "疑似来自前序响应 GET portal.example.com/api/login；无法自动取用"
                 "（不满足自动取用的条件），该参数仍必须由调用方提供",
         "fetch": None, "fetch_block": "source_is_login_endpoint"},
        # 多候选：分析器判为「不可知」，连来源都不给
        {"name": "csrf", "class": "unknown", "suspected_source": None,
         "reason": "multiple_sources", "needs_confirmation": True,
         "note": "在前序 2 个不同端点的响应里都出现该值，无法判定来源（歧义）→ 不可知"},
    ])
    def test_deferred_with_env_channel_and_reason(self, entry):
        src = _server(_registry({entry["name"]: entry}))
        assert "_LOGIN_FETCH" not in src
        assert "csrf: str | None = None" in src        # 关键字限定 + 有默认值（**不标必填**）
        assert "PORTAL_LOGIN_QUERY_CSRF" in src        # 401 自动重登录的 env 通道
        assert TOKEN_VALUE not in src
        doc = src.split("async def login(")[1].split('"""')[1]
        assert "来源未知" in doc and "不填也能调用" in doc
        compile(src, "server.py", "exec")


# --------------------------------------------------------------------------- #
# 运行期行为（假 httpx）
# --------------------------------------------------------------------------- #
def _load_server(tmp_path, monkeypatch, registry: dict, config_result):
    """加载生成的 server.py；`config_result` 是来源接口的响应（status, payload）。"""
    calls: list = []
    business_calls = {"n": 0}

    class _Resp:
        def __init__(self, status: int, payload: dict | None = None):
            self.status_code = status
            self._payload = payload if payload is not None else {}
            self.content = b"{}"
            self.text = "{}"

        def json(self):
            return self._payload

        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError(f"HTTP {self.status_code}")

    class FakeAsyncClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def request(self, method, path, **kwargs):
            calls.append({"method": method, "path": path, **kwargs})
            if path == LOGIN_PATH:
                return _Resp(200, {"data": {"token": "tok"}})
            if SOURCE_URL in str(path):
                status, payload = config_result
                return _Resp(status, payload)
            if path == "/api/todo":
                business_calls["n"] += 1
                # 第一次 401（触发自动重登录），重试那次 200
                return _Resp(401 if business_calls["n"] == 1 else 200, {"data": []})
            return _Resp(404)

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.AsyncClient = FakeAsyncClient
    fake_httpx.HTTPError = type("HTTPError", (Exception,), {})

    class FakeFastMCP:
        def __init__(self, name):
            self.name = name

        def tool(self, *args, **kwargs):
            return lambda fn: fn

        def run(self):
            pass

    fake_fastmcp = types.ModuleType("fastmcp")
    fake_fastmcp.FastMCP = FakeFastMCP

    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    monkeypatch.setitem(sys.modules, "fastmcp", fake_fastmcp)

    target = tmp_path / "server.py"
    target.write_text(render_server(registry)["server.py"], encoding="utf-8")
    spec = importlib.util.spec_from_file_location("gen_login_fetch_server", target)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ERROR_LOG = tmp_path / "error.log"
    module._cache_save = lambda *args, **kwargs: None
    module._cache_load = lambda *args, **kwargs: None
    module.TOKEN_CACHE = tmp_path / "token_cache.bin"
    module.CRED_CACHE = tmp_path / "cred_cache.bin"
    return module, calls


class TestFetchAtRuntime:
    def test_fetched_value_is_used_for_login(self, tmp_path, monkeypatch):
        registry = _registry({"csrf": _fetch_entry()})
        module, calls = _load_server(tmp_path, monkeypatch, registry,
                                     (200, {"data": {"csrf": TOKEN_VALUE}}))

        result = asyncio.run(module._do_login("bob", "pw"))

        assert result["success"] is True
        assert calls[0]["path"] == SOURCE_URL and calls[0]["method"] == "GET"
        login_call = next(c for c in calls if c["path"] == LOGIN_PATH)
        assert login_call["params"] == {"csrf": TOKEN_VALUE}

    def test_fetch_never_triggers_the_relogin_helper(self, tmp_path, monkeypatch):
        """把 `_request` 换成会炸的实现：取用路径必须完全绕开它。"""
        registry = _registry({"csrf": _fetch_entry()})
        module, _ = _load_server(tmp_path, monkeypatch, registry,
                                 (200, {"data": {"csrf": TOKEN_VALUE}}))

        def _boom(*args, **kwargs):
            raise AssertionError("取用路径不得走 _request")

        module._request = _boom
        assert asyncio.run(module._do_login("bob", "pw"))["success"] is True

    def test_missing_field_fails_loudly_and_never_logs_in(self, tmp_path, monkeypatch):
        registry = _registry({"csrf": _fetch_entry()})
        module, calls = _load_server(tmp_path, monkeypatch, registry,
                                     (200, {"data": {}}))

        with pytest.raises(RuntimeError) as excinfo:
            asyncio.run(module._do_login("bob", "pw"))

        message = str(excinfo.value)
        assert "重新抓一次包" in message          # 非技术措辞的下一步
        assert "csrf" in message
        assert TOKEN_VALUE not in message
        assert [c["path"] for c in calls] == [SOURCE_URL], "取不到值就不许硬着头皮登录"
        assert "csrf" in (tmp_path / "error.log").read_text(encoding="utf-8")

    def test_source_http_error_fails_loudly(self, tmp_path, monkeypatch):
        registry = _registry({"csrf": _fetch_entry()})
        module, calls = _load_server(tmp_path, monkeypatch, registry, (500, {}))

        with pytest.raises(RuntimeError) as excinfo:
            asyncio.run(module._do_login("bob", "pw"))

        assert "重新抓一次包" in str(excinfo.value)
        assert [c["path"] for c in calls] == [SOURCE_URL]

    def test_auto_relogin_fetches_then_retries(self, tmp_path, monkeypatch):
        """401 自动重登录这条链路也要能取到值（这正是取用型的价值：无需 .env）。"""
        registry = _registry({"csrf": _fetch_entry()})
        module, calls = _load_server(tmp_path, monkeypatch, registry,
                                     (200, {"data": {"csrf": TOKEN_VALUE}}))
        module._cached_credentials = lambda: ("bob", "secret")

        asyncio.run(module._request(HOST, "GET", "/api/todo"))

        # 精确形态：业务请求 → 401 → （先取用、再登录）→ 业务重试
        assert [c["path"] for c in calls] == ["/api/todo", SOURCE_URL, LOGIN_PATH, "/api/todo"]
        login_call = next(c for c in calls if c["path"] == LOGIN_PATH)
        assert login_call["params"] == {"csrf": TOKEN_VALUE}

    def test_list_field_path_is_walked(self, tmp_path, monkeypatch):
        registry = _registry({"csrf": _fetch_entry(field="$.items[0].id",
                                                  tokens=["items", 0, "id"])})
        module, calls = _load_server(tmp_path, monkeypatch, registry,
                                     (200, {"items": [{"id": TOKEN_VALUE}]}))

        asyncio.run(module._do_login("bob", "pw"))

        login_call = next(c for c in calls if c["path"] == LOGIN_PATH)
        assert login_call["params"] == {"csrf": TOKEN_VALUE}
