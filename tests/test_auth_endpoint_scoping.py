# -*- coding: utf-8 -*-
"""S13：鉴权按**端点**透传（同一主机上混用 Bearer 与纯 Cookie）。

修复前的实测后果（合成夹具跑真 analyzer 复现）：

* 同一主机三段流量（``Authorization: Bearer`` 的接口 + **只**带
  ``JSESSIONID``/``NITRO_SK`` 的纯 Cookie 接口 + ``Authorization: Basic`` 的接口）
  会塌缩成**一个** scheme —— `analyzer` 在同一 host 的多个分组里只留最后一个带
  ``Authorization`` 的，``cookie_names`` 也被那一个分组的集合**覆盖**；
* 生成物再按主机套用这一个 scheme：``_auth_headers(host)`` 对 Bearer/Basic 只返回
  ``Authorization``、**完全不发 ``Cookie``** → 同域里只认 Cookie 的接口稳定 401，
  而且服务端不会说缺什么；反向定成 ``None`` 则 Bearer 接口丢 ``Authorization``。

本文件把这条链路钉住：analyzer 逐端点记 ``auth_hint`` → registry 透传 →
生成物按端点取用凭据。断言的是**实际发出的请求头**（假 httpx 抓），不是代码长什么样。
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import types
from pathlib import Path

from scry_mcp_gen.analyzer import analyze_capture
from scry_mcp_gen.generator import render_server
from scry_mcp_gen.project import (
    init_project,
    is_conflict_change,
    load_registry,
    merge_registry,
    session_to_registry_entries,
)

HOST = "portal.example.com"
BEARER_PATH = "/api/a"
COOKIE_PATH = "/api/reports/daily"
BASIC_PATH = "/api/b"
# 真机（Citrix ADC / NetScaler）实测：会话由这些**名字不认识**的 Cookie 一起构成。
# 修复前 `cookie_names` 被 Bearer/Basic 分组覆盖 → 整类丢失 → 只认 Cookie 的接口 401。
DEVICE_COOKIES = ["JSESSIONID", "NITRO_SK"]


def _triplet(index: int, path: str, headers: dict) -> list[dict]:
    """一条请求的三事件（请求 / 响应 / 响应体），与 capture.jsonl 的形状一致。"""
    request_id = f"r{index}"
    return [
        {"type": "request", "requestId": request_id, "url": f"https://{HOST}{path}",
         "method": "GET", "headers": headers, "resourceType": "XHR"},
        {"type": "response", "requestId": request_id, "status": 200,
         "headers": {"Content-Type": "application/json"}},
        {"type": "response_body", "requestId": request_id, "body": '{"ok":true}', "size": 12},
    ]


def _write_capture(directory: Path, groups: list[tuple[str, dict]], samples: int = 2) -> Path:
    """把 ``[(path, headers), …]`` 写成 capture.jsonl（每组 ``samples`` 条）。"""
    lines: list[dict] = []
    index = 1
    for _ in range(samples):
        for path, headers in groups:
            lines += _triplet(index, path, headers)
            index += 1
    (directory / "capture.jsonl").write_text(
        "\n".join(json.dumps(line, ensure_ascii=False) for line in lines), encoding="utf-8")
    return directory


def _mixed_capture(directory: Path) -> Path:
    """三种方式同一主机：Bearer / 纯 Cookie / Basic（顺序刻意把 Basic 放最后）。"""
    return _write_capture(directory, [
        (BEARER_PATH, {"Accept": "application/json",
                       "Authorization": "Bearer ***"}),
        (COOKIE_PATH, {"Accept": "application/json",
                       "Cookie": "; ".join(f"{name}=***" for name in DEVICE_COOKIES)}),
        # 最后一段带 Authorization —— 修复前正是它把前两段的结论整个覆盖掉
        (BASIC_PATH, {"Accept": "application/json",
                      "Authorization": "Basic ***"}),
    ])


def _registry_from_capture(directory: Path) -> dict:
    analysis = analyze_capture(directory)
    entries, hosts = session_to_registry_entries(analysis, "s1")
    return {"site_name": "portal", "registry_version": 1, "hosts": hosts,
            "endpoints": entries, "auth_login": None}


def _by_path(registry: dict) -> dict:
    return {e["path"]: e for e in registry["endpoints"]}


def _load_server(tmp_path: Path, source: str, monkeypatch, env: dict) -> tuple[object, list]:
    """把生成的 server.py 当模块加载，用假 httpx 记录**实际发出的头**。"""
    import sys

    calls: list = []

    class _Resp:
        status_code = 200
        content = b"{}"
        text = "{}"

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
            calls.append({"method": method, "path": path,
                          "headers": dict(kwargs.get("headers") or {})})
            return _Resp()

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.AsyncClient = FakeAsyncClient
    fake_httpx.HTTPError = type("HTTPError", (Exception,), {})
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    class FakeFastMCP:
        def __init__(self, name):
            pass

        def tool(self, *args, **kwargs):
            return lambda fn: fn

        def run(self):
            pass

    fake_fastmcp = types.ModuleType("fastmcp")
    fake_fastmcp.FastMCP = FakeFastMCP
    monkeypatch.setitem(sys.modules, "fastmcp", fake_fastmcp)

    for key, value in env.items():
        monkeypatch.setenv(key, value)

    target = tmp_path / "server.py"
    target.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("gen_s13_server", target)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, calls


def _call(module, tool_name: str, calls: list) -> dict:
    calls.clear()
    asyncio.run(getattr(module, tool_name)())
    assert calls, f"{tool_name} 根本没有发出请求"
    return calls[0]["headers"]


# --------------------------------------------------------------------------- #
# analyzer：逐端点记实际观测到的鉴权方式
# --------------------------------------------------------------------------- #
class TestAnalyzerRecordsPerEndpointHints:
    def test_each_endpoint_keeps_its_own_hint(self, tmp_path):
        analysis = analyze_capture(_mixed_capture(tmp_path))
        by_path = {ep["path"]: ep for ep in analysis["endpoints"]}

        assert by_path[BEARER_PATH]["auth_hint"] == ["Bearer"]
        assert by_path[COOKIE_PATH]["auth_hint"] == ["cookie"]
        assert by_path[BASIC_PATH]["auth_hint"] == ["Basic"]

    def test_cookie_names_are_union_not_overwritten(self, tmp_path):
        """Cookie 名单必须**跨该主机的全部分组取并集**。

        修复前是「最后一个带非空 Authorization 的分组覆盖前面所有分组」——
        Bearer/Basic 段不带 Cookie，于是 ``cookie_names`` 直接变成空，NITRO_SK
        这类无标记名字整类消失，生成物只填半罐 Cookie 且服务端不说是缺谁。
        """
        analysis = analyze_capture(_mixed_capture(tmp_path))
        host_info = analysis["auth_metadata"]["auth_schemes"][HOST]

        assert host_info["cookie_names"] == DEVICE_COOKIES

    def test_host_info_lists_every_observed_scheme(self, tmp_path):
        """主机级也要能看出「混用」—— `diff_hosts` 靠它报告。"""
        analysis = analyze_capture(_mixed_capture(tmp_path))
        host_info = analysis["auth_metadata"]["auth_schemes"][HOST]

        assert host_info["schemes"] == ["Bearer", "Basic"]


# --------------------------------------------------------------------------- #
# 生成物：按端点发出各自的鉴权头（假 httpx 抓实际请求）
# --------------------------------------------------------------------------- #
class TestGeneratedToolsSendPerEndpointCredentials:
    @staticmethod
    def _render(tmp_path) -> dict:
        return _registry_from_capture(_mixed_capture(tmp_path))

    def test_registry_carries_hint_through_to_generation(self, tmp_path):
        registry = self._render(tmp_path)
        by_path = _by_path(registry)

        assert by_path[BEARER_PATH]["auth_hint"] == ["Bearer"]
        assert by_path[COOKIE_PATH]["auth_hint"] == ["cookie"]

    def test_bearer_endpoint_gets_authorization_only(self, tmp_path, monkeypatch):
        registry = self._render(tmp_path)
        source = render_server(registry)["server.py"]
        module, calls = _load_server(tmp_path, source, monkeypatch, {
            "PORTAL_TOKEN": "tok-1",
            "PORTAL_COOKIE_PORTAL_EXAMPLE_COM": "JSESSIONID=js1; NITRO_SK=nk1",
        })

        headers = _call(module, _by_path(registry)[BEARER_PATH]["tool_name"], calls)

        assert headers.get("Authorization") == "Bearer tok-1"

    def test_cookie_endpoint_gets_the_whole_jar_and_no_authorization(self, tmp_path, monkeypatch):
        """这条就是修复前稳定 401 的那一类接口。"""
        registry = self._render(tmp_path)
        source = render_server(registry)["server.py"]
        module, calls = _load_server(tmp_path, source, monkeypatch, {
            "PORTAL_TOKEN": "tok-1",
            "PORTAL_COOKIE_PORTAL_EXAMPLE_COM": "JSESSIONID=js1; NITRO_SK=nk1",
        })

        headers = _call(module, _by_path(registry)[COOKIE_PATH]["tool_name"], calls)

        assert headers.get("Cookie") == "JSESSIONID=js1; NITRO_SK=nk1"
        assert "Authorization" not in headers

    def test_basic_endpoint_gets_basic_authorization(self, tmp_path, monkeypatch):
        registry = self._render(tmp_path)
        source = render_server(registry)["server.py"]
        module, calls = _load_server(tmp_path, source, monkeypatch, {
            "PORTAL_TOKEN": "tok-1",
            "PORTAL_BASIC_PASSWORD_PORTAL_EXAMPLE_COM": "pw",
        })

        headers = _call(module, _by_path(registry)[BASIC_PATH]["tool_name"], calls)

        assert headers.get("Authorization", "").startswith("Basic ")

    def test_endpoint_that_sends_both_gets_both(self, tmp_path, monkeypatch):
        """实测有接口两者都带：不能只发其中一个。"""
        registry = _registry_from_capture(_write_capture(tmp_path, [
            ("/api/both", {"Accept": "application/json",
                           "Authorization": "Bearer ***",
                           "Cookie": "JSESSIONID=***"}),
        ]))
        assert _by_path(registry)["/api/both"]["auth_hint"] == ["Bearer", "cookie"]

        source = render_server(registry)["server.py"]
        module, calls = _load_server(tmp_path, source, monkeypatch, {
            "PORTAL_TOKEN": "tok-1",
            "PORTAL_COOKIE_PORTAL_EXAMPLE_COM": "JSESSIONID=js1",
        })

        headers = _call(module, _by_path(registry)["/api/both"]["tool_name"], calls)

        assert headers.get("Authorization") == "Bearer tok-1"
        assert headers.get("Cookie") == "JSESSIONID=js1"


# --------------------------------------------------------------------------- #
# 对抗语料：新拼进生成物的 scheme 数据必须走 repr，不能字符串拼接
# --------------------------------------------------------------------------- #
PWN = '__import__("os").system("echo PWNED")'


def _tool_functions(source: str) -> list:
    import ast

    tree = ast.parse(source)
    found = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) \
                    and dec.func.attr == "tool":
                found.append(node)
    return found


class TestAdversarialAuthDataCannotInject:
    """``AUTH_SCHEME`` / ``HOST_AUTH_SCHEME`` 由抓包内容构成 —— 必须只当数据。"""

    def _registry(self, **over) -> dict:
        entry = {
            "tool_name": "get_x", "method": "GET", "host": HOST, "path": "/api/x",
            "path_params": [], "query_params": {}, "sample_count": 2,
            "auth_required": True, "auth_hint": ["Bearer"], "status": "active",
            "description": "d",
        }
        entry.update(over)
        return {"site_name": "portal", "registry_version": 1,
                "hosts": {HOST: {"scheme": "Bearer", "cookie_names": ["JSESSIONID"]}},
                "endpoints": [entry], "auth_login": None}

    CASES = {
        "scheme 里带引号与调用": {"auth_hint": [f'Bearer" ; {PWN} ; _d = ("']},
        "scheme 里带换行": {"auth_hint": ['Bearer\n' + PWN]},
        "主机名注入": {"host": f'{HOST}"\n{PWN} #'},
        "工具名注入": {"tool_name": f'{PWN}'},
        "cookie 名单注入": None,   # 见 test_cookie_names_are_data
    }

    def test_each_case_still_compiles(self):
        for case, over in self.CASES.items():
            if over is None:
                continue
            source = render_server(self._registry(**over))["server.py"]
            compile(source, "server.py", "exec")       # 不抛即通过

    def test_no_executable_call_inside_tool_bodies(self):
        for case, over in self.CASES.items():
            if over is None:
                continue
            source = render_server(self._registry(**over))["server.py"]
            tools = _tool_functions(source)
            assert tools, f"{case}: 未渲染出工具函数，测试本身失效"
            import ast
            for tool in tools:
                for node in ast.walk(tool):
                    if isinstance(node, ast.Call):
                        fn = node.func
                        assert not (isinstance(fn, ast.Name) and fn.id == "__import__"), case
                        assert not (isinstance(fn, ast.Attribute) and fn.attr == "system"), case

    def test_cookie_names_are_data(self, tmp_path, monkeypatch):
        """恶意取值必须**原样当数据**往返 —— 既不破坏语法，也不变成代码。"""
        malicious = f'x" ; {PWN} ; _d = ("'
        registry = self._registry()
        registry["hosts"][HOST]["cookie_names"] = [malicious]
        source = render_server(registry)["server.py"]
        compile(source, "server.py", "exec")            # 不抛即通过

        module, _ = _load_server(tmp_path, source, monkeypatch, {})
        assert module.CREDENTIAL_COOKIES[HOST] == [malicious]


# --------------------------------------------------------------------------- #
# 合并侧：Cookie 取并集、scheme 不被静默降级、混用只告知不拦
# --------------------------------------------------------------------------- #
def _project(tmp_path: Path) -> Path:
    directory = tmp_path / "proj"
    init_project(directory, "portal")
    return directory


class TestMergeKeepsAuthKnowledge:
    def _hosts(self, cookie_names: list[str] | None = None,
               scheme: str | None = "Bearer") -> dict:
        return {HOST: {"scheme": scheme, "schemes": [scheme] if scheme else [],
                       "cookie_names": cookie_names or DEVICE_COOKIES}}

    def test_cookie_names_are_unioned_across_merges(self, tmp_path):
        project = _project(tmp_path)
        merge_registry(project, [], self._hosts(["JSESSIONID"]), "s1")
        merge_registry(project, [], self._hosts(["NITRO_SK"]), "s2")

        assert load_registry(project)["hosts"][HOST]["cookie_names"] == \
            ["JSESSIONID", "NITRO_SK"]

    def test_scheme_is_never_downgraded_to_none(self, tmp_path):
        """这一轮没再抓到 Authorization **不得**把已有方案抹掉 —— 抹掉之后生成物
        不再发 Authorization，Bearer 站点的工具全部 401，而用户看不到这件事。
        """
        project = _project(tmp_path)
        merge_registry(project, [], self._hosts(["JSESSIONID"], scheme="Bearer"), "s1")
        merge_registry(project, [], self._hosts(["JSESSIONID"], scheme=None), "s2",
                       allow_auth_change=True)

        assert load_registry(project)["hosts"][HOST]["scheme"] == "Bearer"

    def test_downgrade_is_refused_by_default_with_readable_message(self, tmp_path):
        project = _project(tmp_path)
        merge_registry(project, [], self._hosts(["JSESSIONID"], scheme="Bearer"), "s1")

        result = merge_registry(project, [], self._hosts(["JSESSIONID"], scheme=None), "s2")

        assert result["success"] is False
        assert result["error"] == "auth_scheme_changed"
        # 面向非技术用户的措辞：不出现 scheme / registry / 合并 这类词。
        assert "登录方式" in result["message"]
        assert "allow_auth_change=true" in result["message"]

    def test_mixed_schemes_are_reported_but_do_not_block(self, tmp_path):
        """混用是受支持的形态（按端点各自取用），只告知、不拦。"""
        project = _project(tmp_path)
        merge_registry(project, [], self._hosts(["JSESSIONID"], scheme="Bearer"), "s1")

        mixed = {HOST: {"scheme": "Bearer", "schemes": ["Bearer", "Basic"],
                        "cookie_names": DEVICE_COOKIES}}
        result = merge_registry(project, [], mixed, "s2")

        assert result["success"] is True
        assert is_conflict_change(result["auth_conflicts"][0]) is True
        assert "不需要" in result["auth_conflicts_hint"]
        assert load_registry(project)["hosts"][HOST]["schemes"] == ["Bearer", "Basic"]

    def test_endpoint_hints_are_unioned_across_merges(self, tmp_path):
        project = _project(tmp_path)
        bearer = {"tool_name": "get_x", "method": "GET", "host": HOST, "path": "/api/x",
                  "path_params": [], "query_params": {}, "sample_count": 1,
                  "auth_required": True, "auth_hint": ["Bearer"], "status": "active"}
        cookie = dict(bearer)
        cookie["auth_hint"] = ["cookie"]
        merge_registry(project, [bearer], self._hosts(), "s1")
        merge_registry(project, [cookie], self._hosts(), "s2")

        stored = load_registry(project)["endpoints"][0]
        assert stored["auth_hint"] == ["Bearer", "cookie"]


# --------------------------------------------------------------------------- #
# README 鉴权节必须讲清「同一服务器上不同接口可以不一样的登录方式」
# --------------------------------------------------------------------------- #
class TestReadmeExplainsMixedAuth:
    def test_mixed_host_is_called_out_and_needs_no_user_action(self, tmp_path):
        registry = _registry_from_capture(_mixed_capture(tmp_path))
        readme = render_server(registry)["README.md"]

        assert "不同接口用了不同的登录方式" in readme
        assert "你不需要手动区分" in readme

    def test_single_scheme_host_is_not_reported_as_mixed(self, tmp_path):
        registry = _registry_from_capture(_write_capture(tmp_path, [
            (BEARER_PATH, {"Accept": "application/json", "Authorization": "Bearer ***"}),
        ]))
        readme = render_server(registry)["README.md"]

        assert "不同接口用了不同的登录方式" not in readme

    def test_host_line_lists_every_method_in_use(self, tmp_path):
        """混用域名只写其中一种，会让用户以为另一半接口也用那种。"""
        readme = render_server(_registry_from_capture(_mixed_capture(tmp_path)))["README.md"]

        assert f"- `{HOST}`：Bearer / Cookie / Basic" in readme

    def test_basic_password_config_appears_for_a_basic_endpoint_only(self, tmp_path):
        """Basic 口令是**配置项**：只看主机级 scheme 会漏掉「同一域名里那个 Basic 接口」，
        它拿不到口令就永远 401。
        """
        registry = _registry_from_capture(_mixed_capture(tmp_path))
        files = render_server(registry)

        assert "PORTAL_BASIC_PASSWORD_PORTAL_EXAMPLE_COM=" in files[".env.example"]
        assert "PORTAL_BASIC_PASSWORD_<HOST>" in files["README.md"]
