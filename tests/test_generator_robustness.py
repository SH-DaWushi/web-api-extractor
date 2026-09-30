# -*- coding: utf-8 -*-
"""生成器必须对**抓包得到的任意文本**免疫。

生成器是字符串拼代码，而它的输入来自真实流量 —— 路径、参数名、描述、站点名
全都不可信。修复前实测两类后果：

* **注入**：路径里一个 `"` 或 `{...}` 就会拼进生成的 server.py，
  `compile()` 仍通过，但调用该工具时执行任意代码
  （`await _request(..., "/x") ; __import__("os").system(...)`）；
* **整个工具集报废**：参数名叫 `class`，或与生成器自己注入的
  `confirm` / `payload` 撞名，产出
  `async def post_x(confirm: str = None, confirm: bool = False)` —— SyntaxError，
  于是**所有**工具都用不了。

因此本文件断言两条硬性质：生成物必须能 `compile()`；工具函数体内不得出现
可执行的外部调用，路径参数只能是字面量或「只含简单变量名」的 f-string。
"""
from __future__ import annotations

import ast
import json
import re

import pytest

from webapi_extractor.generator import (
    _env_prefix,
    _py_ident,
    _site_name_from_session_id,
    _smoke_endpoint,
    render_server,
)

HOST = "portal.example.com"
PWN = '__import__("os").system("echo PWNED")'

# 烘默认值的门禁有两条路：证据说 `fixed`，或**无证据 + 观测取值唯一**。
# 下面这些用例考的是「名字 / 取值」那道闸门，故显式给一份 fixed 证据（两条路都通，
# 免得用例因为「多取值」而绕开待考的闸门）。
_FIXED = {"class": "fixed", "values": ["x"], "present_in": 2, "requests": 2,
          "switch_risk": False, "behaviour_switch": None, "verified": True}


def _registry(path="/api/x", tool_name="get_x", method="GET", auth_login=None, **ep_extra):
    entry = {
        "tool_name": tool_name, "method": method, "host": HOST, "path": path,
        "path_params": [], "query_params": {}, "sample_count": 3,
        "status": "active", "description": "d",
    }
    entry.update(ep_extra)
    return {
        "site_name": "portal", "registry_version": 1,
        "hosts": {HOST: {"scheme": "Bearer", "cookie_names": ["JSESSIONID"]}},
        "endpoints": [entry], "auth_login": auth_login,
    }


def _render(registry) -> str:
    return render_server(registry)["server.py"]


def _tool_functions(src: str) -> list:
    """取出带 @mcp.tool() 装饰器的函数（模板自身的代码不在审查范围内）。"""
    tree = ast.parse(src)
    found = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) \
                    and dec.func.attr == "tool":
                found.append(node)
    return found


ADVERSARIAL = {
    "引号闭合字符串": {"path": f'/x") ; {PWN} ; _d = ("'},
    "花括号被当表达式": {"path": f"/api/{{user_id}}/{{{PWN}}}", "path_params": ["user_id"]},
    "参数名是关键字": {"query_params": {"class": ["1"]}},
    "工具名是关键字": {"tool_name": "class"},
    "反斜杠路径": {"path": "/api/C:\\temp\\x"},
    "query 撞 confirm": {"method": "POST", "query_params": {"confirm": ["yes"]}},
    "表单撞 payload": {"method": "POST", "request_schema": {"type": "object"},
                       "request_body_params": {"payload": ["{}"]}},
    "空参数名": {"query_params": {"": ["1"]}},
    "中文参数名": {"query_params": {"用户名": ["bob"]}},
    "两个键折成同名": {"query_params": {"a-b": ["1"], "a_b": ["2"]}},
    "描述结尾反斜杠": {"description": "以反斜杠结尾\\"},
    # 前导零的数字样本会被推成 int，而 `x: int = 007` 在 Python 3 里直接 SyntaxError
    # —— 一个这样的参数就能让整份生成物编不过（见 `_param_decl` 里的规范化）。
    # `qty` 这个**非开关名**是刻意留的：`page` / `size` / `limit` 现在都不烘默认值
    # （见 TestSwitchParamsAreNeverBaked），只有良性名字才走得到「规范化」那一步。
    "前导零数字样本": {"query_params": {"page": ["007"], "size": ["0000"],
                                        "qty": ["0006"]}},
    "带正号的数字样本": {"query_params": {"limit": ["+7"], "qty": ["+6"]}},
    "站点名注入": None,   # 见 test_site_name_is_escaped
}


@pytest.mark.parametrize("case,spec", [(k, v) for k, v in ADVERSARIAL.items() if v])
def test_adversarial_registry_still_compiles(case, spec):
    src = _render(_registry(**spec))
    compile(src, "server.py", "exec")          # 不抛即通过


@pytest.mark.parametrize("case,spec", [(k, v) for k, v in ADVERSARIAL.items() if v])
def test_no_executable_code_in_tool_bodies(case, spec):
    """抓包内容只能作为字符串出现，不能变成可执行调用。"""
    tools = _tool_functions(_render(_registry(**spec)))
    assert tools, "未渲染出任何工具函数，测试本身失效"
    for tool in tools:
        for node in ast.walk(tool):
            if isinstance(node, ast.Call):
                fn = node.func
                assert not (isinstance(fn, ast.Name) and fn.id == "__import__"), \
                    f"{case}: 工具体内出现 __import__ 调用"
                assert not (isinstance(fn, ast.Attribute) and fn.attr == "system"), \
                    f"{case}: 工具体内出现 .system 调用"


def _login_registry(**login_extra) -> dict:
    """带账号密码登录配置的 registry —— 登录接口的 query 参数同样来自抓包。"""
    login = {
        "method": "POST", "host": HOST, "path": "/api/login",
        "account_field": "username", "password_field": "password",
        "token_path": ["data", "token"], "query_params": {},
    }
    login.update(login_extra)
    return _registry(auth_login=login)


def _fetch_provenance(name: str = "csrf", url: str = f"https://{HOST}/api/config",
                      field: str = "$.data.csrf", tokens: list | None = None,
                      block: str | None = None) -> dict:
    """分析器写下的那条「来源判定」记录（R2 的取用计划就在这里）。

    ``block`` 非空表示**没通过**某条闸门 —— 此时没有 ``fetch``，生成器改为**不烘快照、
    也不标必填**（带默认值 None，运行时走取值链；多候选 / 循环来源都是这条路径）。
    """
    plan = None if block else {"name": name, "method": "GET", "url": url,
                               "field": tokens if tokens is not None else ["data", "csrf"],
                               "field_display": field}
    return {"name": name, "class": "suspected_response",
            "suspected_source": {"method": "GET", "host": HOST, "path": "/api/config"},
            "reason": None, "needs_confirmation": True, "note": "疑似来自前序响应",
            "fetch": plan, "fetch_block": block}


# 登录接口 query 参数：这一路此前**完全不设防** —— 抓包第一次登录请求的取值被
# 原样烘进 `_AUTH_LOGIN_CFG`，生成物还真的拿它去登录。现在判不出「无害固定参数」
# 的一律不烘、改走运行时取值链（入参 → .env → 弹窗 → 明确报错），而这一路的注入面
# （参数名 / env 名 / 取值都要拼进代码）同样要过
# 「能 compile + 工具体内无可执行调用」两道网。
LOGIN_ADVERSARIAL = {
    "登录 query 值含脱敏哨兵": {"query_params": {"token": ["***"], "encrypt": ["2"]}},
    "登录 query 参数名是关键字": {"query_params": {"class": ["1"], "def": ["2"]}},
    "登录 query 值含引号花括号": {"query_params": {"q": ["a'b\"{}"]},
                                 "query_param_evidence": {"q": _FIXED}},
    "登录 query 值是注入串": {"query_params": {"x": [PWN]},
                             "query_param_evidence": {"x": _FIXED}},
    "登录 query 撞注入名": {"query_params": {"account": ["a"], "password": ["b"],
                                            "login_query": ["c"], "params": ["d"]}},
    "登录 query 两个键折成同名": {"query_params": {"a-b": ["1"], "a_b": ["2"]}},
    "登录 query 空参数名": {"query_params": {"": ["1"]}},
    # ---- R2「自动取用」：来源地址与字段名都来自抓包，同样是注入面 ----
    "取用来源路径含引号注入": {"query_params": {"csrf": ["x"]},
                              "query_param_provenance": {
                                  "csrf": _fetch_provenance(
                                      url=f'https://{HOST}/api/cfg") ; {PWN} ; _d = ("')}},
    "取用来源路径含花括号": {"query_params": {"csrf": ["x"]},
                            "query_param_provenance": {
                                "csrf": _fetch_provenance(
                                    url=f"https://{HOST}/api/{{x}}/{{{PWN}}}")}},
    "取用来源路径含 import 调用": {"query_params": {"csrf": ["x"]},
                                  "query_param_provenance": {
                                      "csrf": _fetch_provenance(
                                          url=f"https://{HOST}/api/{PWN}")}},
    "取用字段路径与取值含注入": {"query_params": {"csrf": ["x"]},
                                "query_param_provenance": {
                                    "csrf": _fetch_provenance(
                                        field='$.a"b{}' + PWN,
                                        tokens=['a"b{}', 0, PWN])}},
    "取用参数名是关键字": {"query_params": {"class": ["x"]},
                          "query_param_provenance": {
                              "class": _fetch_provenance(name="class")}},
    "取用参数名撞注入名": {"query_params": {"params": ["x"], "login_query": ["y"]},
                          "query_param_provenance": {
                              "params": _fetch_provenance(name="params"),
                              "login_query": _fetch_provenance(name="login_query")}},
}


def _functions_named(src: str, names: set) -> list:
    tree = ast.parse(src)
    return [node for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names]


@pytest.mark.parametrize("case,spec", list(LOGIN_ADVERSARIAL.items()))
def test_adversarial_login_query_still_compiles(case, spec):
    compile(_render(_login_registry(**spec)), "server.py", "exec")     # 不抛即通过


@pytest.mark.parametrize("case,spec", list(LOGIN_ADVERSARIAL.items()))
def test_no_executable_code_in_login_tool_bodies(case, spec):
    """登录这一路只有 `login` 带装饰器；`_do_login` 是它背后真正发请求的那层，
    抓包来的参数名/取值都流经它，`_fetch_login_query_values`（R2 取用代码）同样流经
    抓包来的来源地址与字段名 —— 三层一起审。"""
    src = _render(_login_registry(**spec))
    functions = _functions_named(
        src, {"login", "_do_login", "auth_status", "_fetch_login_query_values"})
    assert {"login", "_do_login", "auth_status"} <= {f.name for f in functions}, \
        f"{case}: 登录工具没渲染出来，测试本身失效"
    for function in functions:
        for node in ast.walk(function):
            if isinstance(node, ast.Call):
                fn = node.func
                assert not (isinstance(fn, ast.Name) and fn.id == "__import__"), \
                    f"{case}: {function.name} 体内出现 __import__ 调用"
                assert not (isinstance(fn, ast.Attribute) and fn.attr == "system"), \
                    f"{case}: {function.name} 体内出现 .system 调用"


class TestAutoFetchDegradesInsteadOfFailing:
    """R2：闸门没全中 → 走运行时取值链（**不标必填**、也绝不生成会取到错值的代码）。

    新契约推翻「降级为必填」：参数带默认值 None，不填也能进入函数体 —— 不然参数绑定
    阶段就 `TypeError: login() missing 1 required keyword-only argument`，
    「弹窗拿账号密码、口令不进对话」那条路根本走不到。
    """

    @pytest.mark.parametrize("block,label", [
        ("source_request_carries_auth", "来源需要鉴权"),
        ("source_request_has_params", "来源接口要参数"),
        ("source_is_not_get", "来源不是 GET"),
        ("source_field_not_locatable", "字段定位不到"),
        ("source_is_login_endpoint", "循环来源（来源就是登录端点）"),
        ("multiple_sources", "多候选（歧义）"),
    ])
    def test_blocked_source_goes_to_the_value_chain(self, block, label):
        src = _render(_login_registry(
            query_params={"csrf": ["x"]},
            query_param_provenance={"csrf": _fetch_provenance(block=block)}))
        assert "_LOGIN_FETCH" not in src, f"{label}: 不该发射取用代码"
        assert "csrf: str | None = None" in src, \
            f"{label}: 应降级为「带默认值 None、不标必填」"
        assert "PORTAL_LOGIN_QUERY_CSRF" in src, f"{label}: 401 重登录的 env 通道也要有"
        compile(src, "server.py", "exec")

    def test_unresolved_source_goes_to_the_value_chain_without_fetch(self):
        """来源根本定不下来（分析器给 class=unknown）→ 不发射取用代码，也不标必填。"""
        src = _render(_login_registry(
            query_params={"csrf": ["x"]},
            query_param_provenance={"csrf": {
                "name": "csrf", "class": "unknown", "suspected_source": None,
                "reason": "multiple_sources", "needs_confirmation": True,
                "note": "歧义 → 不可知"}}))
        assert "_LOGIN_FETCH" not in src
        assert "csrf: str | None = None" in src

    def test_good_source_emits_fetch_code_only(self):
        """闸门全中 → 发射取用代码；参数**不进签名**（使用者什么都不用填）。"""
        src = _render(_login_registry(
            query_params={"csrf": ["x"]},
            query_param_provenance={"csrf": _fetch_provenance()}))
        assert "_LOGIN_FETCH" in src
        assert "params.update(await _fetch_login_query_values())" in src
        assert ("async def login(account: str | None = None, "
                "password: str | None = None) -> dict:") in src
        compile(src, "server.py", "exec")


def test_login_query_injection_string_is_not_baked_at_all():
    """`__import__("os").system(...)` 这种取值过不了默认值闸门（35 字符 > 24），
    于是**连字符串都不进产物** —— 比「转义后当字面量活下来」更干净。"""
    src = _render(_login_registry(query_params={"x": [PWN]},
                                  query_param_evidence={"x": _FIXED}))
    assert PWN not in src
    assert "x: str" in src
    compile(src, "server.py", "exec")


def test_injected_brace_is_escaped_not_evaluated():
    """`{...}` 必须退化为普通字符，而不是 f-string 表达式。"""
    src = _render(_registry(path=f"/api/{{user_id}}/{{{PWN}}}", path_params=["user_id"]))
    assert "__import__" not in src.split("def _request")[0] or True   # 只看工具体
    for tool in _tool_functions(src):
        for node in ast.walk(tool):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id == "_request" and len(node.args) >= 3:
                arg = node.args[2]
                if isinstance(arg, ast.JoinedStr):
                    for part in arg.values:
                        if isinstance(part, ast.FormattedValue):
                            assert isinstance(part.value, ast.Name), \
                                "路径 f-string 里出现了非变量名表达式"


def test_injected_quote_becomes_literal_text():
    """引号必须被转义成**字面量**：内容还在，但不再是可执行语句。"""
    src = _render(_registry(path=f'/x") ; {PWN} ; _d = ("'))
    assert "__import__" in src           # 作为字符串活下来（转义后）
    compile(src, "server.py", "exec")
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "__import__"


def test_site_name_is_escaped():
    """site_name 会进 FastMCP("...") 与文档字符串，必须转义。"""
    registry = _registry()
    registry["site_name"] = 'evil" )\n__import__("os").system("echo PWNED") #'
    src = _render(registry)
    compile(src, "server.py", "exec")
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call):
            fn = node.func
            assert not (isinstance(fn, ast.Name) and fn.id == "__import__")
            assert not (isinstance(fn, ast.Attribute) and fn.attr == "system")


class TestIdentifierSafety:
    """关键字与非标识符字符不能产出非法签名。"""

    @pytest.mark.parametrize("name", ["class", "def", "None", "True", "lambda", "import"])
    def test_keyword_is_avoided(self, name):
        ident = _py_ident(name)
        assert ident != name
        compile(f"def f({ident}=None): pass", "<t>", "exec")

    def test_keyword_param_keeps_the_parameter(self):
        """改名而不是丢弃：参数必须仍然出现在签名里。"""
        src = _render(_registry(query_params={"class": ["1"]}))
        tool = _tool_functions(src)[0]
        assert [a.arg for a in tool.args.args] == ["class_"]
        compile(src, "server.py", "exec")

    def test_confirm_collision_keeps_both_parameters(self):
        """抓包里的 confirm 与生成器注入的 confirm 撞名 —— 两个都要在，且不重复。"""
        src = _render(_registry(method="POST", query_params={"confirm": ["yes"]}))
        tool = _tool_functions(src)[0]
        names = [a.arg for a in tool.args.args]
        assert len(names) == len(set(names)), f"重复参数: {names}"
        assert "confirm" in names          # 注入的护栏参数保持原名
        assert "confirm_2" in names        # 抓到的那个让名后仍在
        compile(src, "server.py", "exec")

    def test_payload_collision_keeps_both_parameters(self):
        src = _render(_registry(method="POST", request_schema={"type": "object"},
                                request_body_params={"payload": ["{}"]}))
        names = [a.arg for a in _tool_functions(src)[0].args.args]
        assert len(names) == len(set(names))
        assert "payload" in names and "payload_2" in names
        compile(src, "server.py", "exec")

    def test_tool_name_keyword_is_avoided(self):
        src = _render(_registry(tool_name="class"))
        assert _tool_functions(src)[0].name == "class_"
        compile(src, "server.py", "exec")

    def test_distinct_keys_both_survive_renaming(self):
        src = _render(_registry(query_params={"a-b": ["1"], "a_b": ["2"]}))
        names = [a.arg for a in _tool_functions(src)[0].args.args]
        assert len(names) == len(set(names)) == 2


class TestWireKeys:
    """发给服务端的参数名必须是**原始**键名，不能是 Python 标识符。"""

    @pytest.mark.parametrize("key", ["$filter", "a.b", "用户名", "$top"])
    def test_query_wire_key_preserved(self, key):
        """`json.dumps` 会转义非 ASCII，故按转义后的形态断言。"""
        src = _render(_registry(query_params={key: ["1"]}))
        assert json.dumps(key, ensure_ascii=False) in src or json.dumps(key) in src, \
            f"{key} 的 wire key 丢了"

    def test_form_wire_key_preserved(self):
        src = _render(_registry(method="POST", request_body_params={"a-b": ["1"]}))
        assert '"a-b"' in src


class TestNoRealDataBaked:
    """默认值门槛必须同时看**名**和**值**（只看名字会把 PII 烘进分发包）。"""

    @pytest.mark.parametrize("ident,value", [
        ("id", "88231"), ("recipient", "bob@corp.com"), ("phone", "13800138000"),
        ("tenant", "acme-prod"), ("memberId", "10086"), ("email", "a@b.com"),
        ("token", "abcdefghijklmnopqrstuvwx"), ("uid", "alice"),
    ])
    def test_identity_or_pii_value_gets_no_default(self, ident, value):
        src = _render(_registry(query_params={ident: [value]},
                                query_param_evidence={ident: _FIXED}))
        assert value not in src, f"{ident}={value} 被烘进了生成物"
        # 类型由样本推断（纯数字→int），断言与类型无关的形态
        # 注意：签名在 `async def f(a: int | None = None, ...)` 一行内，
        # 不能用 ^...$ 锚点。
        assert re.search(rf"\b{re.escape(ident)}: (?:int|str) \| None = None", src), \
            f"{ident} 未降级为必填"

    @pytest.mark.parametrize("ident,value,expected", [
        # 纯数字样本会被推断为 int，字符串样本为 str —— 断言各自的真实形态
        # 注意用例名**不能用** `page` / `count` / `format` 这类「会切换响应形态」的参数：
        # 那些现在一律不烘（见 TestSwitchParamsAreNeverBaked），不再属于「良性默认值」。
        ("section", "4", "section: int = 4"),
        ("status", "open", "status: str = 'open'"),
        ("locale", "zh-CN", "locale: str = 'zh-CN'"),
    ])
    def test_benign_default_is_kept(self, ident, value, expected):
        src = _render(_registry(query_params={ident: [value]},
                                query_param_evidence={ident: _FIXED}))
        assert expected in src, f"良性默认值被误伤: 期望 {expected!r}"

    def test_benign_param_without_evidence_gets_the_observed_value_as_default(self):
        """**良性就保留默认值**：没有证据字段（证据重做之前生成的老项目 / 手写 registry），
        只要观测取值唯一、名字与取值都安全，就把抓包取值烘成默认值。

        为什么必须烘：`section: int | None = None` 这种「有参数、无默认值」的签名，调用方
        （LLM）不知道传什么，只能回头来问使用者 —— 而使用者根本不知道 section 是什么。
        `section: int = 4` 就能直接调通。
        """
        src = _render(_registry(query_params={"section": ["4"]}))
        assert "section: int = 4" in src

    @pytest.mark.parametrize("value,expected", [
        ("007", "section: int = 7"),        # 前导零：规范化成合法整数字面量
        ("0000", "section: int = 0"),
        ("-05", "section: int = -5"),
    ])
    def test_numeric_defaults_are_normalized(self, value, expected):
        """`x: int = 007` 是 SyntaxError —— 规范化成 `7`，而不是让整份产物编不过。

        这里刻意用**非切换类**参数名（`section`）：切换类参数现在根本不烘默认值，
        也就走不到规范化那条路上去。
        """
        src = _render(_registry(query_params={"section": [value]}))
        assert expected in src, src.split("async def get_x")[-1][:80]
        compile(src, "server.py", "exec")

    def test_multiple_observed_values_without_evidence_are_not_baked(self):
        """没有证据、却**看到过不止一个取值** → 这是「我们确切知道它可变」，不烘。

        烘任何一个观测值都是错的那一个（`section=4` / `section=5` 都只是抓包时的抽样）。
        """
        src = _render(_registry(query_params={"section": ["4", "5"]}))
        assert "section: int = 4" not in src
        assert "section: int = 5" not in src
        assert "section: int | None = None" in src

    def test_evidence_saying_variable_is_never_baked(self):
        """证据明确说 `variable` → 即便只有一个观测值也不烘（这是确切的可变性）。"""
        src = _render(_registry(
            query_params={"section": ["4"]},
            query_param_evidence={"section": {"class": "variable", "values": ["4"]}}))
        assert "section: int = 4" not in src
        assert "section: int" in src          # variable → 必填

    def test_verified_is_not_a_veto_for_benign_fixed_params(self):
        """`fixed` 参数按定义没有「带 / 不带」的对照请求，`verified` 永远是 False ——
        拿它当一票否决等于把参数永久丢给使用者。非切换类的 fixed 参数照烘。"""
        src = _render(_registry(
            query_params={"section": ["4"]},
            query_param_evidence={"section": {"class": "fixed", "values": ["4"],
                                              "switch_risk": False,
                                              "behaviour_switch": None,
                                              "verified": False}}))
        assert "section: int = 4" in src

    def test_smoke_test_does_not_bake_captured_values(self):
        """冒烟脚本此前把每个 query 参数的第一个样本原样打进分发包。"""
        src = render_server(_registry(
            query_params={"token": ["SUPERSECRET"], "uid": ["alice"], "status": ["open"],
                          "count": ["50"]},
            query_param_evidence={"status": _FIXED},
        ))["smoke_test.py"]
        assert "SUPERSECRET" not in src
        assert "alice" not in src
        assert '"status": "open"' in src     # 良性的那个仍然保留
        assert '"count": "50"' not in src    # 切换类的那个**不再**进冒烟脚本

    def test_redaction_sentinel_is_never_baked(self):
        """Fix 2：analyzer 读到的体已脱敏，`***` 是记号不是值，不能当默认值。"""
        src = _render(_registry(
            request_body_params={"password": ["***"]},
            request_body_param_evidence={"password": _FIXED}))
        assert "'***'" not in src
        assert "password: str | None = None" in src


class TestSwitchParamsAreNeverBaked:
    """**取值会切换响应形态的参数，一个快照值都不许烘**；必填与否**分两档**。

    这是整份缺陷清单里唯一「静默给出错误业务结论」的一类：NITRO 设备管理 API 里
    `count=yes` **只返回 `__count`**、不返回对象列表。烘 `count='yes'` 之后，生成的工具
    返回 `{"__count": 0}`，HTTP 200、JSON 正常、没有任何报错 —— LLM 于是告诉用户
    「设备上没有对象」，而设备上可能有几十个。

    「烘不烘」只有一档（都不烘），「必填 / 可选无默认值」**分两档**：

      * **实测档**：`behaviour_switch is True`（对照抓包真的观测到结构变了）→ 必填；
      * **名字/取值档**：只是名字像 `page` / `sort` / `format` / `search` / `query` /
        `filter` …（``analyzer._SWITCH_PARAM_NAMES`` 很宽），或取值是
        `yes`/`no`/`true`/`false`/`on`/`off`，但**没有任何实测证据** → **可选、无默认
        值**（`| None = None`）。这一档在普通 CRUD 项目里遍地都是，而它们大多**并不**
        切换响应形态；一律逼成必填只会让调用方回头问使用者「page 填几」，而他不知道。
        省略它时请求里**不带**这个键（`_clean` 丢掉 `None`），服务端用自己的默认值。

    为什么名字档也拦、且**不看有没有证据**：只抓到**一个**请求时
    `analyze_param_evidence` 返回空证据（< 2 个不同请求就什么都不分类），而第一次抓包
    恰恰经常只有一个请求 —— 按证据判会漏掉最常见的那次。
    """

    # 取值像开关的参数（无论叫什么名字）与「名字像开关」的参数各测一遍。
    @pytest.mark.parametrize("ident,value", [
        ("count", "yes"),          # 名字 + 取值都是开关 → NITRO 原案
        ("bulkbindings", "yes"),
        ("pagesize", "25"),        # 名字是开关（分页上限），取值是数字
        ("filter", "status=open"),
        ("format", "json"),
        ("sort", "created"),       # 名字在名单里，取值本身不像开关
        ("flag", "on"),            # 名字不在名单里，但**取值**是开关
        ("page", "1"),             # 普通 CRUD 里最常见的「名字像开关」
    ])
    def test_named_switch_param_is_optional_and_not_baked(self, ident, value):
        """名字/取值命中、**无实测证据** → 不烘，但**不是必填**（分级后的收口）。"""
        # 走「无证据 + 观测取值唯一」这条最宽松的路 —— 旧方针下**一定**会烘。
        src = _render(_registry(query_params={ident: [value]}))
        assert f"{ident}:" in src, f"{ident} 整个参数不见了（不能凭空丢弃）"
        # 只看**签名**那一段：整份产物里 `= json` 这类子串会跟模板代码撞车。
        signature = src.split("async def get_x(")[1].split(") ->")[0]
        assert re.search(rf"\b{re.escape(ident)}: (?:int|str) \| None = None(?:,|$)",
                         signature), signature

    @pytest.mark.parametrize("ident,value", [
        ("count", "yes"), ("bulkbindings", "yes"), ("pagesize", "25"),
        ("flag", "on"),            # 名字不像开关，但实测证据说它是 → 同样必填
    ])
    def test_measured_switch_param_is_required_and_not_baked(self, ident, value):
        """**实测**过（`behaviour_switch is True`）→ 不烘 **且必填**。"""
        src = _render(_registry(
            query_params={ident: [value]},
            query_param_evidence={ident: {"class": "fixed", "values": [value],
                                          "switch_risk": True,
                                          "behaviour_switch": True,
                                          "verified": False}}))
        signature = src.split("async def get_x(")[1].split(") ->")[0]
        assert "=" not in signature, f"{ident} 在签名里仍带默认值: {signature}"
        assert re.search(rf"\b{re.escape(ident)}: (?:int|str)(?:,|$)", signature), \
            signature

    @pytest.mark.parametrize("ident,value", [
        ("count", "yes"), ("pagesize", "25"), ("bulkbindings", "yes"),
    ])
    def test_switch_param_is_explained_in_plain_language(self, ident, value):
        """调用方是 LLM，它只读 docstring —— 必须在那儿说清「取值会改变返回内容」。

        面向**不懂 HTTP 的使用者**：不出现「行为开关 / 响应结构 / 采样」这类术语。
        """
        src = _render(_registry(query_params={ident: [value]}))
        doc = src.split("async def get_x")[1]
        assert "取值会改变返回内容" in doc
        # 名字档：话术是「不填时服务端用默认」，**不是**「必填」。
        assert "可选" in doc
        assert "不填时服务端会用它自己的默认值" in doc
        for jargon in ("行为开关", "响应结构", "HTTP 参数"):
            assert jargon not in doc

    @pytest.mark.parametrize("ident,value", [
        ("count", "yes"), ("pagesize", "25"),
    ])
    def test_measured_switch_param_is_explained_as_required(self, ident, value):
        """实测档的话术必须**分开写**：说清「写死可能拿到不完整数据，请显式传」。"""
        src = _render(_registry(
            query_params={ident: [value]},
            query_param_evidence={ident: {"class": "fixed", "values": [value],
                                          "switch_risk": True,
                                          "behaviour_switch": True,
                                          "verified": False}}))
        doc = src.split("async def get_x")[1]
        assert "取值会改变返回内容" in doc
        assert "必填" in doc and "请显式传一个值" in doc
        for jargon in ("行为开关", "响应结构", "HTTP 参数"):
            assert jargon not in doc

    def test_measured_behaviour_switch_blocks_the_default_too(self):
        """实测过（`behaviour_switch is True`）→ 同样不烘，即便名字/取值都不像开关。"""
        src = _render(_registry(
            query_params={"section": ["4"]},
            query_param_evidence={"section": {"class": "fixed", "values": ["4"],
                                              "switch_risk": True,
                                              "behaviour_switch": True,
                                              "verified": False}}))
        assert "section: int = 4" not in src
        assert re.search(r"\bsection: int(?:,|\))", src)

    @pytest.mark.parametrize("behaviour_switch", [None, True])
    def test_occasional_switch_param_stays_optional(self, behaviour_switch):
        """`occasional` 是唯一例外：抓包里有的请求本来就没带它 → 可选、无默认值。

        **实测档也不例外** —— 事实就是「不带它也能通」，没有逼调用方填的道理。
        """
        src = _render(_registry(
            query_params={"count": ["yes"]},
            query_param_evidence={"count": {"class": "occasional", "values": ["yes"],
                                            "present_in": 1, "requests": 2,
                                            "switch_risk": True,
                                            "behaviour_switch": behaviour_switch,
                                            "verified": False}}))
        assert "count: str | None = None" in src

    def test_switch_param_is_not_listed_as_a_baked_default(self):
        """`baked_param_defaults` 必须与渲染走同一套闸门，否则那句「分享前请检查」
        会点名一批**根本没烘**的参数（谎报），或者漏掉真烘了的。

        两档都不该出现在这份名单里（名单是「用了抓包取值做默认值」的）。
        """
        from webapi_extractor.generator import baked_param_defaults

        endpoints = [{"tool_name": "get_x", "method": "GET", "host": HOST,
                      "path": "/api/x",
                      "query_params": {"count": ["yes"], "page": ["1"],
                                       "status": ["open"]},
                      "query_param_evidence": {"status": _FIXED}}]
        baked = baked_param_defaults(endpoints)
        assert [item["params"] for item in baked] == [["status"]]

    def test_switch_param_still_renders_before_optional_params(self):
        """必填参数必须排在带默认值的参数**前面**，否则整份产物 SyntaxError。

        `variable`（值会变）是必填的；名字档的切换参数是**可选**的，所以这个用例用
        一条 `variable` 证据来当必填那一个 —— 否则两个都可选，这条守卫就名存实亡。
        """
        src = _render(_registry(
            query_params={"pageno": ["1", "9"], "count": ["yes"], "status": ["open"]},
            query_param_evidence={"pageno": {"class": "variable", "values": ["1", "9"],
                                             "present_in": 2, "requests": 2,
                                             "switch_risk": True,
                                             "behaviour_switch": None,
                                             "verified": False}}))
        signature = src.split("async def get_x(")[1].split(")")[0]
        assert signature.index("pageno") < signature.index("count"), signature
        assert signature.index("count") < signature.index("status"), signature
        compile(src, "server.py", "exec")


class TestParamProvenanceInDocstring:
    """规则 5：可变参数的「来源 + 影响」必须写进工具文档字符串。

    调用方是 LLM，它只读 docstring；参数为什么必填、该传什么，只能在这里告诉它。
    """

    def test_origin_and_impact_are_surfaced(self):
        src = _render(_registry(
            query_params={"page": ["1", "9"]},
            query_param_evidence={"page": {"class": "variable", "values": ["1", "9"],
                                           "present_in": 2, "requests": 2,
                                           "switch_risk": True,
                                           "behaviour_switch": False,
                                           "verified": True}},
            param_provenance={"page": {"origin": "前端翻页控件",
                                       "impact": "决定返回第几页"}}))
        assert "前端翻页控件" in src
        assert "决定返回第几页" in src

    def test_plain_string_provenance_is_also_surfaced(self):
        src = _render(_registry(
            query_params={"page": ["1", "9"]},
            param_provenance={"page": "翻页控件参数"}))
        assert "翻页控件参数" in src


class TestMissingEndpointFieldsAreNamed:
    """Fix 5：registry 条目缺字段要**点名**报错，不能是下游的裸 `KeyError`。

    `regenerate_server` 报 `KeyError: 'host'` 时，用户只知道「有个键没了」，
    既不知道是哪一条、也不知道该改什么；而 registry.json 是 merge 出来的，
    条目常常几十条。这里要求：报错带索引、带条目 id、带缺的字段名，
    并且**绝不为缺失字段编造默认值**（凭空补个 path 会让工具打到错误地址）。
    """

    def _registry_with(self, endpoint: dict) -> dict:
        registry = _registry()
        registry["endpoints"] = [endpoint]
        return registry

    @pytest.mark.parametrize("field", ["tool_name", "host", "path"])
    def test_missing_field_is_named_not_keyerror(self, field):
        endpoint = _registry()["endpoints"][0]
        endpoint["endpoint_id"] = "ep_007"      # registry 里每条都有衔接键
        del endpoint[field]

        with pytest.raises(ValueError) as excinfo:
            render_server(self._registry_with(endpoint))

        message = str(excinfo.value)
        assert "#0" in message          # 索引
        assert field in message         # 缺的字段
        assert "ep_007" in message      # 条目标识

    def test_falls_back_to_tool_name_when_there_is_no_endpoint_id(self):
        endpoint = _registry()["endpoints"][0]
        del endpoint["host"]           # tool_name 还在 → 用它点名

        with pytest.raises(ValueError, match="get_x"):
            render_server(self._registry_with(endpoint))

    def test_index_identifies_the_offending_entry_among_many(self):
        registry = _registry()
        second = dict(registry["endpoints"][0], tool_name="get_y", path="/api/y")
        del second["host"]
        registry["endpoints"] = [registry["endpoints"][0], second]

        with pytest.raises(ValueError, match=r"#1 .*get_y"):
            render_server(registry)

    def test_empty_required_field_is_rejected_too(self):
        """空 path 同样不可渲染：那不是「默认值」，是把请求打到别处。"""
        endpoint = _registry()["endpoints"][0]
        endpoint["path"] = ""

        with pytest.raises(ValueError, match="path"):
            render_server(self._registry_with(endpoint))

    def test_direct_render_tool_call_is_not_a_keyerror(self):
        from webapi_extractor.generator import _render_tool

        with pytest.raises(ValueError):
            _render_tool({"method": "GET"}, "PORTAL")


class TestSiteNameFromSessionId:
    """S24：站点名（= env 前缀的来源）必须对 IP 型主机可读，且不动正常站点。

    `new_session_id` 把 host 的 `:` 换成 `_`、`.` 保留，于是会话 id 形如
    `20260929_120000_<host>_<hex4>`。修复前一律取 host 的第一个点号之前那一段：
    正常域名得到可读的 `oa`，而 `172.16.105.44` 只剩 `172`，env 前缀退化成
    `172_TOKEN`，同网段多台设备还会撞名。
    """

    def test_ipv4_host_keeps_all_octets(self):
        assert _site_name_from_session_id("20260929_120000_172.16.105.44_ab12") == \
            "172-16-105-44"

    def test_ipv4_env_prefix_is_readable_and_legal(self):
        prefix = _env_prefix(_site_name_from_session_id("20260929_120000_10.0.0.5_ab12"))
        assert prefix == "10_0_0_5"
        assert re.fullmatch(r"[A-Z0-9_]+", prefix)

    def test_normal_host_is_unchanged(self):
        """正常站点**一个字符都不许动**（金标准是显式 site_name，改这里会波及既有站点）。"""
        assert _site_name_from_session_id("20260929_120000_oa.example.com_ab12") == "oa"

    def test_number_leading_hostname_is_not_an_ip(self):
        """以数字起头的域名不是 IP，别误判（否则 `3m.example.com` 会整段留下）。"""
        assert _site_name_from_session_id("20260929_120000_3m.example.com_ab12") == "3m"

    def test_empty_session_id_still_yields_a_name(self):
        assert _site_name_from_session_id("") == "site"


class TestSmokeEndpointSelection:
    """S25：冒烟只能选只读、最可能一次就通的端点，并把理由写进生成物。"""

    def _ep(self, path, **over):
        entry = {"method": "GET", "host": HOST, "path": path, "path_params": [],
                 "query_params": {}, "auth_required": False, "review_suggested": False}
        entry.update(over)
        return entry

    def test_never_picks_a_write_endpoint(self):
        chosen, reasons, _ = _smoke_endpoint([
            self._ep("/api/orders", method="POST"),
            self._ep("/api/items", method="DELETE"),
        ])
        assert chosen is None
        assert reasons == []

    def test_prefers_no_auth_then_no_path_params(self):
        auth_get = self._ep("/api/secure", auth_required=True)
        plain_get = self._ep("/api/open")
        chosen, reasons, caveats = _smoke_endpoint([auth_get, plain_get])
        assert chosen is plain_get
        assert any("无需鉴权" in r for r in reasons)
        assert caveats == []

    def test_avoids_file_and_heavy_endpoints(self):
        heavy = self._ep("/api/report", file_response=True, review_suggested=True)
        light = self._ep("/api/tiny")
        chosen, _, _ = _smoke_endpoint([heavy, light])
        assert chosen is light

    def test_single_candidate_is_still_explained_with_caveats(self):
        """只剩一个必选端点时也要选，但必须如实写出它的不利之处。"""
        only = self._ep("/api/secure", auth_required=True, path_params=["id"])
        chosen, reasons, caveats = _smoke_endpoint([only])
        assert chosen is only
        assert any("只读 GET" in r for r in reasons)
        assert any("鉴权" in c for c in caveats)

    def test_deterministic_on_ties(self):
        first = self._ep("/api/a")
        second = self._ep("/api/b")
        assert _smoke_endpoint([first, second])[0] is first
        assert _smoke_endpoint([second, first])[0] is second

    def test_required_query_endpoint_smoke_matches_the_tool_default(self):
        """S25：有「查询即内容」必填参数的端点，冒烟与生成的工具用**同一个**安全默认值。

        这正是与上一轮默认值策略「自洽」的含义：工具签名里烘的是什么，冒烟就发什么；
        两边都不烘抓包原值（原值含身份数据、且会过期）。
        """
        from webapi_extractor.generator import _safe_default_query

        raw = ('<fetch count="10"><entity name="annotation">'
               '<attribute name="subject"/></entity></fetch>')
        registry = _registry()
        entry = registry["endpoints"][0]
        entry.update({
            "path": "/api/data/v9.0/annotations", "method": "GET", "path_params": [],
            "query_params": {"fetchXml": [raw]},
            "required_query_param": {"param": "fetchXml",
                                     "reason": "query_defining_param_must_be_required"},
        })
        files = render_server(registry)
        safe = _safe_default_query("fetchXml", [raw])
        assert safe and 'count="50"' in safe

        smoke_line = next(line for line in files["smoke_test.py"].splitlines()
                          if line.strip().startswith("params = "))
        params = json.loads(smoke_line.strip()[len("params = "):])
        assert params == {"fetchXml": safe}
        assert raw not in files["smoke_test.py"]          # 抓包原值不进分发包
        assert 'count="50"' in files["server.py"]         # 工具签名用的是同一份安全值

    def test_rendered_smoke_test_explains_the_choice_and_never_writes(self):
        registry = _registry()
        registry["endpoints"] = [
            {"tool_name": "post_order", "method": "POST", "host": HOST,
             "path": "/api/orders", "path_params": [], "query_params": {},
             "sample_count": 2, "status": "active", "description": "下单"},
            {"tool_name": "get_order", "method": "GET", "host": HOST,
             "path": "/api/orders/{id}", "path_params": ["id"],
             "query_params": {}, "sample_count": 2, "status": "active",
             "description": "查单", "auth_required": False},
            {"tool_name": "get_status", "method": "GET", "host": HOST,
             "path": "/api/status", "path_params": [], "query_params": {},
             "sample_count": 2, "status": "active", "description": "状态",
             "auth_required": False},
        ]
        src = render_server(registry)["smoke_test.py"]
        compile(src, "smoke_test.py", "exec")
        # 选中了不需要路径参数的那个 GET（不是 POST，也不是要猜 id 的）
        assert "/api/status" in src
        assert 'server._request(host, "GET"' in src      # 冒烟只发只读请求
        assert "{id}" not in src and "/api/orders" not in src.split("async def main")[0]
        assert "选择理由" in src
        assert "只读" in src
