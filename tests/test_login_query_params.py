# -*- coding: utf-8 -*-
"""登录接口（``auth_login``）的 query 参数：去泄漏 + 分类 + env 通道。

修复前有**一条完整的泄漏链**（不是刻意豁免，是漏了）：

    `project._sanitize_registry_urls` 只遍历 ``registry["endpoints"]``，而
    ``auth_login`` 不在其中；``set_auth_login`` 又直接赋值不做清洗。

于是抓包**第一次登录请求**的 query 取值（`?tenant=acme` / `?signature=…`）
原样进了两个交付物：``registry.json``（随 `export_user_package` 交给同事）与
生成物里的 ``_AUTH_LOGIN_CFG``（**生成物真的会拿它去登录**）。

修法分两步，缺一不可：
  1. 擦除规则（analyzer 那一份）接上 ``auth_login`` 这条出口；
  2. 生成器不再假设「registry 里的 query 取值都能直接烘」：过得了
     `_stable_default_value` 的**良性**取值（无害固定参数，如 `encrypt=2`；
     或无证据但取值唯一）照旧烘默认值；**值会变**（证据说 `variable`）、像真实
     数据/凭据、是哨兵 `***` 或空值的，一律**不烘**（也不标必填！），取值按运行时链
     **调用入参 → .env → 原生弹窗询问 → 都没有则明确报错并点名缺哪个** 取，并把
     `.env` 通道补上（401 自动重登录拿不到工具入参）。来源确定的参数另有第三条路：
     运行时自动取用（见 `tests/test_login_query_fetch.py`）。

**新契约（推翻「改必填」）**：这些参数**带默认值 `None`**，不填也能进入函数体 —— 否则参数
绑定阶段就 `TypeError: login() missing 1 required keyword-only argument`，
「弹窗拿账号密码、口令不进对话」那条路在这类站点上完全走不到。
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import types
from pathlib import Path

import pytest

from scry_mcp_gen.generator import render_server
from scry_mcp_gen.project import (
    export_user_package,
    init_project,
    load_registry,
    save_registry,
    set_auth_login,
)

HOST = "portal.example.com"
SECRET = "SUPERSECRET"
LOGIN_PATH = "/api/login"


def _endpoint() -> dict:
    return {
        "endpoint_id": "ep_001", "tool_name": "get_todo", "method": "GET",
        "host": HOST, "path": "/api/todo", "path_params": [],
        "query_params": {}, "request_body_params": {}, "status": "active",
        "auth_required": True, "description": "待办",
    }


def _login(query_params: dict, evidence: dict | None = None) -> dict:
    login = {
        "method": "POST", "host": HOST, "path": LOGIN_PATH,
        "account_field": "username", "password_field": "password",
        "token_path": ["data", "token"], "query_params": query_params,
    }
    if evidence is not None:
        login["query_param_evidence"] = evidence
    return login


def _registry(auth_login: dict | None = None) -> dict:
    return {
        "site_name": "portal", "registry_version": 1,
        "hosts": {HOST: {"scheme": "Bearer", "cookie_names": []}},
        "endpoints": [_endpoint()], "auth_login": auth_login,
    }


def _fixed(values: list) -> dict:
    """「每个不同请求都带它、且值完全一样」的证据 —— 有资格烘默认值的一类。

    （另一类是**没有证据但观测取值唯一**；`verified` 只作为记录，不再一票否决。）
    """
    return {"class": "fixed", "values": list(values), "present_in": 2,
            "requests": 2, "verified": True}


def _server(registry: dict) -> str:
    return render_server(registry)["server.py"]


def _cfg_line(server: str) -> str:
    return next(l for l in server.splitlines() if l.startswith("_AUTH_LOGIN_CFG = "))


# --------------------------------------------------------------------------- #
# analyzer：登录端点的 query 样本与证据必须**随端点移出 endpoints 时保留下来**
# --------------------------------------------------------------------------- #
class TestAnalyzerKeepsLoginQueryEvidence:
    """`detect_auth_login` 以前只留「第一个取值」，而且把参数证据整份丢掉。

    于是生成器既看不出「这个值是不是抓包当时那一次会话特有的」，也就只能把真值烘进
    代码。这里锁住两件事：样本是**全量 list**、证据带过来了。
    """

    def test_login_keeps_all_values_and_evidence(self):
        from scry_mcp_gen.analyzer import detect_auth_login

        login_ep = {
            "endpoint_id": "ep_001", "method": "POST", "host": HOST,
            "path": LOGIN_PATH, "auth_required": False,
            "request_schema": {"properties": {"username": {}, "password": {}}},
            "response_schema": {"properties": {"data": {"properties": {"token": {}}}}},
            "query_params": {"encrypt": ["2"], "tenant": ["acme", "other"]},
            "query_param_evidence": {
                "encrypt": _fixed(["2"]),
                "tenant": {"class": "variable", "values": ["acme", "other"],
                           "present_in": 2, "requests": 2, "verified": True},
            },
        }
        login = detect_auth_login([login_ep], None)

        assert login is not None
        assert login["query_params"] == {"encrypt": ["2"],          # 全量，不是首个
                                         "tenant": ["acme", "other"]}
        assert login["query_param_evidence"]["tenant"]["class"] == "variable"

    def test_crypto_detection_accepts_both_shapes(self):
        """`detect_password_encryption` 读 `query_params["encrypt"]`：
        list（新）与标量（老 registry）都要认，否则加密策略会静默消失。"""
        from scry_mcp_gen.crypto_analyzer import detect_password_encryption

        assert detect_password_encryption(None, _login({"encrypt": ["2"]})) == {
            "scheme": "rsa-oaep-sha256", "version": "2", "public_key": None}
        assert detect_password_encryption(None, _login({"encrypt": "2"})) == {
            "scheme": "rsa-oaep-sha256", "version": "2", "public_key": None}
        assert detect_password_encryption(None, _login({"encrypt": []})) is None


# --------------------------------------------------------------------------- #
# Step 1：去泄漏（registry 落盘 + 分发两个出口）
# --------------------------------------------------------------------------- #
class TestAuthLoginQueryValuesAreSanitised:
    """`auth_login` 不是 endpoint，此前整条漏掉：真值会落盘、会被分发、还会被拿去登录。"""

    def test_save_registry_redacts_credentials_but_keeps_benign(self, tmp_path: Path):
        project = tmp_path / "proj"
        init_project(project, "portal")
        set_auth_login(project, _login({"token": [SECRET], "encrypt": ["2"]}))

        stored = load_registry(project)["auth_login"]
        assert stored["query_params"]["token"] == ["***"]     # 凭据类：遮蔽
        assert stored["query_params"]["encrypt"] == ["2"]     # 良性固定参数：不误伤
        # 参数名一律保留（生成器的签名/分类要靠它）
        assert set(stored["query_params"]) == {"token", "encrypt"}
        assert SECRET not in (project / "registry.json").read_text(encoding="utf-8")

    def test_caller_dict_is_not_mutated_in_place(self, tmp_path: Path):
        """`set_auth_login` 收到的是调用方的 dict，不能顺手把它改掉。"""
        project = tmp_path / "proj"
        init_project(project, "portal")
        login = _login({"token": [SECRET]})
        set_auth_login(project, login)
        assert login["query_params"]["token"] == [SECRET]

    def test_legacy_scalar_query_params_are_handled(self, tmp_path: Path):
        """老 registry / 老调用方传的是**标量**（`{"token": "xxx"}`），同样要洗。

        标量若直接进 `sanitize_query_params`，`list("SUPERSECRET")` 会被拆成字符，
        于是洗出 `["*","*","*",…]` —— 既不遮蔽也没保留原值。
        """
        project = tmp_path / "proj"
        init_project(project, "portal")
        set_auth_login(project, _login({"token": SECRET, "encrypt": "2"}))

        stored = load_registry(project)["auth_login"]["query_params"]
        assert stored == {"token": ["***"], "encrypt": ["2"]}

    def test_export_user_package_carries_no_secret(self, tmp_path: Path):
        """分发包（registry/README/server/smoke_test）里读不到登录 query 的取值。"""
        project = tmp_path / "proj"
        init_project(project, "portal")
        set_auth_login(project, _login({"token": [SECRET], "encrypt": ["2"]}))
        save_registry(project, load_registry(project))
        # 再渲染一次生成物（server.py / README.md / .env.example 都进分发包）
        from scry_mcp_gen.generator import write_files
        write_files(project, {k: v for k, v in render_server(load_registry(project)).items()
                              if k != "registry.json"})
        export_user_package(project, tmp_path / "dist")

        seen = []
        for path in (tmp_path / "dist").rglob("*"):
            if path.is_file():
                seen.append(path.name)
                assert SECRET not in path.read_text(encoding="utf-8"), f"{path.name} 夹带了凭据"
        assert "registry.json" in seen and "server.py" in seen and ".env.example" in seen

    def test_export_path_sanitises_even_if_never_resaved(self, tmp_path: Path):
        """老项目（盘上仍是原始值）导出时也要洗 —— 导出走同一个出口。"""
        project = tmp_path / "proj"
        init_project(project, "portal")
        raw = _registry(_login({"token": [SECRET], "encrypt": ["2"]}))
        (project / "registry.json").write_text(json.dumps(raw), encoding="utf-8")

        export_user_package(project, tmp_path / "dist")
        shipped = json.loads((tmp_path / "dist" / "registry.json").read_text(encoding="utf-8"))
        assert shipped["auth_login"]["query_params"] == {"token": ["***"], "encrypt": ["2"]}


# --------------------------------------------------------------------------- #
# Step 2/3：生成器闸门 + 分类（(c) 烘默认值 / (b) 运行时取值链，不标必填）
# --------------------------------------------------------------------------- #
class TestLoginQueryParamClassification:
    def test_benign_fixed_param_keeps_its_default(self):
        """(c)：过得了闸门的固定参数照旧烘默认值（行为不变）。"""
        server = _server(_registry(_login(
            {"encrypt": ["2"]}, {"encrypt": _fixed(["2"])})))
        assert "'query_params': {'encrypt': '2'}" in _cfg_line(server)
        # 没有 (b) 类参数 → 签名与修复前逐字节一致（不加任何参数）
        assert ("async def login(account: str | None = None, "
                "password: str | None = None) -> dict:") in server

    def test_variable_param_is_optional_with_unknown_source_note(self):
        """值会变（证据说 `variable`）→ **不烘快照、也不标必填**（带默认值 None）。

        新契约：不填也要能进入函数体 —— 否则参数绑定阶段就
        `TypeError: login() missing 1 required keyword-only argument`，
        弹窗那条路（拿账号密码、口令不进对话）在这类站点上根本走不到。
        docstring 必须说明「来源未知」与取值链。
        """
        server = _server(_registry(_login(
            {"tenant": ["acme"]}, {"tenant": {"class": "variable", "values": ["acme"],
                                               "present_in": 2, "requests": 2,
                                               "verified": True}})))
        assert "tenant: str | None = None" in server          # 关键字限定 + 有默认值
        doc = server.split("async def login(")[1].split('"""')[1]
        assert "来源未知" in doc
        assert "不填也能调用" in doc                          # 取值链写进 docstring
        # 抓包取值绝不烘进生成物
        assert "'acme'" not in _cfg_line(server)

    def test_benign_single_value_without_evidence_is_baked(self):
        """**良性就保留默认值**：旧 registry 没有证据字段，但取值唯一且无害 → 烘。

        （`encrypt` 不是身份/时间类名字，值 `2` 也不像具体数据。）
        """
        server = _server(_registry(_login({"encrypt": ["2"]})))
        assert "'query_params': {'encrypt': '2'}" in _cfg_line(server)

    def test_multiple_values_without_evidence_are_not_baked_and_not_required(self):
        """没有证据、却看到过不止一个取值 → 确切知道它可变 → 不烘任何一个（带默认值 None）。"""
        server = _server(_registry(_login({"tenant": ["acme", "other"]})))
        assert "tenant: str | None = None" in server
        assert "'acme'" not in server and "'other'" not in server

    def test_identity_like_name_without_evidence_is_not_baked_and_not_required(self):
        """名字是身份/时间类 → 无论有没有证据都不烘（值可能只是抓包那个人的）。"""
        server = _server(_registry(_login({"tenant": ["acme"]})))
        assert "tenant: str | None = None" in server
        assert "'acme'" not in server

    def test_empty_value_param_is_not_dropped_and_not_required(self):
        """空串取值：`_cfg` 构造会丢弃空值参数（Step 2），所以它必须落在 (b) 里
        由运行时取值链决定发什么 —— 否则这个参数会从登录请求里**凭空消失**。"""
        server = _server(_registry(_login({"client_type": [""]})))
        assert "client_type: str | None = None" in server
        assert "'query_params': {}" in _cfg_line(server)
        assert "PORTAL_LOGIN_QUERY_CLIENT_TYPE" in _cfg_line(server)

    def test_scalar_values_from_old_registry_are_understood(self):
        """老 registry / 老调用方写的是标量：按单元素列表读，别当成「多个样本」。"""
        server = _server(_registry(_login({"encrypt": "2"},
                                          {"encrypt": _fixed(["2"])})))
        assert "'query_params': {'encrypt': '2'}" in _cfg_line(server)

    def test_redaction_sentinel_becomes_optional_not_resent(self):
        """registry 里剩下的哨兵 `***` 既不能烘、也不能发：既不烘默认值，也不标必填。"""
        server = _server(_registry(_login({"token": ["***"]})))
        assert "token: str | None = None" in server
        assert "***" not in _cfg_line(server)          # 记号不进 cfg
        assert "token: str | None = '***'" not in server

    def test_deferred_params_are_keyword_only_and_never_rename_existing(self):
        """这些参数必须**关键字限定 + 带默认值 None**：关键字限定才不会顶掉
        account/password 的位置语义（也不能排在带默认值的参数后面 —— `x=None, y: str`
        直接 SyntaxError）；默认值 None 才能「不填也进入函数体」（弹窗那条路的前提）。"""
        server = _server(_registry(_login({"tenant": ["acme"], "account": ["bob"]})))
        line = next(l for l in server.splitlines() if l.startswith("async def login("))
        assert line == ("async def login(account: str | None = None, "
                        "password: str | None = None, *, tenant: str | None = None, "
                        "account_2: str | None = None) -> dict:")
        # 线上参数名仍是抓包观测到的那个（ident 只用于 Python 侧）
        assert "('account', 'PORTAL_LOGIN_QUERY_ACCOUNT', account_2)" in server

    def test_empty_query_params_is_byte_identical(self):
        """金标准：`query_params == {}` 时生成物不受本次修改影响。"""
        server = _server(_registry(_login({})))
        assert ("async def _do_login(account: str, password: str) -> dict:") in server
        assert "login_query_params" not in server
        assert ("    return {k: v for k, v in (params or {}).items() "
                "if v is not None}") in server
        assert "params=_clean(cfg['query_params']) or None," in server

    def test_env_example_has_placeholders_only(self):
        files = render_server(_registry(_login({"tenant": ["acme"]})))
        env = files[".env.example"]
        assert "PORTAL_LOGIN_QUERY_TENANT=" in env
        assert "acme" not in env                      # 只放占位符，绝不写抓包真值
        assert "PORTAL_LOGIN_QUERY_TENANT=" not in (
            render_server(_registry(_login({})))[".env.example"])

    def test_readme_documents_deferred_login_params(self):
        readme = render_server(_registry(_login({"tenant": ["acme"]})))["README.md"]
        assert "PORTAL_LOGIN_QUERY_TENANT" in readme
        assert "acme" not in readme
        assert "PORTAL_LOGIN_QUERY_TENANT" not in (
            render_server(_registry(_login({})))["README.md"])


# --------------------------------------------------------------------------- #
# 生成物行为：哨兵永不到线上 + 401 自动重登录的 env 通道
# --------------------------------------------------------------------------- #
def _load_server(tmp_path, monkeypatch, registry: dict, responses: list,
                 login_ok: bool = True):
    """加载生成的 server.py（假 httpx），返回 (module, calls)。"""
    calls: list = []

    class _Resp:
        def __init__(self, status: int, payload: dict | None = None):
            self.status_code = status
            self._payload = payload or {}
            self.content = b"{}"
            self.text = "{}"

        def json(self):
            return self._payload

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
            if path == LOGIN_PATH:
                return _Resp(200, {"data": {"token": "tok"}} if login_ok else {})
            return _Resp(responses.pop(0) if responses else 200)

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
    spec = importlib.util.spec_from_file_location("gen_login_query_server", target)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # 不碰 DPAPI / 不碰网络
    module.ERROR_LOG = tmp_path / "error.log"
    module._cache_save = lambda *args, **kwargs: None
    module._cache_load = lambda *args, **kwargs: None
    module.TOKEN_CACHE = tmp_path / "token_cache.bin"
    module.CRED_CACHE = tmp_path / "cred_cache.bin"
    return module, calls


class TestSentinelNeverReachesTheWire:
    """纵深防御：即使 registry 里还留着 `***`，也不能被当成参数值发出去。

    `tenant=***` 服务端不认识 → 登录必失败，而且是**静默的正常请求**（没有异常、
    没有日志），排障时会以为是密码错。
    """

    def _registry_with_sentinel(self) -> dict:
        # 直接拿未清洗的 registry 渲染（最坏情况：老项目 / 上游漏洗）
        return _registry(_login({"token": ["***"], "encrypt": ["2"]}))

    def test_cfg_carries_no_sentinel(self):
        server = _server(self._registry_with_sentinel())
        assert "***" not in _cfg_line(server)
        assert "PORTAL_LOGIN_QUERY_TOKEN" in _cfg_line(server)   # 改走 env/入参

    def test_serialized_cfg_literal_contains_no_captured_value(self):
        """**直接**审 `_AUTH_LOGIN_CFG = {...}` 的序列化**文本**（不是审 `_cfg` dict）。

        生成物真的会拿 cfg 里的值去登录，所以「dict 里没有」还不够：必须落到**产物
        文本**上 —— 抓包取值读不到、脱敏哨兵也读不到，而 (c) 的良性固定值照旧烘着。
        """
        import ast

        server = _server(_registry(_login(
            {"encrypt": ["2"], "tenant": ["acme"], "token": ["***"]},
            {"encrypt": _fixed(["2"])})))
        line = _cfg_line(server)
        literal = ast.literal_eval(line.split("=", 1)[1].strip())

        assert literal["query_params"] == {"encrypt": "2"}          # (c) 照旧烘着
        assert literal["login_query_params"] == {                   # (b) 只留 env 名
            "tenant": "PORTAL_LOGIN_QUERY_TENANT",
            "token": "PORTAL_LOGIN_QUERY_TOKEN"}
        assert "acme" not in line and "***" not in line             # 文本上就没有
        assert "acme" not in server
        # 全文里 `***` 只允许出现在 `_clean` 的哨兵闸门里（那是**判定**，不是取值）
        assert server.count("***") == 1 and 'v == "***"' in server

    def test_request_params_never_contain_the_mark(self, tmp_path, monkeypatch):
        """401 自动重登录这条（无工具入参）走 env：发出去的 params 里没有 `***`。"""
        import asyncio

        registry = self._registry_with_sentinel()
        module, calls = _load_server(tmp_path, monkeypatch, registry, [])
        monkeypatch.setenv("PORTAL_LOGIN_QUERY_TOKEN", "real-token")
        monkeypatch.setenv("PORTAL_LOGIN_QUERY_ENCRYPT", "2")
        asyncio.run(module._do_login("bob", "pw"))

        assert calls[0]["path"] == LOGIN_PATH
        assert calls[0]["params"] == {"token": "real-token", "encrypt": "2"}

    def test_baked_and_required_params_are_merged(self, tmp_path, monkeypatch):
        """(c) 烘入的固定参数 + (b) env 提供的参数合成同一份 params。"""
        import asyncio

        registry = _registry(_login(
            {"encrypt": ["2"], "tenant": ["acme"]},
            {"encrypt": _fixed(["2"])}))
        module, calls = _load_server(tmp_path, monkeypatch, registry, [])
        monkeypatch.setenv("PORTAL_LOGIN_QUERY_TENANT", "acme-from-env")
        asyncio.run(module._do_login("bob", "pw"))

        assert calls[0]["params"] == {"encrypt": "2", "tenant": "acme-from-env"}

    def test_clean_helper_drops_marks_even_if_called_directly(self, tmp_path,
                                                              monkeypatch):
        module, _ = _load_server(tmp_path, monkeypatch,
                                 self._registry_with_sentinel(), [])
        assert module._clean({"a": "***", "b": "****", "c": "2", "d": None}) == {"c": "2"}


class TestReloginUsesEnvChannel:
    """401 自动重登录只能走 .env：配了 → 重试成功；没配 → **大声**报错。"""

    def _load(self, tmp_path, monkeypatch, responses):
        registry = _registry(_login({"tenant": ["acme"]}))
        module, calls = _load_server(tmp_path, monkeypatch, registry, responses)
        module._cached_credentials = lambda: ("bob", "secret")
        return module, calls

    def test_configured_env_makes_retry_succeed(self, tmp_path, monkeypatch):
        import asyncio

        module, calls = self._load(tmp_path, monkeypatch, [401, 200])
        monkeypatch.setenv("PORTAL_LOGIN_QUERY_TENANT", "acme")

        asyncio.run(module._request(HOST, "GET", "/api/todo"))

        assert [c["path"] for c in calls] == ["/api/todo", LOGIN_PATH, "/api/todo"]
        assert calls[1]["params"]["tenant"] == "acme"

    def test_missing_env_fails_loudly_and_names_the_variable(self, tmp_path,
                                                            monkeypatch):
        import asyncio

        module, calls = self._load(tmp_path, monkeypatch, [401, 200])
        monkeypatch.delenv("PORTAL_LOGIN_QUERY_TENANT", raising=False)

        with pytest.raises(RuntimeError) as excinfo:
            asyncio.run(module._request(HOST, "GET", "/api/todo"))

        message = str(excinfo.value)
        assert "PORTAL_LOGIN_QUERY_TENANT" in message      # 点名缺哪个 env
        assert "***" not in message
        # 不是静默跳过：登录请求根本没发（也就没有「重试又 401」的假象）
        assert [c["path"] for c in calls] == ["/api/todo"]
        log = (tmp_path / "error.log").read_text(encoding="utf-8")
        assert "PORTAL_LOGIN_QUERY_TENANT" in log

    def test_login_tool_accepts_the_param_directly(self, tmp_path, monkeypatch):
        """调用方传参优先于 .env（自动重登录之外的正常路径）。"""
        import asyncio

        module, calls = self._load(tmp_path, monkeypatch, [])
        monkeypatch.setenv("PORTAL_LOGIN_QUERY_TENANT", "from-env")
        asyncio.run(module.login("bob", "pw", tenant="from-caller"))

        assert calls[0]["params"]["tenant"] == "from-caller"

    def test_direct_login_without_value_names_the_missing_param(self, tmp_path,
                                                                monkeypatch):
        """直接调用 login(...) 且取不到值：**不抛在参数绑定阶段**，而是返回结构化失败并
        点名缺的是哪个参数（弹窗在本环境弹不出 → 降级到明确报错）。"""
        import asyncio

        module, calls = self._load(tmp_path, monkeypatch, [])
        monkeypatch.delenv("PORTAL_LOGIN_QUERY_TENANT", raising=False)

        async def _no_dialog(function):      # 无图形环境：弹窗拿不到值
            return None

        module._run_native = _no_dialog
        result = asyncio.run(module.login("bob", "pw", tenant=""))

        assert result["success"] is False
        assert result["error"] == "missing_login_query_params"
        assert result["missing_params"] == ["tenant"]          # 点名缺哪个
        assert "PORTAL_LOGIN_QUERY_TENANT" in result["message"]  # 也给出 .env 出路
        assert calls == []                                     # 取不到值就不许硬着头皮登录
        assert "PORTAL_LOGIN_QUERY_TENANT" in (
            tmp_path / "error.log").read_text(encoding="utf-8")


class TestDeferredParamValueChain:
    """取值链：调用入参 → .env → 原生弹窗询问 → 都没有则明确报错点名。

    关键回归：这些参数**不进必填位**。此前标成必填 → 参数绑定阶段就
    `TypeError: login() missing 1 required keyword-only argument`，函数体根本进不去，
    「弹窗拿账号密码、口令不进对话」那条路在这类站点上完全走不到。
    """

    def _module(self, tmp_path, monkeypatch):
        registry = _registry(_login({"tenant": ["acme"]}))
        module, calls = _load_server(tmp_path, monkeypatch, registry, [])
        module._cached_credentials = lambda: None      # 逼出账号密码弹窗那条路
        return module, calls

    def _clear_env(self, monkeypatch):
        for name in ("PORTAL_ACCOUNT", "PORTAL_PASSWORD", "PORTAL_LOGIN_QUERY_TENANT"):
            monkeypatch.delenv(name, raising=False)

    def test_missing_param_does_not_block_the_credential_dialog(self, tmp_path,
                                                                monkeypatch):
        """核心缺陷回归：缺 query 参数**不能**挡住账号密码弹窗。

        无参 `login()` 必须先进函数体（弹窗拿账号密码），再到缺参数那一步。
        """
        import asyncio

        module, _ = self._module(tmp_path, monkeypatch)
        self._clear_env(monkeypatch)
        asked: list = []

        async def _fake_run_native(function):
            asked.append(function)
            if function is module._ask_credentials_native:
                return ("bob", "pw")
            return None                                # 参数弹窗「弹不出」

        module._run_native = _fake_run_native
        result = asyncio.run(module.login())

        assert module._ask_credentials_native in asked, "缺 query 参数不该挡住账号密码弹窗"
        assert result["error"] == "missing_login_query_params"
        assert result["missing_params"] == ["tenant"]
        # 口令与取值都不进返回体
        assert "pw" not in json.dumps(result, ensure_ascii=False)

    def test_dialog_value_is_used_for_login(self, tmp_path, monkeypatch):
        """弹窗问到的值真的用上，且**绝不进返回体**。"""
        import asyncio

        module, calls = self._module(tmp_path, monkeypatch)
        self._clear_env(monkeypatch)

        async def _fake_run_native(function):
            if function is module._ask_credentials_native:
                return ("bob", "pw")
            return {"tenant": "from-dialog"}

        module._run_native = _fake_run_native
        result = asyncio.run(module.login())

        assert result["success"] is True
        assert calls[0]["params"]["tenant"] == "from-dialog"
        assert "from-dialog" not in json.dumps(result, ensure_ascii=False)

    def test_env_beats_the_dialog(self, tmp_path, monkeypatch):
        """.env 有值就不该再弹窗（能不问就不问）。"""
        import asyncio

        module, calls = self._module(tmp_path, monkeypatch)
        monkeypatch.setenv("PORTAL_LOGIN_QUERY_TENANT", "from-env")
        calls_native: list = []

        async def _fake_run_native(function):
            calls_native.append(function)
            return None

        module._run_native = _fake_run_native
        result = asyncio.run(module.login("bob", "pw"))

        assert result["success"] is True
        assert calls[0]["params"]["tenant"] == "from-env"
        assert calls_native == [], "参数已由 .env 提供时不该打断用户"

    def test_secret_like_params_are_masked_in_the_dialog(self, tmp_path, monkeypatch):
        """名字像 token / 密钥的参数，弹窗标签带「不会显示」且用掩码输入。"""
        registry = _registry(_login({"apiKey": ["x"], "tenant": ["acme"]}))
        source = render_server(registry)["server.py"]
        assert '_LOGIN_SECRET_PARAMS = ["apiKey"]' in source
        assert "show='*' if _secret else None" in source
        assert "（不会显示）" in source
        compile(source, "server.py", "exec")

    def test_docstring_tells_the_agent_about_the_param_popup(self, tmp_path, monkeypatch):
        """弹窗会打断用户：docstring 必须讲清「先征得同意」与取消时的降级出口。"""
        module, _ = self._module(tmp_path, monkeypatch)
        doc = module.login.__doc__ or ""
        assert "missing_login_query_params" in doc
        assert "征得用户同意" in doc
        assert "弹窗" in doc



# --------------------------------------------------------------------------- #
# 硬护栏：工具数不变
# --------------------------------------------------------------------------- #
class TestExtractorToolCountUnchanged:
    def test_extractor_server_still_exposes_21_tools(self):
        """本次修改只动 project/analyzer/generator，抽取器自身的工具面不得变。"""
        source = (Path(__file__).resolve().parents[1]
                  / "scry_mcp_gen" / "server.py").read_text(encoding="utf-8")
        assert source.count("@mcp.tool()") == 21

    def test_generated_login_tool_keeps_its_name_and_credentials(self):
        server = _server(_registry(_login({"tenant": ["acme"]})))
        assert "@mcp.tool()" in server
        assert re.search(r"async def login\(account: str \| None = None, "
                         r"password: str \| None = None", server)
        assert "async def auth_status() -> dict:" in server
