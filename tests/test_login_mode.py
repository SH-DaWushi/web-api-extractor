# -*- coding: utf-8 -*-
"""「能不能靠构造请求登录」—— 两层判据 + 生成物分支 + 401 指路的那句话。

用户已定的口径（两层，**以实际结果为准**）：

* **第一层（静态）**：只看登录请求**自己**的字段名与取值形态。验证码字段 / 二次验证
  字段 / 无法复现的前端加密口令 → 预判「构造 POST 登录不可行」；签名 / 时间戳这类参数
  单独出现时**不足以判死**（只记进 `signals`，真判决交给第二层）。
* **第二层（实测）**：`auth.http_login` 真的 POST 一次；失败就换个形态**再 POST 一次**，
  并把实际结果落盘成 ``<auth_states>/<site_key>.login_mode.json`` 边车。实测结果一旦
  存在就**覆盖**静态预判。

修复前的关键缺口：`http_login` 失败只把 `fallback=interactive` 回给对话，**不落盘、
不进 analysis/registry**，于是生成期一无所知，照旧发射一个必然失败的 `login()` ——
生成物「假装有 401 自动重登录」。本文件同时守住：

* 判据确实进了 analysis（并由生成期读得到）；
* 判为 `interactive` 时生成物**自带交互式登录**（真实浏览器窗口 + 用户确认，
  **绝不自动判定**），并把 `playwright` 钉死版本写进 `requirements.txt`；
* 字段**缺省**时（老 registry / 老 analysis.json）产物与以前**逐字节相同**；
* 401 报错里点到名的 `.env` 变量**必须真的在 `.env.example` 里**（修复前硬写
  `<PREFIX>_TOKEN`，而纯 Cookie 站点的 `.env.example` 里根本没有这一行）。
"""
from __future__ import annotations

import ast
import asyncio
import inspect
import json
import re
from pathlib import Path

import pytest

from webapi_extractor import auth as auth_module
from webapi_extractor.analyzer import analyze_capture, detect_auth_login
from webapi_extractor.auth import http_login
from webapi_extractor.generator import (
    _PLAYWRIGHT_PIN,
    render_server,
)

HOST = "oa.example.com"
LOGIN_PATH = "/api/login"
LOGIN_URL = f"https://{HOST}/"
ACCOUNT = "alice"
PASSWORD = "Sup3r-Secret-Pw!"
PWN = '__import__("os").system("echo PWNED")'


# --------------------------------------------------------------------------- #
# 夹具
# --------------------------------------------------------------------------- #
def _login_endpoint(**over) -> dict:
    """`detect_auth_login` 的输入：一个「账号 + 口令」登录端点。"""
    entry = {
        "endpoint_id": "ep_001", "method": "POST", "host": HOST, "path": LOGIN_PATH,
        "auth_required": False,
        "request_schema": {"properties": {"username": {}, "password": {}}},
        "response_schema": {"properties": {"data": {"properties": {"token": {}}}}},
        "query_params": {}, "query_param_evidence": {},
    }
    entry.update(over)
    return entry


def _request(request_id, url, method="GET", headers=None, post_data=None):
    event = {"type": "request", "requestId": request_id, "url": url, "method": method,
             "headers": headers or {}, "resourceType": "XHR"}
    if post_data is not None:
        event["postData"] = post_data
    return event


def _response(request_id, status=200):
    return {"type": "response", "requestId": request_id, "status": status,
            "headers": {"Content-Type": "application/json"}}


def _body(request_id, body):
    return {"type": "response_body", "requestId": request_id, "body": body,
            "size": len(body or ""), "body_dropped": False}


def _login_events(post_data) -> list:
    return [
        _request("login", f"https://{HOST}{LOGIN_PATH}", "POST", post_data=post_data),
        _response("login"),
        _body("login", json.dumps({"data": {"token": "tok"}})),
    ]


def _session(tmp_path, *, post_data=None, auth_state_path=None, name="s") -> Path:
    """写一份最小抓包（含一次登录请求）+ 一份 session.json（可带 auth_state_path）。"""
    session = tmp_path / name
    session.mkdir(parents=True, exist_ok=True)
    events = _login_events(post_data if post_data is not None
                           else json.dumps({"username": "u", "password": "p"}))
    (session / "capture.jsonl").write_text(
        "\n".join(json.dumps(event, ensure_ascii=False) for event in events) + "\n",
        encoding="utf-8")
    metadata = {"session_id": name, "url": LOGIN_URL, "status": "stopped"}
    if auth_state_path is not None:
        metadata["auth_state_path"] = str(auth_state_path)
    (session / "session.json").write_text(json.dumps(metadata, ensure_ascii=False),
                                          encoding="utf-8")
    return session


def _sidecar(states_dir: Path, *, verdict: str, host: str = HOST, attempts: int = 2,
             reason: str = "interactive_required", statuses=(200, 200),
             stem: str = "oa_example_com") -> Path:
    """按 `auth.record_login_mode` 的契约手写一份实测边车。"""
    states_dir.mkdir(parents=True, exist_ok=True)
    path = states_dir / f"{stem}.login_mode.json"
    path.write_text(json.dumps({
        "host": host, "verdict": verdict, "attempts": attempts, "reason": reason,
        "statuses": list(statuses), "checked_at": "2026-09-30T00:00:00+00:00",
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _registry(auth_login=None, **over) -> dict:
    registry = {
        "site_name": "portal", "registry_version": 1,
        "hosts": {HOST: {"scheme": None, "cookie_names": ["JSESSIONID", "loginToken"]}},
        "endpoints": [{
            "tool_name": "get_api_system_status", "method": "GET", "host": HOST,
            "path": "/api/system/status", "path_params": [], "query_params": {},
            "auth_required": True, "status": "active", "description": "系统状态",
        }],
        "auth_login": auth_login,
    }
    registry.update(over)
    return registry


def _post_login(verdict="interactive", signals=("captcha_field",), measured=None) -> dict:
    block = {"verdict": verdict, "basis": "static" if measured is None else "measured",
             "signals": list(signals)}
    if measured is not None:
        block["measured"] = measured
    return block


def _interactive_login(**over) -> dict:
    login = {"method": "POST", "host": HOST, "path": LOGIN_PATH,
             "account_field": "username", "password_field": "password",
             "token_path": ["data", "token"], "query_params": {},
             "post_login": _post_login(**over)}
    return login


def _render(registry) -> dict:
    return render_server(registry)


def _server(registry) -> str:
    return render_server(registry)["server.py"]


def _tool_functions(src: str) -> list:
    """带 @mcp.tool() 装饰器的函数（模板自身的代码不在审查范围内）。"""
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


def _injection_findings(src: str) -> list:
    """工具函数体里有没有「抓包内容变成可执行调用」的痕迹。"""
    findings = []
    for tool in _tool_functions(src):
        for node in ast.walk(tool):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in ("__import__", "eval", "exec"):
                findings.append(f"call:{fn.id}@{tool.name}")
            if isinstance(fn, ast.Attribute) and fn.attr in ("system", "popen", "spawn"):
                findings.append(f"call:.{fn.attr}@{tool.name}")
            if isinstance(fn, ast.Name) and fn.id == "_request" and len(node.args) >= 3:
                arg = node.args[2]
                if isinstance(arg, ast.JoinedStr):
                    for part in arg.values:
                        if isinstance(part, ast.FormattedValue) \
                                and not isinstance(part.value, ast.Name):
                            findings.append(f"unsafe_fstring@{tool.name}")
                elif not isinstance(arg, (ast.Constant, ast.Subscript, ast.Name)):
                    findings.append(f"path_arg:{type(arg).__name__}@{tool.name}")
    return findings


# --------------------------------------------------------------------------- #
# 第一层：静态信号
# --------------------------------------------------------------------------- #
class TestStaticSignals:
    def _signals(self, tmp_path, **over):
        login = detect_auth_login([_login_endpoint(**over)], None)
        assert login is not None, "夹具失效：登录端点没被识别"
        return login

    def test_captcha_field_predicts_interactive(self, tmp_path):
        login = self._signals(tmp_path, request_schema={"properties": {
            "username": {}, "password": {}, "captcha": {}}})
        assert login["post_login"]["verdict"] == "interactive"
        assert login["post_login"]["basis"] == "static"
        assert "captcha_field" in login["post_login"]["signals"]

    def test_mfa_field_predicts_interactive(self):
        login = self._signals(None, request_schema={"properties": {
            "username": {}, "password": {}, "otp": {}}})
        assert login["post_login"]["verdict"] == "interactive"
        assert "mfa_field" in login["post_login"]["signals"]

    def test_form_body_captcha_is_seen_too(self):
        """表单编码的登录接口同样要能看出验证码字段。

        真实抓包里 `request_schema` 是从请求体（JSON **或表单**）推出来的；这里让验证码
        只出现在 `request_body_params` 里，同时断言两个来源都被看（老 registry 可能只有
        其中一个）。
        """
        login = self._signals(None,
                              request_schema={"properties": {"username": {}, "password": {}}},
                              request_body_params={"username": ["u"], "password": ["p"],
                                                   "verify_code": ["1234"]})
        assert login["post_login"]["verdict"] == "interactive"
        assert "captcha_field" in login["post_login"]["signals"]

    def test_signed_params_alone_do_not_kill_post_login(self):
        """签名 / 时间戳单独出现时**不能**判死：很多站点登录并不校验它们。

        判成「不能 POST」会把本来能用的自动登录换成「弹浏览器」，那是负优化。
        """
        login = self._signals(None, request_schema={"properties": {
            "username": {}, "password": {}, "timestamp": {}, "nonce": {}, "sign": {}}})
        assert login["post_login"]["verdict"] == "post_ok"
        assert "signed_params" in login["post_login"]["signals"]

    def test_plain_login_is_post_ok(self):
        login = self._signals(None)
        assert login["post_login"]["verdict"] == "post_ok"
        assert login["post_login"]["signals"] == []

    def test_encrypt_version_without_public_key_predicts_interactive(self, tmp_path):
        """前端加密但**拿不到公钥** → 生成物只会把明文发出去，登录必然失败。"""
        session = _session(tmp_path, post_data=json.dumps({"username": "u", "password": "p"}))
        endpoints = [_login_endpoint(query_params={"encrypt": ["2"]})]
        login = detect_auth_login(endpoints, session)
        assert login is not None
        assert "encrypted_password" in login["post_login"]["signals"]
        assert login["post_login"]["verdict"] == "interactive"

    def test_encrypt_version_with_public_key_stays_post_ok(self, tmp_path):
        """取得到公钥 = 生成物**会**复现该加密 → 不该判成交互式（否则把能用的登录弄丢）。"""
        session = _session(tmp_path, post_data=json.dumps({"username": "u", "password": "p"}))
        scripts = session / "scripts"
        scripts.mkdir()
        (scripts / "login.js").write_text(
            'var k = "-----BEGIN PUBLIC KEY-----\\nQUJDREVGR0g=\\n-----END PUBLIC KEY-----";',
            encoding="utf-8")
        login = detect_auth_login([_login_endpoint(query_params={"encrypt": ["2"]})], session)
        assert login is not None
        assert login["password_encryption"]["public_key"]
        assert "encrypted_password" not in login["post_login"]["signals"]
        assert login["post_login"]["verdict"] == "post_ok"


# --------------------------------------------------------------------------- #
# 第二层：实测结果落盘 → 进 analysis（生成期据此判定）
# --------------------------------------------------------------------------- #
class TestMeasuredVerdictReachesAnalysis:
    def test_measured_failure_wins_over_static(self, tmp_path):
        """实测登录失败 → 即使静态没抓到信号，也判 interactive。"""
        states = tmp_path / "auth_states"
        state_path = states / "oa_example_com.json"
        _sidecar(states, verdict="interactive", reason="rejected_credentials")
        session = _session(tmp_path, auth_state_path=state_path)

        analysis = analyze_capture(session)
        post = analysis["auth_login"]["post_login"]
        assert post["verdict"] == "interactive"
        assert post["basis"] == "measured"
        assert post["measured"]["reason"] == "rejected_credentials"
        assert post["measured"]["attempts"] == 2
        # 边车里的 host 不往 analysis 里搬（registry 是要分发的，少一个字段少一个面）
        assert "host" not in post["measured"]

    def test_measured_success_wins_over_static_captcha(self, tmp_path):
        """**以实际结果为准**：静态说有验证码、实测真能登录 → 按「能登录」处理。"""
        states = tmp_path / "auth_states"
        state_path = states / "oa_example_com.json"
        _sidecar(states, verdict="post_ok", reason="", statuses=(200,))
        session = _session(tmp_path, post_data=json.dumps(
            {"username": "u", "password": "p", "captcha": "1234"}), auth_state_path=state_path)

        analysis = analyze_capture(session)
        post = analysis["auth_login"]["post_login"]
        assert post["verdict"] == "post_ok"
        assert post["basis"] == "measured"
        assert "captcha_field" in post["signals"], "静态信号仍要如实记下（用户有权知道）"

    def test_sidecar_for_another_host_is_ignored(self, tmp_path):
        states = tmp_path / "auth_states"
        state_path = states / "other_example_com.json"
        _sidecar(states, verdict="interactive", host="other.example.com",
                 stem="other_example_com")
        session = _session(tmp_path, auth_state_path=state_path)

        analysis = analyze_capture(session)
        assert analysis["auth_login"]["post_login"]["basis"] == "static"

    def test_missing_or_broken_metadata_falls_back_to_static(self, tmp_path):
        """读不到实测结果只意味着「退回静态预判」，绝不能让分析失败。"""
        session = _session(tmp_path, auth_state_path=tmp_path / "nope" / "x.json")
        analysis = analyze_capture(session)
        assert analysis["auth_login"]["post_login"]["verdict"] == "post_ok"

        (session / "session.json").write_text("{not json", encoding="utf-8")
        analysis = analyze_capture(session)
        assert analysis["auth_login"]["post_login"]["basis"] == "static"

    def test_unreadable_sidecar_falls_back_to_static(self, tmp_path):
        states = tmp_path / "auth_states"
        states.mkdir(parents=True)
        (states / "oa_example_com.login_mode.json").write_text("{not json", encoding="utf-8")
        session = _session(tmp_path, auth_state_path=states / "oa_example_com.json")

        analysis = analyze_capture(session)
        assert analysis["auth_login"]["post_login"]["basis"] == "static"

    def test_verdict_lands_in_registry_which_is_what_the_generator_reads(self, tmp_path):
        """判据要能一路走到 registry.json —— 生成期读的就是它。"""
        from webapi_extractor.project import init_project, load_registry, set_auth_login

        project = tmp_path / "proj"
        init_project(project, "portal")
        set_auth_login(project, _interactive_login())
        stored = load_registry(project)["auth_login"]["post_login"]
        assert stored["verdict"] == "interactive"
        assert stored["signals"] == ["captcha_field"]


class TestSummaryKeyIsAlwaysReadable:
    """`analyze_traffic` 摘要里的 `auth_login_post_login` 键常驻（消费方可无条件读）。"""

    def test_summary_shape_without_login(self):
        from webapi_extractor.analyzer import login_post_summary

        assert login_post_summary(None) == {"verdict": None, "basis": None,
                                            "signals": [], "measured_reason": None}

    def test_summary_carries_the_verdict(self):
        from webapi_extractor.analyzer import login_post_summary

        summary = login_post_summary(_interactive_login(
            measured={"verdict": "interactive", "attempts": 2,
                      "reason": "interactive_required", "statuses": [200, 200]}))
        assert summary["verdict"] == "interactive"
        assert summary["basis"] == "measured"
        assert summary["signals"] == ["captcha_field"]
        assert summary["measured_reason"] == "interactive_required"
        assert "statuses" not in summary, "状态码这类细节只留在 analysis/registry 里"


# --------------------------------------------------------------------------- #
# 第二层：http_login 真的 POST、失败再试一次、并把结论落盘
# --------------------------------------------------------------------------- #
class _FakeCookie:
    def __init__(self, name, value):
        self.name, self.value = name, value
        self.domain, self.path = HOST, "/"
        self.secure, self.expires = True, -1


class _FakeJar:
    def __init__(self, cookies):
        self.jar = list(cookies)


class _Resp:
    def __init__(self, status=200, text="", payload=None):
        self.status_code, self.text, self._payload = status, text, payload
        self.url = LOGIN_URL

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class _FakeClient:
    """按脚本回放响应：`posts` 依次用于每次 POST，`page` 用于 GET 登录页。

    ``post_sets_cookies`` 模拟「POST 之后服务端才下发凭据类 Cookie」——
    这正是判定「实测能不能换来凭据」要区分的场景。
    """

    def __init__(self, posts, page=None, cookies=(), post_sets_cookies=()):
        self._posts, self._page = list(posts), page or _Resp(200, "")
        self._post_cookies = list(post_sets_cookies)
        self.calls: list[tuple[str, str, str]] = []
        self.cookies = _FakeJar([_FakeCookie(n, v) for n, v in cookies])

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def get(self, url, **kwargs):
        self.calls.append(("GET", url, ""))
        return self._page

    async def post(self, url, **kwargs):
        body = "json" if "json" in kwargs else ("form" if "data" in kwargs else "?")
        self.calls.append(("POST", url, body))
        for name, value in self._post_cookies:
            self.cookies.jar.append(_FakeCookie(name, value))
        self._post_cookies = []
        return self._posts.pop(0)


def _install_client(monkeypatch, client):
    monkeypatch.setattr(auth_module.httpx, "AsyncClient", lambda *a, **kw: client)
    monkeypatch.setattr(auth_module, "_MEMORY_SECRETS", {})
    return client


def _login_form_page() -> _Resp:
    return _Resp(200, text='<form action="/api/login"><input name="username">'
                           '<input name="password"><input name="csrf" value="c1"></form>')


class TestHttpLoginRecordsTheVerdict:
    def test_success_with_token_records_post_ok(self, monkeypatch, tmp_path):
        states = tmp_path / "auth_states"
        client = _FakeClient([_Resp(200, payload={"token": "t1"})])
        _install_client(monkeypatch, client)

        result = asyncio.run(http_login(LOGIN_URL, ACCOUNT, PASSWORD, states,
                                        f"{LOGIN_URL}{LOGIN_PATH.lstrip('/')}"))
        assert result["success"] is True
        sidecar = json.loads((states / "oa_example_com.login_mode.json").read_text("utf-8"))
        assert sidecar["verdict"] == "post_ok"
        assert client.calls == [("POST", f"{LOGIN_URL}api/login", "json")], "成功时不该重试"

    def test_nested_token_counts_as_evidence(self, monkeypatch, tmp_path):
        """token 在 `data.token` 里（很常见）也算实测通过 —— 否则会误判成交互式。

        回报与落盘必须一致：不能一边跟用户说「构造请求登录没成功，改用浏览器」，
        一边把 `post_ok` 记进边车（生成物据此发射 `login()`）。
        """
        states = tmp_path / "auth_states"
        client = _FakeClient([_Resp(200, payload={"data": {"token": "t1"}})])
        _install_client(monkeypatch, client)

        result = asyncio.run(http_login(LOGIN_URL, ACCOUNT, PASSWORD, states,
                                        f"{LOGIN_URL}{LOGIN_PATH.lstrip('/')}"))
        sidecar = json.loads((states / "oa_example_com.login_mode.json").read_text("utf-8"))
        assert sidecar["verdict"] == "post_ok"
        assert result["success"] is True, "结论说能登录，回报就不能说失败"

    def test_verdict_and_report_never_contradict(self, monkeypatch, tmp_path):
        """不变量：`interactive` ⇒ 回报失败；`post_ok` ⇒ 回报成功。"""
        states = tmp_path / "auth_states"
        client = _FakeClient([_Resp(401, text="bad"), _Resp(401, text="bad")],
                             page=_login_form_page())
        _install_client(monkeypatch, client)
        result = asyncio.run(http_login(LOGIN_URL, ACCOUNT, PASSWORD, states,
                                        f"{LOGIN_URL}{LOGIN_PATH.lstrip('/')}"))
        sidecar = json.loads((states / "oa_example_com.login_mode.json").read_text("utf-8"))
        assert sidecar["verdict"] == "interactive" and result["success"] is False
        assert result["reason"] == "rejected_credentials"

    def test_new_credential_cookie_counts_as_evidence(self, monkeypatch, tmp_path):
        """POST **之后**新下发的凭据类 Cookie → 能自动登录。"""
        states = tmp_path / "auth_states"
        client = _FakeClient([_Resp(200, text="ok")],
                             post_sets_cookies=[("loginToken", "t9")])
        _install_client(monkeypatch, client)

        asyncio.run(http_login(LOGIN_URL, ACCOUNT, PASSWORD, states,
                               f"{LOGIN_URL}{LOGIN_PATH.lstrip('/')}"))
        sidecar = json.loads((states / "oa_example_com.login_mode.json").read_text("utf-8"))
        assert sidecar["verdict"] == "post_ok"

    def test_login_page_cookie_in_the_baseline_is_not_evidence(self, monkeypatch, tmp_path):
        """登录页的 GET 已经下发 JSESSIONID，POST 失败后它**不是**新凭据。"""
        states = tmp_path / "auth_states"
        client = _FakeClient([_Resp(200, text="bad"), _Resp(200, text="bad")],
                             page=_login_form_page(), cookies=[("JSESSIONID", "s1")])
        _install_client(monkeypatch, client)

        asyncio.run(http_login(LOGIN_URL, ACCOUNT, PASSWORD, states,
                               f"{LOGIN_URL}{LOGIN_PATH.lstrip('/')}"))
        sidecar = json.loads((states / "oa_example_com.login_mode.json").read_text("utf-8"))
        assert sidecar["verdict"] == "no_evidence", \
            "只在「POST 前后 Cookie 没变化」时才会走到这里：不下结论，交回静态预判"

    def test_failure_posts_twice_with_a_corrected_shape(self, monkeypatch, tmp_path):
        """失败 → 换个形态**再 POST 一次**（参数承载方式一并修正），并落盘 interactive。"""
        states = tmp_path / "auth_states"
        fail = _Resp(200, text='{"code":1,"msg":"用户名或密码错误"}')
        client = _FakeClient([fail, _Resp(200, text='{"code":1}')], page=_login_form_page())
        _install_client(monkeypatch, client)

        result = asyncio.run(http_login(LOGIN_URL, ACCOUNT, PASSWORD, states,
                                        f"{LOGIN_URL}{LOGIN_PATH.lstrip('/')}"))
        assert result["success"] is False
        assert result["fallback"] == "interactive"
        assert result["attempts"] == 2
        shapes = [call[2] for call in client.calls if call[0] == "POST"]
        assert shapes == ["json", "form"], f"第二次必须换个形态再 POST：{client.calls}"
        sidecar = json.loads((states / "oa_example_com.login_mode.json").read_text("utf-8"))
        assert sidecar["verdict"] == "interactive"
        assert sidecar["attempts"] == 2
        assert sidecar["statuses"] == [200, 200]

    def test_captcha_text_in_the_failure_response_is_the_reason(self, monkeypatch, tmp_path):
        """服务端自己说要验证码 —— 这是最强的一手证据，原因码要如实记下。"""
        states = tmp_path / "auth_states"
        client = _FakeClient([_Resp(200, text="请输入验证码"),
                              _Resp(200, text="请输入验证码")], page=_login_form_page())
        _install_client(monkeypatch, client)

        result = asyncio.run(http_login(LOGIN_URL, ACCOUNT, PASSWORD, states,
                                        f"{LOGIN_URL}{LOGIN_PATH.lstrip('/')}"))
        assert result["reason"] == "interactive_required"
        sidecar = json.loads((states / "oa_example_com.login_mode.json").read_text("utf-8"))
        assert sidecar["reason"] == "interactive_required"

    def test_page_cookie_alone_is_not_evidence(self, monkeypatch, tmp_path):
        """只 GET 到登录页（页面自己下发 JSESSIONID）**不算**能构造请求登录。

        修复前的成功判据只看 Cookie 罐非空 —— 于是带验证码的站点会被记成 `post_ok`，
        生成物又会假装有 401 自动重登录。这里必须记成「没有证据」，交回静态预判。
        """
        states = tmp_path / "auth_states"
        client = _FakeClient([], page=_Resp(200, text="<html>login</html>"),
                             cookies=[("JSESSIONID", "s1")])
        _install_client(monkeypatch, client)

        asyncio.run(http_login(LOGIN_URL, ACCOUNT, PASSWORD, states))
        assert client.calls == [("GET", LOGIN_URL, "")], "没找到表单时不该乱 POST"
        sidecar = json.loads((states / "oa_example_com.login_mode.json").read_text("utf-8"))
        assert sidecar["verdict"] == "no_evidence"

    def test_sidecar_never_contains_credentials(self, monkeypatch, tmp_path):
        """边车是长期留存的本地文件：绝不能写账号 / 口令 / 响应正文。"""
        states = tmp_path / "auth_states"
        client = _FakeClient([_Resp(200, text=f"bad {ACCOUNT} {PASSWORD}"),
                              _Resp(200, text="bad")], page=_login_form_page())
        _install_client(monkeypatch, client)

        asyncio.run(http_login(LOGIN_URL, ACCOUNT, PASSWORD, states,
                               f"{LOGIN_URL}{LOGIN_PATH.lstrip('/')}"))
        raw = (states / "oa_example_com.login_mode.json").read_bytes()
        assert ACCOUNT.encode() not in raw and PASSWORD.encode() not in raw
        assert b"bad" not in raw, "响应正文不得进边车"
        body = json.loads(raw.decode("utf-8"))
        assert set(body) == {"host", "verdict", "attempts", "reason", "statuses", "checked_at"}

    def test_failure_message_is_actionable_for_a_non_technical_user(self, monkeypatch, tmp_path):
        """失败时要给出**出路**（改用交互式登录），而不是把原因码丢给用户。"""
        states = tmp_path / "auth_states"
        client = _FakeClient([_Resp(200, text="nope"), _Resp(200, text="nope")],
                             page=_login_form_page())
        _install_client(monkeypatch, client)

        result = asyncio.run(http_login(LOGIN_URL, ACCOUNT, PASSWORD, states,
                                        f"{LOGIN_URL}{LOGIN_PATH.lstrip('/')}"))
        assert result["login_mode_recorded"] is True
        assert "自带交互式登录" in result["message"]
        assert "open_browser_login" in result["message"], "要告诉 Agent 现在该怎么办"

    def test_unwritable_sidecar_does_not_break_login(self, monkeypatch, tmp_path):
        """落盘失败只是「生成期读不到」，绝不能把登录流程本身搞崩。"""
        states = tmp_path / "auth_states"
        states.mkdir(parents=True)
        (states / "oa_example_com.login_mode.json").mkdir()   # 同名目录 → 写不进去
        client = _FakeClient([_Resp(200, payload={"token": "t1"})])
        _install_client(monkeypatch, client)

        result = asyncio.run(http_login(LOGIN_URL, ACCOUNT, PASSWORD, states,
                                        f"{LOGIN_URL}{LOGIN_PATH.lstrip('/')}"))
        assert result["success"] is True


# --------------------------------------------------------------------------- #
# 生成器：只在拿到明确结论时改产物；其余情况逐字节不变
# --------------------------------------------------------------------------- #
class TestGeneratorGate:
    def test_absent_field_changes_nothing(self):
        """老 registry（没有这个键）与 `post_ok` / `None` 的产物必须**逐字节相同**。"""
        legacy = _registry(_interactive_login())
        legacy["auth_login"].pop("post_login")
        baseline = _render(legacy)

        with_ok = _registry(_interactive_login(verdict="post_ok", signals=()))
        assert _render(with_ok) == baseline

        with_none = _registry(dict(_interactive_login(), post_login=None))
        assert _render(with_none) == baseline

    def test_post_ok_with_signals_still_changes_nothing(self):
        """弱信号（签名 / 时间戳）不足以改产物 —— 只写进 registry，供人看。"""
        legacy = _registry(_interactive_login())
        legacy["auth_login"].pop("post_login")
        assert _render(_registry(_interactive_login(
            verdict="post_ok", signals=("signed_params",)))) == _render(legacy)

    def test_interactive_emits_playwright_pinned_in_requirements(self):
        files = _render(_registry(_interactive_login()))
        assert f"playwright=={_PLAYWRIGHT_PIN}" in files["requirements.txt"], \
            "交互式登录要钉死 playwright 版本（内核按版本缓存，放开会重下浏览器）"

    def test_interactive_drops_the_fake_auto_relogin(self):
        """判为「不能 POST」就不能再发射 `login()` / `_do_login()`（那套必然失败）。"""
        src = _server(_registry(_interactive_login()))
        assert "async def _do_login(" not in src
        assert "async def login(" not in src
        assert "async def auth_status(" not in src
        assert "_AUTH_LOGIN_CFG = None" not in src, "登录配置仍要保留（登录页地址要用）"

    def test_interactive_emits_the_three_tools(self):
        src = _server(_registry(_interactive_login()))
        for name in ("login_interactive", "get_login_status", "confirm_login"):
            assert re.search(rf"async def {name}\(\)", src), name
        compile(src, "server.py", "exec")

    def test_interactive_never_auto_confirms(self):
        """**绝不自动判定登录完成**：状态只由 confirm_login 翻转，轮询里不得写 completed。

        （技能侧 `auth.py` 记过这次事故：自动放行会在用户还在输密码时就把会话判成完成。）
        """
        src = _server(_registry(_interactive_login()))
        body = src.split("async def _interactive_worker(")[1].split("@mcp.tool()")[0]
        # 轮询里唯一的状态写入必须是「保存好了」；completed / confirmed 只能由工具翻转。
        writes = [line.strip() for line in body.splitlines() if '_INTERACTIVE["status"] =' in line]
        assert writes == ['_INTERACTIVE["status"] = "saved"'], writes
        assert 'while _INTERACTIVE.get("session_id") == session_id' in body
        # 只读的那个工具不得改状态（否则 Agent 轮询几次就把登录「轮」完了）。
        status_tool = src.split("async def get_login_status(")[1].split("@mcp.tool()")[0]
        assert '_INTERACTIVE["status"]' not in status_tool.replace(
            '_INTERACTIVE.get("status")', "")

    def test_interactive_reads_cookies_from_the_saved_state(self):
        """登录态保存后，工具要真的带上它（不必手工往 .env 粘 Cookie）。"""
        src = _server(_registry(_interactive_login()))
        assert "_cookies_from_auth_state(host)" in src
        assert "auth_state.json" in src
        assert "storage_state(path=str(_AUTH_STATE))" in src

    def test_interactive_installs_playwright_at_initialization(self):
        src = _server(_registry(_interactive_login()))
        assert "_prepare_playwright_in_background()" in src
        assert '"playwright==" + _PLAYWRIGHT_PIN' in src
        assert '"-m", "playwright", "install", "chromium"' in src

    def test_interactive_readme_explains_the_one_thing_to_do(self):
        readme = _render(_registry(_interactive_login()))["README.md"]
        assert "login_interactive()" in readme and "confirm_login()" in readme
        assert "没有 401 自动重登录" in readme, "不能承诺自动续期"
        assert "不会**自动判定" in readme or "不会自动判定" in readme.replace("*", "")
        assert "验证码字段" in readme, "判据要如实列给用户（为什么不能自动登录）"

    def test_interactive_env_example_has_no_account_password_lines(self):
        env = _render(_registry(_interactive_login()))["requirements.txt"]
        assert "playwright" in env
        example = _render(_registry(_interactive_login()))[".env.example"]
        assert "PORTAL_ACCOUNT" not in example and "PORTAL_PASSWORD" not in example
        assert "login_interactive" in example

    def test_interactive_401_hint_points_at_the_browser_window(self):
        src = _server(_registry(_interactive_login()))
        assert "login_interactive()" in src
        assert "可调用 login(account=" not in src, "不能指一个不存在的 login()"

    def test_context_is_marked_as_not_postable(self, tmp_path):
        """`post_login` 是分析侧元数据：不进 `_AUTH_LOGIN_CFG`（运行期没人读它）。"""
        src = _server(_registry(_interactive_login()))
        cfg = next(line for line in src.splitlines()
                   if line.startswith("_AUTH_LOGIN_CFG = "))
        assert "post_login" not in cfg


# --------------------------------------------------------------------------- #
# 401 指路必须与 `.env.example` 同一份事实
# --------------------------------------------------------------------------- #
def _auth_fail_vars(src: str) -> list[str]:
    """取 401 报错里那句「请检查 .env 中的 X、Y」点到的变量名。"""
    match = re.search(r"请检查 \.env 中的 ([^\"\n]+?) 配置。", src)
    assert match, "401 报错里没有指路那句"
    return re.findall(r"[A-Z][A-Z0-9_]+", match.group(1))


class TestAuthFailureHintMatchesEnvExample:
    """修复前硬写 `<PREFIX>_TOKEN`，而纯 Cookie 站点的 `.env.example` 里没有这一行。"""

    SHAPES = {
        "cookie_only": {"scheme": None, "cookie_names": ["JSESSIONID"]},
        "bearer": {"scheme": "Bearer", "cookie_names": []},
        "basic": {"scheme": "Basic", "cookie_names": []},
        "mixed": {"scheme": "Bearer", "cookie_names": ["JSESSIONID"],
                  "schemes": ["Bearer", "Basic"]},
    }

    @pytest.mark.parametrize("name", sorted(SHAPES))
    def test_every_named_variable_exists_in_env_example(self, name):
        files = _render(_registry(hosts={HOST: dict(self.SHAPES[name])}))
        named = _auth_fail_vars(files["server.py"])
        assert named, f"{name}: 没点到任何变量，测试本身可疑"
        for var in named:
            assert re.search(rf"^{var}=", files[".env.example"], re.M), \
                f"{name}: 401 报错让用户去配 {var}，而 .env.example 里没有这一行"

    @pytest.mark.parametrize("name", sorted(SHAPES))
    def test_named_variable_exists_for_interactive_projects_too(self, name):
        files = _render(_registry(_interactive_login(),
                                  hosts={HOST: dict(self.SHAPES[name])}))
        for var in _auth_fail_vars(files["server.py"]):
            assert re.search(rf"^{var}=", files[".env.example"], re.M), name

    def test_cookie_site_points_at_the_cookie_variable(self):
        files = _render(_registry(hosts={HOST: {"scheme": None,
                                                "cookie_names": ["JSESSIONID"]}}))
        assert "PORTAL_COOKIE_OA_EXAMPLE_COM" in files["server.py"]

    def test_mixed_site_names_the_token_it_now_provides(self):
        """混用站点里 Bearer 接口需要 token —— README 一直这么说，`.env.example` 也得给。"""
        files = _render(_registry(hosts={HOST: {"scheme": "Bearer",
                                                "cookie_names": ["JSESSIONID"],
                                                "schemes": ["Bearer", "Basic"]}}))
        assert "PORTAL_TOKEN" in _auth_fail_vars(files["server.py"])
        assert re.search(r"^PORTAL_TOKEN=$", files[".env.example"], re.M)

    def test_public_site_does_not_point_at_cookies(self):
        """没有 Cookie 通道时不该指 Cookie 变量。"""
        files = _render(_registry(
            hosts={HOST: {"scheme": None, "cookie_names": []}},
            endpoints=[dict(_registry()["endpoints"][0], auth_required=False)]))
        assert "PORTAL_COOKIE_" not in _auth_fail_vars(files["server.py"])


# --------------------------------------------------------------------------- #
# 对抗语料：交互式注入
# --------------------------------------------------------------------------- #
class TestAdversarialInteractive:
    """交互式登录把 **host**（抓包得来、不可信）写进生成物 —— 必须是纯字面量。"""

    def _registry_with(self, host: str, site: str = "portal", **ep_over) -> dict:
        entry = {"tool_name": "get_x", "method": "GET", "host": host,
                 "path": f'/api/x") ; {PWN} ; _d = ("', "path_params": [],
                 "query_params": {}, "auth_required": True, "status": "active",
                 "description": "line1\n" + PWN}
        entry.update(ep_over)
        return {
            "site_name": site, "registry_version": 1,
            "hosts": {host: {"scheme": None, "cookie_names": ["JSESSIONID"]}},
            "endpoints": [entry],
            "auth_login": {"method": "POST", "host": host, "path": "/api/login",
                           "account_field": "username", "password_field": "password",
                           "token_path": ["data", "token"], "query_params": {},
                           "post_login": _post_login()},
        }

    CASES = {
        "host_quote_injection": (f'x" ; {PWN} ; _d = ("', "portal"),
        "host_brace_injection": (f"a{{b}}.{PWN}", "portal"),
        "host_newline_injection": ("a\n" + PWN, "portal"),
        "host_backslash_and_hash": ('a\\b#c."' + PWN, "portal"),
        "site_name_injection": (HOST, 'evil" )\n' + PWN + ' #'),
    }

    @pytest.mark.parametrize("case", sorted(CASES))
    def test_compiles(self, case):
        host, site = self.CASES[case]
        compile(_server(self._registry_with(host, site)), "server.py", "exec")

    @pytest.mark.parametrize("case", sorted(CASES))
    def test_no_injection(self, case):
        host, site = self.CASES[case]
        src = _server(self._registry_with(host, site))
        assert _injection_findings(src) == [], "工具函数体里出现了可执行调用"
        assert "login_interactive" in src

    def test_login_url_is_a_lookup_not_an_interpolation(self):
        """登录页地址只能拿 host 当**键**去查 HOSTS，不能拼进源码结构里。"""
        src = _server(self._registry_with(f'x" ; {PWN} ; _d = ("'))
        assert "_LOGIN_URL = str(HOSTS.get(_LOGIN_HOST) or \"\") + \"/\"" in src

    def test_captured_host_is_not_executed_at_render_time(self):
        """渲染期不得把抓包内容当代码求值（返回的就是文本）。"""
        host = 'x" ; ' + PWN + ' ; _d = ("'
        files = _render(self._registry_with(host))
        assert isinstance(files["server.py"], str)
        assert "PWNED" not in files["server.py"] or host in files["server.py"]


# --------------------------------------------------------------------------- #
# 结构守卫：auth.py 的第二层实现细节
# --------------------------------------------------------------------------- #
class TestAuthImplementationGuards:
    def test_record_helper_writes_only_the_verdict_fields(self):
        source = inspect.getsource(auth_module.record_login_mode)
        for forbidden in ("password", "username", "ACCOUNT"):
            assert forbidden not in source, f"边车写入里不该出现 {forbidden}"

    def test_http_login_keeps_the_legacy_success_semantics(self):
        """工具的成功判据不变（兼容既有调用方）；「实测有凭据」另外判。"""
        source = inspect.getsource(auth_module.http_login)
        assert "success = response.status_code in {200, 201, 204, 302}" \
            in inspect.getsource(auth_module._evaluate_login_response)
        assert "no_evidence" in source

    def test_no_auto_login_loop_in_the_probe(self):
        """实测只试**两次**，绝不在失败后反复重试登录（会锁账号）。"""
        source = inspect.getsource(auth_module.http_login)
        assert "while" not in source
