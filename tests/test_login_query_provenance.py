# -*- coding: utf-8 -*-
"""任务 1：(a) 类「疑似来源」——登录 query 参数的值疑似来自**前面的某个响应**。

用户已决定：这类**只上报、不生成代码**。分析器据此只产出线索（写进 analysis.json 的
``auth_login["query_param_provenance"]`` 与 ``analyze_traffic`` 摘要），交给人 / LLM
确认；生成器**完全不知道**这个字段存在（本文件直接断言 ``generator.py`` 里没有它）。

判定必须按**抓包的时间顺序**：``analyzer._index_capture`` 按 requestId 塞 dict、丢掉
了跨 requestId 的先后，所以实现自己按文件顺序扫一遍 ``capture.jsonl``。本文件的夹具
因此全部按**真实顺序**书写。

判不出来是**常态**：值太短 / 是脱敏哨兵 / 在前序响应里多命中 / 来源体被丢或非 JSON /
循环依赖（来源就是登录端点、校验端点，或带同一个鉴权头，或晚于登录）—— 每条都要报
「不可知」，且**绝不**编一个来源出来。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from webapi_extractor.analyzer import (
    PROVENANCE_SUSPECTED,
    PROVENANCE_UNKNOWN,
    analyze_capture,
    analyze_query_param_provenance,
    login_query_leads,
    login_query_unknown_count,
)

HOST = "portal.example.com"
LOGIN_PATH = "/api/login"
VALUE = "TOKENVALUE123456"          # 16 字符，过得了「长度 >= 8」闸门


# --------------------------------------------------------------------------- #
# 夹具：按文件顺序写 capture.jsonl
# --------------------------------------------------------------------------- #
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


def _json_request(request_id, url):
    """一个带 JSON 响应体的普通 GET 请求（三事件一组）。"""
    return [_request(request_id, url), _response(request_id),
            _body(request_id, json.dumps({"data": {"token": "x"}}))]


def _login_events(value=VALUE, request_id="login", headers=None, post_data=None):
    query = "" if value is None else f"?csrf={value}"
    return [
        _request(request_id, f"https://{HOST}{LOGIN_PATH}{query}", "POST",
                 headers, post_data if post_data is not None
                 else json.dumps({"username": "u", "password": "p"})),
        _response(request_id),
        _body(request_id, json.dumps({"data": {"token": "tok"}})),
    ]


def _write(tmp_path, events, name="s"):
    session = tmp_path / name
    session.mkdir(parents=True, exist_ok=True)
    (session / "capture.jsonl").write_text(
        "\n".join(json.dumps(event, ensure_ascii=False) for event in events) + "\n",
        encoding="utf-8")
    return session


def _login_of(session):
    analysis = analyze_capture(session)
    assert analysis.get("auth_login"), "夹具本身失效：登录端点没被识别出来"
    return analysis["auth_login"]


# --------------------------------------------------------------------------- #
# (i) 能判定：前序的公共无鉴权 GET 响应里含该值
# --------------------------------------------------------------------------- #
class TestSuspectedSourceIsReported:
    def test_source_endpoint_is_named(self, tmp_path):
        events = [
            _request("cfg", f"https://{HOST}/api/config"),
            _response("cfg"),
            _body("cfg", json.dumps({"data": {"csrf": VALUE}})),
        ] + _login_events()

        login = _login_of(_write(tmp_path, events))
        entry = login["query_param_provenance"]["csrf"]

        assert entry["class"] == PROVENANCE_SUSPECTED
        assert entry["suspected_source"] == {
            "method": "GET", "host": HOST, "path": "/api/config",
            "response_field": "$.data.csrf"}
        assert entry["needs_confirmation"] is True
        # 五条闸门全中 → 给出**可自动取用**的计划（生成器据此发射取用代码），
        # 说明里写明「自动」「无需你填写」，而不是把活推给使用者。
        assert entry["fetch"] == {
            "name": None, "method": "GET",
            "url": f"https://{HOST}/api/config",
            "field": ["data", "csrf"], "field_display": "$.data.csrf"}
        assert entry["fetch_block"] is None
        assert "自动" in entry["note"] and "无需你填写" in entry["note"]
        # 上报里**绝不**出现取值（避免二次泄漏，也避免被当成「可以烘的值」）
        assert VALUE not in json.dumps(entry, ensure_ascii=False)

    def test_analyze_capture_keeps_the_field_on_auth_login(self, tmp_path):
        events = [_request("cfg", f"https://{HOST}/api/config"), _response("cfg"),
                  _body("cfg", json.dumps({"config": {"csrf": VALUE}}))] + _login_events()
        login = _login_of(_write(tmp_path, events))
        assert "query_param_provenance" in login
        assert login["query_param_provenance"]["csrf"]["class"] == PROVENANCE_SUSPECTED

    def test_order_matters_not_dict_insertion(self, tmp_path):
        """同样的端点，出现在登录**之后**就不能算来源（时序不成立）。"""
        events = _login_events() + [
            _request("cfg", f"https://{HOST}/api/config"),
            _response("cfg"),
            _body("cfg", json.dumps({"csrf": VALUE})),
        ]
        login = _login_of(_write(tmp_path, events))
        entry = login["query_param_provenance"]["csrf"]
        assert entry["class"] == PROVENANCE_UNKNOWN
        assert entry["suspected_source"] is None


# --------------------------------------------------------------------------- #
# (ii) 判不出：值太短 / 多命中
# --------------------------------------------------------------------------- #
class TestUnknownBecauseOfValueShapeOrAmbiguity:
    def test_short_value_is_unknown(self, tmp_path):
        events = [_request("cfg", f"https://{HOST}/api/config"), _response("cfg"),
                  _body("cfg", json.dumps({"csrf": "1"}))] + _login_events(value="1")
        login = _login_of(_write(tmp_path, events))
        entry = login["query_param_provenance"]["csrf"]

        assert entry["class"] == PROVENANCE_UNKNOWN
        assert entry["suspected_source"] is None
        assert entry["reason"] == "value_too_short"
        assert "长度" in entry["note"]

    def test_multiple_endpoints_are_ambiguous(self, tmp_path):
        events = [
            _request("a", f"https://{HOST}/api/config"), _response("a"),
            _body("a", json.dumps({"csrf": VALUE})),
            _request("b", f"https://{HOST}/api/banner"), _response("b"),
            _body("b", json.dumps({"csrf": VALUE})),
        ] + _login_events()
        login = _login_of(_write(tmp_path, events))
        entry = login["query_param_provenance"]["csrf"]

        assert entry["class"] == PROVENANCE_UNKNOWN
        assert entry["reason"] == "multiple_sources"
        assert entry["suspected_source"] is None
        assert "歧义" in entry["note"]
        assert entry["needs_confirmation"] is True

    def test_dropped_source_body_is_unknown(self, tmp_path):
        """来源体被丢弃 → 无法核对 → 不可知（不猜）。"""
        events = [
            _request("cfg", f"https://{HOST}/api/config"),
            _response("cfg"),
            {"type": "response_body", "requestId": "cfg", "body": None,
             "body_dropped": True, "size": 999999},
        ] + _login_events()
        login = _login_of(_write(tmp_path, events))
        entry = login["query_param_provenance"]["csrf"]

        assert entry["class"] == PROVENANCE_UNKNOWN
        assert entry["reason"] == "preceding_bodies_unavailable"
        assert "无法核对全部前序响应体" in entry["note"]
        assert "1 条被丢弃/不可用" in entry["note"]

    def test_non_json_source_is_never_used(self, tmp_path):
        """非 JSON 的前序响应体**不做**子串模糊比对 —— 值明明在里面也不认。"""
        events = [
            _request("cfg", f"https://{HOST}/api/config"), _response("cfg"),
            _body("cfg", f"plain text csrf={VALUE} end"),
        ] + _login_events()
        login = _login_of(_write(tmp_path, events))
        entry = login["query_param_provenance"]["csrf"]

        assert entry["class"] == PROVENANCE_UNKNOWN
        assert entry["suspected_source"] is None
        assert entry["reason"] == "preceding_bodies_unavailable"
        assert "1 条非 JSON" in entry["note"]


# --------------------------------------------------------------------------- #
# (iii) 循环依赖：绝不报成来源
# --------------------------------------------------------------------------- #
class TestCircularDependencyIsNeverASource:
    def test_source_is_the_login_endpoint_itself(self, tmp_path):
        """前序的 GET /api/login（登录页/自身响应）含该值 —— 仍是循环，不可知。"""
        events = [
            _request("page", f"https://{HOST}{LOGIN_PATH}"),
            _response("page"),
            _body("page", json.dumps({"csrf": VALUE})),
        ] + _login_events()
        login = _login_of(_write(tmp_path, events))
        entry = login["query_param_provenance"]["csrf"]

        assert entry["class"] == PROVENANCE_UNKNOWN
        assert entry["suspected_source"] is None
        assert entry["reason"] == "source_is_login_endpoint"
        assert "循环" in entry["note"]

    def test_source_carries_the_same_auth_header(self, tmp_path):
        auth = {"Authorization": "Bearer SAMEASLOGIN"}
        events = [
            _request("cfg", f"https://{HOST}/api/config", headers=auth),
            _response("cfg"),
            _body("cfg", json.dumps({"csrf": VALUE})),
        ] + _login_events(headers=auth)
        login = _login_of(_write(tmp_path, events))
        entry = login["query_param_provenance"]["csrf"]

        assert entry["class"] == PROVENANCE_UNKNOWN
        assert entry["suspected_source"] is None
        assert entry["reason"] == "source_carries_login_auth_header"

    def test_source_is_the_verify_endpoint(self, tmp_path):
        """来源是 auth_login["verify"] 指向的校验端点 → 循环，不可知。"""
        events = [
            _request("my", f"https://{HOST}/api/my/profile",
                     headers={"Authorization": "Bearer X"}),
            _response("my"),
            _body("my", json.dumps({"csrf": VALUE})),
        ] + _login_events()
        login = _login_of(_write(tmp_path, events))
        assert login["verify"] == {"host": HOST, "path": "/api/my/profile"}, \
            "夹具本身失效：校验端点没被识别"
        entry = login["query_param_provenance"]["csrf"]

        assert entry["class"] == PROVENANCE_UNKNOWN
        assert entry["suspected_source"] is None
        assert entry["reason"] == "source_is_verify_endpoint"

    def test_source_is_later_than_login(self, tmp_path):
        events = _login_events() + [
            _request("cfg", f"https://{HOST}/api/config"), _response("cfg"),
            _body("cfg", json.dumps({"csrf": VALUE})),
        ]
        login = _login_of(_write(tmp_path, events))
        entry = login["query_param_provenance"]["csrf"]

        assert entry["class"] == PROVENANCE_UNKNOWN
        assert entry["suspected_source"] is None
        assert entry["reason"] == "source_not_before_login"
        assert "时序" in entry["note"]


# --------------------------------------------------------------------------- #
# (iv) 脱敏哨兵：不可知，且不出现任何猜测值
# --------------------------------------------------------------------------- #
class TestRedactionSentinel:
    def test_sentinel_is_unknown_and_never_guesses(self, tmp_path):
        """值为 `***` 时，即便前序响应里躺着「像是真值」的串，也不许猜它。"""
        guess_a = "REALSECRETVALUE123456"
        guess_b = "ANOTHERSECRETVALUE99"
        events = [
            _request("cfg", f"https://{HOST}/api/config"), _response("cfg"),
            _body("cfg", json.dumps({"csrf": guess_a})),
            _request("cfg2", f"https://{HOST}/api/banner"), _response("cfg2"),
            _body("cfg2", json.dumps({"csrf": guess_b})),
        ] + _login_events(value="***")
        login = _login_of(_write(tmp_path, events))
        entry = login["query_param_provenance"]["csrf"]

        assert entry["class"] == PROVENANCE_UNKNOWN
        assert entry["reason"] == "redaction_sentinel"
        assert entry["suspected_source"] is None
        dumped = json.dumps(login["query_param_provenance"], ensure_ascii=False)
        # 任何输出里都不出现 `***` 以外的猜测值
        assert guess_a not in dumped and guess_b not in dumped

    def test_asterisk_variants_are_also_sentinels(self, tmp_path):
        events = _json_request("cfg", f"https://{HOST}/api/config") + _login_events(value="****")
        login = _login_of(_write(tmp_path, events))
        assert login["query_param_provenance"]["csrf"]["reason"] == "redaction_sentinel"


# --------------------------------------------------------------------------- #
# 摘要侧：只给**可行动**的线索（不带取值），「不可知」只给聚合计数
# --------------------------------------------------------------------------- #
class TestSummaryLeads:
    def _provenance_dict(self):
        return {
            "csrf": {"name": "csrf", "class": PROVENANCE_SUSPECTED,
                     "suspected_source": {"method": "GET", "host": HOST, "path": "/api/config"},
                     "reason": None, "needs_confirmation": True, "note": "疑似来自…",
                     "fetch": {"name": "csrf", "method": "GET",
                               "url": f"https://{HOST}/api/config",
                               "field": ["data", "csrf"], "field_display": "$.data.csrf"},
                     "fetch_block": None},
            # 「不可知」是常态：登录前必然先加载 HTML/JS/图片，逐条列就是每个参数一条。
            "page": {"name": "page", "class": PROVENANCE_UNKNOWN,
                     "suspected_source": None, "reason": "not_observed_in_preceding_response",
                     "needs_confirmation": False, "note": "未在任何前序响应体里出现 → 不可知"},
            "ts": {"name": "ts", "class": PROVENANCE_UNKNOWN,
                   "suspected_source": None, "reason": "gate",
                   "needs_confirmation": False, "note": "取值太短 → 不可知"},
        }

    def test_only_actionable_lead_is_listed(self):
        """只有「疑似来自响应」且给出来源端点的那条才上摘要，且绝不带取值。"""
        login = {"query_param_provenance": self._provenance_dict()}
        leads = login_query_leads(login)

        assert [lead["param"] for lead in leads] == ["csrf"]
        assert leads[0]["suspected_source"]["path"] == "/api/config"
        assert VALUE not in json.dumps(leads, ensure_ascii=False)

    def test_auto_fill_plan_is_surfaced(self):
        """R2：线索要**可行动** —— 「生成的服务会自己去这个地址取」必须出现在摘要里。"""
        leads = login_query_leads({"query_param_provenance": self._provenance_dict()})
        assert leads[0]["auto_fill"] == {
            "from": f"GET https://{HOST}/api/config", "field": "$.data.csrf"}

    def test_blocked_auto_fill_is_null_not_a_lie(self):
        """取用不了时 `auto_fill` 必须是 `None`（该参数会走必填），不能谎称会自动取。"""
        entry = dict(self._provenance_dict()["csrf"], fetch=None,
                     fetch_block="source_request_carries_auth")
        leads = login_query_leads({"query_param_provenance": {"csrf": entry}})
        assert leads[0]["auto_fill"] is None

    def test_unknown_is_aggregated_not_listed(self):
        """两条不可知 → 不出现在列表里，只由计数汇总（不制造逐条噪音）。"""
        login = {"query_param_provenance": self._provenance_dict()}
        assert login_query_unknown_count(login) == 2
        assert "page" not in [lead["param"] for lead in login_query_leads(login)]

    def test_suspected_but_sourceless_entry_is_not_actionable(self):
        login = {"query_param_provenance": {
            "x": {"name": "x", "class": PROVENANCE_SUSPECTED, "suspected_source": None,
                  "reason": "ambiguous", "needs_confirmation": True, "note": "歧义"}}}
        assert login_query_leads(login) == []
        assert login_query_unknown_count(login) == 1

    def test_missing_provenance_is_empty(self):
        assert login_query_leads(None) == []
        assert login_query_leads({}) == []
        assert login_query_unknown_count(None) == 0
        assert login_query_unknown_count({}) == 0


class TestDirectApiDegradesSafely:
    def test_no_session_dir_or_capture_yields_nothing(self, tmp_path):
        login = {"host": HOST, "method": "POST", "path": LOGIN_PATH,
                 "query_params": {"csrf": [VALUE]}}
        assert analyze_query_param_provenance(None, login) == {}
        assert analyze_query_param_provenance(tmp_path / "nope", login) == {}

    def test_login_request_absent_from_capture_is_unknown(self, tmp_path):
        """抓包里没有这次登录请求（例如 registry 来自别的会话）→ 不可知，不猜。"""
        session = _write(tmp_path, _json_request("cfg", f"https://{HOST}/api/config"))
        login = {"host": HOST, "method": "POST", "path": LOGIN_PATH,
                 "query_params": {"csrf": [VALUE]}}
        entry = analyze_query_param_provenance(session, login)["csrf"]

        assert entry["class"] == PROVENANCE_UNKNOWN
        assert entry["suspected_source"] is None
        assert "找不到" in entry["note"]


# --------------------------------------------------------------------------- #
# 护栏：绝不生成取用代码（generator 对字段一无所知）
# --------------------------------------------------------------------------- #
class TestGeneratorNeverSeesTheField:
    def test_extractor_tool_count_unchanged(self):
        source = (Path(__file__).resolve().parents[1]
                  / "webapi_extractor" / "server.py").read_text(encoding="utf-8")
        assert source.count("@mcp.tool()") == 21

    def test_provenance_is_not_in_the_registry_it_ships(self, tmp_path):
        """端到端护栏：从这样一次抓包生成，抓包取值不得出现在产物里。

        走的正是真实链路：analysis.auth_login → ``set_auth_login``（registry 出口，
        凭据类 query 取值被洗成 `***`）→ ``render_server``。``csrf`` 有可自动取用的来源，
        生成器发射的是**取用代码**（去来源接口现取），真值既不落 registry 也不进产物。
        """
        from webapi_extractor.generator import render_server
        from webapi_extractor.project import init_project, load_registry, set_auth_login

        events = [_request("cfg", f"https://{HOST}/api/config"), _response("cfg"),
                  _body("cfg", json.dumps({"csrf": VALUE}))] + _login_events()
        login = _login_of(_write(tmp_path, events))

        project = tmp_path / "proj"
        init_project(project, "portal")
        set_auth_login(project, login)
        registry = load_registry(project)
        registry["endpoints"] = [{"tool_name": "get_x", "method": "GET", "host": HOST,
                                  "path": "/api/config", "auth_required": False,
                                  "status": "active", "query_params": {}}]

        assert registry["auth_login"]["query_params"]["csrf"] == ["***"]
        files = render_server(registry)
        for name, text in files.items():
            assert VALUE not in text, f"{name} 夹带了抓包取值"

    def test_generated_server_omits_provenance_metadata(self, tmp_path):
        """生成物不得原样夹带**分析侧元数据**（逐值结论 / 原因码 / note）——但**取用计划**
        必须进生成物：R2 要的就是「登录前自己去来源接口取」，来源地址本来就该写在代码里。

        所以这里断言两件事：(1) 整份 ``query_param_provenance`` 记录不被烘进任何产物、
        `_AUTH_LOGIN_CFG` 里也没有这个键；(2) 取用计划指名了来源端点（否则等于没做）。
        registry.json 必须**保留**整份记录。
        """
        from webapi_extractor.generator import render_server
        from webapi_extractor.project import init_project, load_registry, set_auth_login

        source_path = "/api/init-config"
        events = [_request("cfg", f"https://{HOST}{source_path}"), _response("cfg"),
                  _body("cfg", json.dumps({"csrf": VALUE}))] + _login_events()
        login = _login_of(_write(tmp_path, events))
        assert login["query_param_provenance"]["csrf"]["suspected_source"]["path"] == source_path

        project = tmp_path / "proj-prov"
        init_project(project, "portal")
        set_auth_login(project, login)
        registry = load_registry(project)

        # registry 是记录：这条线索必须还在（别去擦它）。
        assert registry["auth_login"]["query_param_provenance"]["csrf"]["class"] == PROVENANCE_SUSPECTED

        files = render_server(registry)
        assert "server.py" in files, "render_server 未产出 server.py，测试本身失效"
        for name, text in files.items():
            assert "query_param_provenance" not in text, f"{name} 夹带了分析侧元数据"
        cfg_line = next(l for l in files["server.py"].splitlines()
                        if l.startswith("_AUTH_LOGIN_CFG = "))
        assert "query_param_provenance" not in cfg_line
        # 取用计划：来源地址与字段路径在，抓包取值不在。
        assert source_path in files["server.py"]
        assert "_LOGIN_FETCH" in files["server.py"]
        assert VALUE not in files["server.py"]


# --------------------------------------------------------------------------- #
# 工具层：analyze_traffic 摘要里的线索（可行动的才列，常驻键）
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def web(tmp_path_factory):
    """导入 server.py，并把它的数据目录固定在本模块的临时目录（绝不碰真实数据根）。"""
    import importlib
    import os

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


class TestAnalyzeTrafficSummary:
    def _session(self, web, tmp_path, monkeypatch, events, session_id="s1"):
        sessions = tmp_path / "sessions"
        sessions.mkdir(exist_ok=True)
        monkeypatch.setattr(web.store, "sessions_dir", sessions)
        directory = sessions / session_id
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "capture.jsonl").write_text(
            "\n".join(json.dumps(event, ensure_ascii=False) for event in events) + "\n",
            encoding="utf-8")
        (directory / "session.json").write_text(
            json.dumps({"session_id": session_id, "status": "stopped"}), encoding="utf-8")
        return session_id

    async def test_leads_appear_without_values(self, web, tmp_path, monkeypatch):
        events = [_request("cfg", f"https://{HOST}/api/config"), _response("cfg"),
                  _body("cfg", json.dumps({"csrf": VALUE}))] + _login_events()
        session_id = self._session(web, tmp_path, monkeypatch, events)

        result = await web.analyze_traffic(session_id)

        leads = result["auth_login_query_leads"]
        assert [lead["param"] for lead in leads] == ["csrf"]
        assert leads[0]["class"] == PROVENANCE_SUSPECTED
        assert leads[0]["suspected_source"]["path"] == "/api/config"
        # 端到端：公共无鉴权 GET + 早于登录 + 完整 JSON → 摘要直接给出取用计划
        assert leads[0]["auto_fill"]["from"] == f"GET https://{HOST}/api/config"
        assert leads[0]["auto_fill"]["field"] == "$.csrf"
        assert result["auth_login_query_unknown_count"] == 0
        assert VALUE not in json.dumps(result, ensure_ascii=False)

    async def test_a_non_public_source_yields_a_null_auto_fill(self, web, tmp_path,
                                                               monkeypatch):
        """来源带了鉴权头（不是公共接口）→ 不自动取用（`auto_fill` 为 null），
        但线索照旧上报（人仍能看到来源是哪个端点）。"""
        auth = {"Authorization": "Bearer OTHER"}
        events = [_request("cfg", f"https://{HOST}/api/config", headers=auth),
                  _response("cfg"),
                  _body("cfg", json.dumps({"csrf": VALUE}))] + _login_events()
        session_id = self._session(web, tmp_path, monkeypatch, events, session_id="s-auth")

        result = await web.analyze_traffic(session_id)

        leads = result["auth_login_query_leads"]
        assert [lead["param"] for lead in leads] == ["csrf"]
        assert leads[0]["auto_fill"] is None
        assert "自动取用" in leads[0]["note"] or "无法自动取用" in leads[0]["note"]
        assert VALUE not in json.dumps(result, ensure_ascii=False)

    async def test_all_unknown_gives_empty_list_plus_count(self, web, tmp_path, monkeypatch):
        """一条都判不出来源（常态）→ 列表为空、计数 > 0，而不是一堆逐条条目。"""
        events = _login_events()
        session_id = self._session(web, tmp_path, monkeypatch, events, session_id="s-unknown")

        result = await web.analyze_traffic(session_id)

        assert result["auth_login_query_leads"] == []
        assert result["auth_login_query_unknown_count"] >= 1

    async def test_keys_are_always_present_even_without_login_query_params(
            self, web, tmp_path, monkeypatch):
        """两个键**常驻**（空列表 / 0），风格同 needs_more_samples，消费方可无条件读。"""
        events = _login_events(value=None)
        session_id = self._session(web, tmp_path, monkeypatch, events, session_id="s2")

        result = await web.analyze_traffic(session_id)

        assert result["auth_login_query_leads"] == []
        assert result["auth_login_query_unknown_count"] == 0

