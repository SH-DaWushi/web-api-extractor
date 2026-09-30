# -*- coding: utf-8 -*-
"""`server.py` 工具层的迭代链路契约。

`runbook/06-iterate.md` 让 Agent 调的就是这几个工具（`diff_capture` / `merge_capture` /
`regenerate_server` / `export_project`），而 `tests/` **此前从不 import `server.py`**
（reference 的「测试」一节如实写着「21 个 MCP 工具层本身无测试」）。工具层比库层多两件事，
也是最容易出错的地方：

- 每个工具先确认 `analysis.json` 存在，否则**必须**提示先调 `analyze_traffic`，
  而不是抛异常、也不是拿空内容去合并；
- `merge_capture` 的 `endpoint_keys` 是 `"METHOD|host|path"` 三段字符串，
  解析错一位就会**静默少合并**端点 —— 用户明明确认了，却没进 registry。

导入 `server.py` 会跑 `Settings.from_environment()` + `ensure_directories()` + `recover_orphans()`
（后者会改真实会话状态），故本文件先把数据目录指到临时目录再导入，绝不碰本机
`~/.webapiextractor`。
"""
from __future__ import annotations

import asyncio
import importlib
import json
import os
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from webapi_extractor.auth import LoginSession
from webapi_extractor.project import init_project, load_registry, save_registry

HOST = "oa.example.com"


@pytest.fixture(scope="module")
def web(tmp_path_factory):
    """导入 server.py，并把它的数据目录固定在本模块的临时目录。"""
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


def _ep(name: str, **extra) -> dict:
    endpoint = {"method": "GET", "host": HOST, "path": f"/api/{name}", "query_params": {},
                "sample_count": 2, "request_schema": None, "response_schema": None,
                "auth_required": False, "description": None, "notes": None,
                "url": f"https://{HOST}/api/{name}"}
    endpoint.update(extra)
    return endpoint


def _letter_path(i: int) -> str:
    """第 i 条互不合并的路径（**纯字母**：数字段会被命名参数化折成 `{id}` 而并成一条）。"""
    return "/api/" + "".join(chr(ord("a") + (i // (26 ** k)) % 26) for k in (2, 1, 0))


def _analysis(endpoints: list[dict]) -> dict:
    return {"endpoints": endpoints,
            "auth_metadata": {"auth_schemes": {HOST: {"scheme": "cookie",
                                                      "cookie_names": ["JSESSIONID"]}}}}


@pytest.fixture()
def lab(web, tmp_path, monkeypatch):
    """每个用例一套临时会话目录与项目目录。"""
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    monkeypatch.setattr(web.store, "sessions_dir", sessions)

    def write_session(session_id: str, endpoints: list[dict]) -> str:
        directory = sessions / session_id
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "analysis.json").write_text(
            json.dumps(_analysis(endpoints), ensure_ascii=False), encoding="utf-8")
        return session_id

    def make_project(name: str = "proj") -> str:
        directory = tmp_path / name
        init_project(directory, "portal")
        return str(directory)

    return SimpleNamespace(web=web, tmp_path=tmp_path, write_session=write_session,
                           make_project=make_project, sessions=sessions)


class TestAnalysisGuard:
    """少一次 analyze_traffic 就合并 —— 会让 registry 静默变空，必须先拦住。"""

    async def test_diff_capture_without_analysis_says_what_to_do(self, lab):
        result = await lab.web.diff_capture(lab.make_project(), "s-never-analyzed")
        assert result["success"] is False
        assert result["error"] == "analysis_not_found"
        assert "analyze_traffic" in result["message"]

    async def test_merge_capture_without_analysis_does_not_touch_registry(self, lab):
        project = lab.make_project()
        before = (Path(project) / "registry.json").read_text(encoding="utf-8")

        result = await lab.web.merge_capture(project, "s-never-analyzed")

        assert result["success"] is False
        assert (Path(project) / "registry.json").read_text(encoding="utf-8") == before

    async def test_diff_capture_without_registry_report_is_readable(self, lab):
        session = lab.write_session("s1", [_ep("pets")])
        result = await lab.web.diff_capture(str(lab.tmp_path / "not-a-project"), session)

        assert result["success"] is False
        assert "registry.json" in result["error"]


class TestMergeCaptureTool:
    async def test_all_endpoints_merged_without_selection(self, lab):
        project = lab.make_project()
        session = lab.write_session("s1", [_ep("pets"), _ep("orders")])

        result = await lab.web.merge_capture(project, session)

        assert result["success"] is True
        assert result["added"] == 2

    async def test_endpoint_keys_select_a_subset(self, lab):
        project = lab.make_project()
        session = lab.write_session("s1", [_ep("pets"), _ep("orders")])

        result = await lab.web.merge_capture(
            project, session, endpoint_keys=[f"GET|{HOST}|/api/orders"])

        assert result["added"] == 1
        assert [e["path"] for e in load_registry(project)["endpoints"]] == ["/api/orders"]

    async def test_endpoint_key_host_may_carry_a_port(self, lab):
        """`new_session_id` 会把 host 的 `:` 换成 `_`，但 endpoint 的 host 带端口是常态。"""
        project = lab.make_project()
        host_with_port = "oa.example.com:8443"
        session = lab.write_session("s1", [_ep("pets", host=host_with_port),
                                           _ep("orders")])

        result = await lab.web.merge_capture(
            project, session, endpoint_keys=[f"GET|{host_with_port}|/api/pets"])

        assert result["added"] == 1
        assert load_registry(project)["endpoints"][0]["host"] == host_with_port

    async def test_merge_into_missing_project_is_reported_not_crashed(self, lab):
        session = lab.write_session("s1", [_ep("pets")])
        result = await lab.web.merge_capture(str(lab.tmp_path / "nope"), session)

        assert result["success"] is False
        assert "project.json" in result["error"]


class TestAuthChangeIsDisclosedInPlainLanguage:
    """S13：鉴权变化必须**用用户看得懂的话**报出来，而且不能把「混用」当成变化。

    修复前「这一轮一条 Authorization 都没再抓到」是静默的：合并后生成物不再发
    Authorization，Bearer 站点的工具全部 401，而任何输出里都看不到发生过这件事。
    """

    def _write_capture_analysis(self, lab, session_id: str, host_info: dict) -> str:
        directory = lab.sessions / session_id
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "analysis.json").write_text(json.dumps(
            {"endpoints": [_ep("pets")],
             "auth_metadata": {"auth_schemes": {HOST: host_info}}},
            ensure_ascii=False), encoding="utf-8")
        return session_id

    async def _merged_project(self, lab) -> str:
        project = lab.make_project()
        lab.write_session("s1", [_ep("pets")])
        assert (await lab.web.merge_capture(project, "s1"))["success"] is True
        return project

    async def test_downgrade_is_refused_with_a_readable_message(self, lab):
        project = await self._merged_project(lab)
        session = self._write_capture_analysis(
            lab, "s2", {"scheme": None, "cookie_names": ["JSESSIONID"]})

        result = await lab.web.merge_capture(project, session)

        assert result["success"] is False
        assert result["error"] == "auth_scheme_changed"
        # 面向非技术用户：不出现 scheme / registry 这类词，并给出下一步怎么做。
        assert "登录方式" in result["message"]
        assert "allow_auth_change=true" in result["message"]

    async def test_mixed_methods_on_one_host_do_not_block_and_are_explained(self, lab):
        project = await self._merged_project(lab)
        session = self._write_capture_analysis(
            lab, "s2", {"scheme": "cookie", "schemes": ["cookie", "Bearer"],
                        "cookie_names": ["JSESSIONID"]})

        result = await lab.web.merge_capture(project, session)

        assert result["success"] is True
        assert result["auth_conflicts"]
        assert "不需要" in result["auth_conflicts_hint"]

    async def test_diff_capture_always_exposes_both_auth_keys(self, lab):
        """两个键**常驻**：消费方可以无条件读，不必先判键在不在。"""
        project = await self._merged_project(lab)
        session = self._write_capture_analysis(
            lab, "s2", {"scheme": "cookie", "cookie_names": ["JSESSIONID"]})

        report = await lab.web.diff_capture(project, session)

        assert report["auth_changes"] == []
        assert report["auth_changes_hint"] == ""
        assert report["auth_conflicts"] == []
        assert report["auth_conflicts_hint"] == ""


class TestMergeCaptureDisclosesWhatItSkipped:
    """S29：默认合并只并入「会被生成的」端点 —— 这是**安全**的默认，但必须说出来。

    使用者（和 Agent）默认只读合并结果。若结果只给一个 added 数字，他无从知道
    「这次抓到的某几条根本没进 registry」——那正是「事后才发现少了端点」的来源。
    因此 `not_merged` / `not_merged_hint` **常驻**：无事可报时是空列表 / 空串。
    """

    async def test_default_merge_skips_ungeneratable_and_lists_them(self, lab):
        project = lab.make_project()
        session = lab.write_session("s1", [
            _ep("pets", endpoint_id="ep_001"),
            _ep("track", endpoint_id="ep_002", noise=True),
            _ep("page.aspx", endpoint_id="ep_003", non_json_response=True),
            _ep("report.csv", endpoint_id="ep_004", non_json_response=True,
                file_response=True),
        ])

        result = await lab.web.merge_capture(project, session)

        # 只并入了「会被生成的」：普通端点 + 被豁免的文件下载端点
        assert result["success"] is True
        assert result["added"] == 2
        paths = {e["path"] for e in load_registry(project)["endpoints"]}
        assert paths == {"/api/pets", "/api/report.csv"}
        # 没并进来的，逐条给出衔接键 + 原因 + 下一步
        assert [item["endpoint_id"] for item in result["not_merged"]] == ["ep_002", "ep_003"]
        assert {item["reason"] for item in result["not_merged"]} == {"noise", "non_json_response"}
        assert "include_endpoint_ids" in result["not_merged_hint"]
        assert "/api/track" in result["not_merged_hint"]

    async def test_skipped_list_and_hint_are_always_present(self, lab):
        """键常驻：消费方可以无条件读，不必先判键在不在（风格同 analyze_traffic）。"""
        project = lab.make_project()
        session = lab.write_session("s1", [_ep("pets")])

        result = await lab.web.merge_capture(project, session)

        assert result["not_merged"] == []
        assert result["not_merged_hint"] == ""

    async def test_explicit_selection_does_not_blame_unpicked_endpoints(self, lab):
        """调用方只挑了 /api/pets 时，「没并 /api/orders」是选择，不是跳过。"""
        project = lab.make_project()
        session = lab.write_session("s1", [_ep("pets"), _ep("orders")])

        result = await lab.web.merge_capture(
            project, session, endpoint_keys=[f"GET|{HOST}|/api/pets"])

        assert result["added"] == 1
        assert result["not_merged"] == []

    async def test_seen_but_skipped_endpoint_is_not_marked_unseen(self, lab):
        """S29 的另一半：见过、但本轮被判成噪音的端点，**不能**被标成「本轮未见」。

        修复前：`entries` 是过滤后的，一条仍在抓包里、只是被判成噪音的端点会被写进
        `unseen_since` —— 明明是这次抓到的，却告诉使用者「本轮没见到」，
        方向完全反了（会把人引向「网站把这个接口下线了」）。
        """
        project = lab.make_project()
        first = lab.write_session("s1", [_ep("pets")])
        assert (await lab.web.merge_capture(project, first))["added"] == 1

        second = lab.write_session("s2", [_ep("pets", noise=True), _ep("orders")])
        result = await lab.web.merge_capture(project, second)

        assert result["marked_unseen"] == 0
        stored = {e["path"]: e for e in load_registry(project)["endpoints"]}
        assert stored["/api/pets"]["unseen_since"] is None
        assert [item["path"] for item in result["not_merged"]] == ["/api/pets"]


class TestRegenerateAndExportTools:
    async def test_regenerate_renders_the_merged_endpoints(self, lab):
        project = lab.make_project()
        session = lab.write_session("s1", [_ep("pets")])
        await lab.web.merge_capture(project, session)

        result = await lab.web.regenerate_server(project)

        assert result["success"] is True
        assert "/api/pets" in (Path(project) / "server.py").read_text(encoding="utf-8")

    async def test_regenerate_on_locked_project(self, lab):
        project = lab.make_project()
        data = json.loads((Path(project) / "project.json").read_text(encoding="utf-8"))
        data["locked"] = True
        (Path(project) / "project.json").write_text(json.dumps(data), encoding="utf-8")

        result = await lab.web.regenerate_server(project)

        assert (result["success"], result["error"]) == (False, "project_locked")

    async def test_export_project_without_registry(self, lab):
        result = await lab.web.export_project(str(lab.tmp_path / "not-a-project"),
                                             str(lab.tmp_path / "dist"))
        assert result["success"] is False
        assert "registry.json" in result["error"]

    async def test_export_ships_a_runnable_user_package(self, lab):
        project = lab.make_project()
        session = lab.write_session("s1", [_ep("pets")])
        await lab.web.merge_capture(project, session)
        await lab.web.regenerate_server(project)

        result = await lab.web.export_project(project, str(lab.tmp_path / "dist"))

        assert result["success"] is True
        assert "server.py" in result["files"] and "registry.json" in result["files"]
        # registry.json 只是给诊断工具读的元数据，用户态里没有改它的代码
        server = (lab.tmp_path / "dist" / "server.py").read_text(encoding="utf-8")
        assert "merge_registry" not in server


class TestToolCallsAreAudited:
    async def test_chain_calls_land_in_the_audit_log(self, lab):
        """写操作要留痕：合并/再生成都经过 @audited，审计日志是事后唯一的凭证。"""
        project = lab.make_project()
        session = lab.write_session("s1", [_ep("pets")])
        await lab.web.merge_capture(project, session)
        await lab.web.regenerate_server(project)

        log = lab.web.settings.audit_path.read_text(encoding="utf-8")
        assert "merge_capture" in log and "regenerate_server" in log

    async def test_audit_log_does_not_leak_credentials(self, lab):
        """审计日志会落盘，凭据绝不能进去（这里以 Cookie 值做代表）。"""
        project = lab.make_project()
        session = lab.write_session("s1", [_ep("pets")])
        await lab.web.merge_capture(project, session)

        log = lab.web.settings.audit_path.read_text(encoding="utf-8")
        assert "JSESSIONID" not in log

    async def test_unwritable_audit_log_does_not_mask_a_successful_result(self, lab,
                                                                        monkeypatch):
        """Fix 4：审计写失败**不能**把成功的工具调用变成失败响应。

        `@audited` 是在工具成功返回**之后**才写日志；此前写失败会把异常抛回装饰器，
        结果被替换成 `{"success": false, "error": "PermissionError: ..."}`，
        真实结果整条丢失（用户重试 → 重复合并）。现在失败不抛，改为挂在结果上。
        """
        blocker = lab.tmp_path / "not-a-dir"
        blocker.write_text("x", encoding="utf-8")   # 占位文件 → 其下建目录必然失败
        monkeypatch.setattr(lab.web.audit, "path", blocker / "audit.log")

        project = lab.make_project()
        session = lab.write_session("s1", [_ep("pets")])
        result = await lab.web.merge_capture(project, session)

        assert result["success"] is True            # 真实结果一个字都没丢
        assert result["added"] == 1
        assert result["audit_log"] == "not_written"
        assert result["audit_log_error"]


class TestUserModeHasNoProjectTools:
    async def test_generated_server_exposes_only_read_only_diagnostics(self, lab):
        """用户态子 MCP 不能带任何项目改写工具（它是分发出去的）。"""
        project = lab.make_project()
        session = lab.write_session("s1", [_ep("pets")])
        await lab.web.merge_capture(project, session)
        await lab.web.regenerate_server(project)

        server = (Path(project) / "server.py").read_text(encoding="utf-8")
        for admin_tool in ("def diff_capture", "def merge_capture", "def regenerate_server",
                           "def export_project"):
            assert admin_tool not in server
        assert "def tool_catalog" in server       # 只读诊断工具在


def _write_minimal_capture(lab, session_id: str, requests: list[dict]) -> str:
    """写一份最小 capture.jsonl（`analyze_traffic` 是从它跑出来的）。"""
    directory = lab.sessions / session_id
    directory.mkdir(parents=True, exist_ok=True)
    lines: list[dict] = []
    for index, item in enumerate(requests):
        request_id = f"r{index}"
        lines.append({"type": "request", "requestId": request_id,
                      "url": item["url"], "method": item.get("method", "GET"),
                      "headers": item.get("headers", {}), "resourceType": "XHR"})
        lines.append({"type": "response", "requestId": request_id, "status": 200,
                      "headers": item.get("response_headers",
                                          {"Content-Type": "application/json"})})
        lines.append({"type": "response_body", "requestId": request_id,
                      "body": item.get("body", "{}"), "size": item.get("size", 2),
                      "body_dropped": item.get("body_dropped", False)})
    (directory / "capture.jsonl").write_text(
        "\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")
    # analyze_traffic 先读 session.json（不存在的会话要报 session_not_found）
    (directory / "session.json").write_text(
        json.dumps({"session_id": session_id, "status": "stopped"}),
        encoding="utf-8")
    return session_id


class TestAnalyzeTrafficDigest:
    """`analyze_traffic` 摘要的契约（F5 / F6）。

    F5：生成阶段会跳过三类端点（噪音 / `not_independently_callable` /
    `non_json_response`）。此前摘要对它们**只字不提**，于是 Agent 在摘要里看到的
    端点到生成时凭空消失，任何地方都没有原因可讲。摘要现在要单独列出「不会被生成
    的端点 + 原因」，同时**保持不变**的既有字段（`endpoint_id / method / host /
    path / auth_required / sample_count / description`）。

    F6：摘要里的 `endpoint_id` 就是 registry 里存的衔接键 —— 中间被过滤/合并掉
    端点不会让后面的键前移。
    """

    def _write_capture(self, lab, session_id: str, requests: list[dict]) -> str:
        """写一份最小 capture.jsonl（analyze_traffic 是从它跑出来的）。"""
        return _write_minimal_capture(lab, session_id, requests)

    ODATA = ("/api/data/v9.0/systemusers(abc)"
             "/Microsoft.Dynamics.CRM.RetrievePrincipalAccess")

    def _mixed_capture(self, lab, session_id: str = "s1") -> str:
        return self._write_capture(lab, session_id, [
            {"url": "https://vortex.data.microsoft.com/collect/v1", "method": "POST"},
            {"url": f"https://{HOST}/api/orders"},
            {"url": f"https://{HOST}{self.ODATA}"},
            {"url": f"https://{HOST}/api/page.aspx", "response_headers": {
                "Content-Type": "text/html"}, "body": "<html>ok</html>"},
        ])

    async def test_digest_keeps_its_existing_fields(self, lab):
        result = await lab.web.analyze_traffic(self._mixed_capture(lab))

        assert all({"endpoint_id", "method", "host", "path", "auth_required",
                    "sample_count", "description"} <= set(item)
                   for item in result["endpoints"])

    async def test_dropped_endpoints_are_reported_with_a_reason(self, lab):
        result = await lab.web.analyze_traffic(self._mixed_capture(lab))

        reasons = {item["path"]: item["reason"] for item in result["not_generated"]}
        assert reasons == {
            "/collect/v1": "noise",
            self.ODATA: "not_independently_callable",
            "/api/page.aspx": "non_json_response",
        }
        # 业务端点不在「不会被生成」名单里
        assert "/api/orders" not in reasons

    async def test_report_stays_compact_and_keeps_the_hand_off_key(self, lab):
        result = await lab.web.analyze_traffic(self._mixed_capture(lab))

        digest_ids = {item["path"]: item["endpoint_id"] for item in result["endpoints"]}
        for item in result["not_generated"]:
            # 只给衔接键 + 路径 + 原因，不塞 schema
            assert set(item) <= {"endpoint_id", "method", "host", "path",
                                 "reason", "reasons", "detail"}
            assert item["endpoint_id"] == digest_ids[item["path"]]

    async def test_baked_defaults_are_listed_by_name_only(self, lab):
        """R1：哪些参数用了抓包取值作默认值，摘要里必须列出来（**只给参数名，不给取值**）。

        使用者要在「分享这个 MCP 给别人」之前检查它们 —— 抓包取值是当时那一次会话的。
        取值本身进摘要等于把抓包数据塞进 LLM 上下文：既噪音又多一个泄漏面。

        **刻意反转的旧断言**：本用例原先钉的是 `== [["page", "count"]]` —— 即
        「`page` / `count` 会被烘成默认值」。按新方针那是**缺陷**：这个端点在
        NITRO 这类 API 上一烘 `count='50'`，调用方就可能拿到不完整的数据还以为
        是全部。现在它们一律不烘（降级为必填），只剩真正良性的 `status`。
        """
        session = self._write_capture(lab, "s1", [
            {"url": f"https://{HOST}/api/orders?page=1&count=50&status=open"},
        ])
        result = await lab.web.analyze_traffic(session)

        baked = result["baked_param_defaults"]
        assert [item["params"] for item in baked] == [["status"]]
        assert baked[0]["endpoint_id"], "必须指名是哪个端点"
        assert "status" in result["baked_param_notice"]
        assert "分享" in result["baked_param_notice"], "措辞要面向使用者"
        # 切换类参数**不再**出现在「分享前请检查」的名单里（它们根本没被烘）
        assert "page" not in result["baked_param_notice"]
        assert "count" not in result["baked_param_notice"]
        # 取值绝不出现（`open` 是被烘进生成物的取值；摘要里只给参数名）
        assert '"1"' not in json.dumps(result["baked_param_defaults"])
        assert "50" not in result["baked_param_notice"]
        assert "50" not in json.dumps(result["baked_param_defaults"])
        assert "open" not in json.dumps(result["baked_param_defaults"])

    async def test_baked_keys_are_always_present(self, lab):
        """无话可说时是空列表 / 空串（消费方可无条件读，风格同 needs_more_samples）。"""
        session = self._write_capture(lab, "s1", [{"url": f"https://{HOST}/api/plain"}])
        result = await lab.web.analyze_traffic(session)

        assert result["baked_param_defaults"] == []
        assert result["baked_param_notice"] == ""

    async def test_needs_more_samples_names_only_the_thin_endpoints(self, lab):
        """证据不足的端点必须**点名**，Agent 不用翻 analysis.json 就知道该让用户重做什么。"""
        session = self._write_capture(lab, "s1", [
            # 两个**不同**请求（query 不同）→ 证据足够，不该出现在清单里
            {"url": f"https://{HOST}/api/orders?page=1"},
            {"url": f"https://{HOST}/api/orders?page=2"},
            # 只有一个（不同）请求 → 任何参数都分类不了，必须点名
            {"url": f"https://{HOST}/api/thin"},
        ])
        result = await lab.web.analyze_traffic(session)

        digest_ids = {item["path"]: item["endpoint_id"] for item in result["endpoints"]}
        assert [item["path"] for item in result["needs_more_samples"]] == ["/api/thin"]
        entry = result["needs_more_samples"][0]
        # 衔接键与摘要 / registry 用的是同一个
        assert entry["endpoint_id"] == digest_ids["/api/thin"]
        # 精简：只有衔接键 + 位置 + 不同请求数，无 schema / 样本值 / 请求体
        assert set(entry) == {"endpoint_id", "method", "host", "path",
                              "distinct_request_count"}
        assert entry["distinct_request_count"] == 1
        # 聚合计数与逐端点清单口径一致
        assert result["stats"]["insufficient_samples"] == 1

    async def test_needs_more_samples_is_empty_list_when_all_have_evidence(self, lab):
        """无话可说时给**空列表**（不是缺键），消费方可以无条件读它。"""
        session = self._write_capture(lab, "s1", [
            {"url": f"https://{HOST}/api/orders?page=1"},
            {"url": f"https://{HOST}/api/orders?page=2"},
        ])
        result = await lab.web.analyze_traffic(session)

        assert result["needs_more_samples"] == []
        assert result["stats"]["insufficient_samples"] == 0

    async def test_review_suggested_is_flagged_but_is_not_a_drop_reason(self, lab):
        """待复核不是「不会生成」：只挂在端点自己身上。"""
        session = self._write_capture(lab, "s1", [
            {"url": f"https://{HOST}/api/heavy", "size": 2 * 1024 * 1024},
        ])
        result = await lab.web.analyze_traffic(session)

        assert result["endpoints"][0]["review_suggested"] is True
        assert result["not_generated"] == []

    async def test_digest_endpoint_id_is_the_key_stored_in_the_registry(self, lab):
        """F6 端到端：摘要给的键 == registry 里存的键（噪声不会把后面的键顶前一位）。"""
        session = self._write_capture(lab, "s1", [
            {"url": "https://vortex.data.microsoft.com/collect/v1", "method": "POST"},
            {"url": f"https://{HOST}/api/orders"},
        ])
        digest = await lab.web.analyze_traffic(session)
        digest_ids = {item["path"]: item["endpoint_id"] for item in digest["endpoints"]}
        assert digest_ids["/api/orders"] == "ep_002"        # 噪声端点占住 ep_001
        assert digest["not_generated"][0]["endpoint_id"] == "ep_001"

        project = lab.make_project()
        await lab.web.merge_capture(project, session)

        stored = {e["path"]: e["endpoint_id"] for e in load_registry(project)["endpoints"]}
        assert stored == {"/api/orders": "ep_002"}

    # ---- S19：待复核要**解释为什么**，不能只给一个裸布尔 ---------------------- #
    async def test_review_suggested_carries_a_plain_language_reason(self, lab):
        """非技术使用者看到 `review_suggested: true` 会问「所以呢」——必须给出人话。"""
        session = self._write_capture(lab, "s1", [
            {"url": f"https://{HOST}/api/heavy", "size": 2 * 1024 * 1024},
        ])
        result = await lab.web.analyze_traffic(session)

        entry = result["endpoints"][0]
        assert entry["review_suggested"] is True
        hint = entry["review_suggested_hint"]
        assert "体积" in hint and ("确认" in hint or "人工" in hint)
        # 仍然只标记、不丢弃（阈值不得变成静默丢弃）
        assert result["not_generated"] == []

    # ---- S20：响应体被整条丢弃必须在摘要里看得见 ---------------------------- #
    async def test_dropped_response_body_is_visible_and_actionable(self, lab):
        """响应超限被丢弃后，端点没有响应结构；摘要必须说清 + 给出可行动的补救。"""
        session = self._write_capture(lab, "s1", [
            {"url": f"https://{HOST}/api/big", "size": 5_000_000,
             "body": None, "body_dropped": True},
        ])
        result = await lab.web.analyze_traffic(session)

        assert result["endpoints"][0]["response_body_dropped"] is True
        assert result["stats"]["response_body_dropped"] == 1
        assert result["dropped_response_bodies"] == 1
        hint = result["dropped_response_bodies_hint"]
        # S24：提示必须指向 Agent **做得到**的下一步 —— start_capture 的那个参数，
        # 而不是让使用者去设环境变量（他做不到，也不需要做）。
        assert "上限" in hint and "start_capture" in hint
        assert "response_limit_bytes" in hint
        assert "WEB_API_EXTRACTOR_RESPONSE_LIMIT" not in hint
        # 是「提示怎么补救」，不是「把大响应塞进上下文」
        assert len(json.dumps(result)) < 20000

    async def test_no_dropped_bodies_is_zero_and_empty(self, lab):
        session = self._write_capture(lab, "s1", [{"url": f"https://{HOST}/api/plain"}])
        result = await lab.web.analyze_traffic(session)

        assert result["dropped_response_bodies"] == 0
        assert result["dropped_response_bodies_hint"] == ""
        assert result["endpoints"][0].get("response_body_dropped") is None

    # ---- S23：摘要膨胀时有损收敛，但省略多少、去哪查必须写清楚 --------------- #
    async def test_truncation_keys_are_always_present(self, lab):
        session = self._write_capture(lab, "s1", [{"url": f"https://{HOST}/api/plain"}])
        result = await lab.web.analyze_traffic(session)

        assert result["truncated"] == {}
        assert result["truncated_hint"] == ""

    async def test_oversized_summary_is_capped_and_explains_the_loss(self, lab):
        """抓包规模大时摘要必须有界，且写明省略了多少、完整清单在哪里。"""
        web = lab.web
        cap = web.SUMMARY_ENDPOINT_CAP
        requests = [{"url": f"https://{HOST}{_letter_path(i)}"} for i in range(cap + 25)]
        session = self._write_capture(lab, "s1", requests)
        result = await web.analyze_traffic(session)

        assert len(result["endpoints"]) == cap
        assert result["truncated"]["endpoints"] == 25
        assert "25" in result["truncated_hint"]
        # 被省略的部分仍可在落盘文件里查到（且生成不受影响）
        assert result["full_result_path"].endswith("analysis.json")
        full = json.loads(Path(result["full_result_path"]).read_text(encoding="utf-8"))
        assert len(full["endpoints"]) == cap + 25
        assert "endpoint_ids" in result["truncated_hint"] or "生成" in result["truncated_hint"]

    async def test_baked_notice_covers_params_even_when_the_detail_list_is_capped(self, lab):
        """S23：明细列表截断后，「分享前请检查」那句仍要覆盖**全部**被烘参数。

        否则使用者会以为「检查完列出的那些就够了」—— 那正是截断本身要避免的静默丢失。

        取值刻意**不用** `on` / `yes` 这类开关记号：那类参数现在一律不烘
        （见 TestSwitchParamsAreNeverBaked），本用例要考的是**截断**，不是闸门。
        """
        web = lab.web
        cap = web.SUMMARY_SIDE_LIST_CAP
        count = cap + 5
        requests = [{"url": f"https://{HOST}{_letter_path(i)}?pfx{i}=abc"}
                    for i in range(count)]
        session = self._write_capture(lab, "s1", requests)
        result = await web.analyze_traffic(session)

        assert len(result["baked_param_defaults"]) == cap    # 明细被截断
        assert result["truncated"]["baked_param_defaults"] == 5
        assert f"pfx{count - 1}" in result["baked_param_notice"]   # 被截掉那条的参数仍在告警


class TestSwitchParamEndToEnd:
    """真路径：真实抓包 → analyzer → registry → 生成物签名。

    单测层面（`test_generator_robustness`）已经钉住闸门，这里补的是**证据确实从
    分析器一路传到生成器**：`switch_risk` 由 `analyzer._annotate_evidence` 写下，
    经 registry 的 `query_param_evidence` 到达 `generator._param_decl`。
    """

    async def test_nitro_style_snapshot_values_never_reach_the_signature(self, lab):
        """NITRO 原案形态：`pageno`（会变）+ `count=yes` / `pagesize=25`（固定）。

        修复前生成的是
        `list_vserver(pageno: int, count: str = 'yes', pagesize: int = 25)`——
        `count='yes'` 让接口只返回 `__count`，调用方据此告诉用户「设备上没有对象」。
        修复后这三个快照值一个都不进签名，但**必填与否分两档**：

        * `pageno` 每次取值都不同（`variable`）→ 必填；
        * `count` / `pagesize` 名字像开关，可抓包里两次都带**同一个**值 ——
          没有「带 / 不带」的对照，`detect_behaviour_switch` 只能返回 `None`，
          于是只落到**名字档** → **可选、无默认值**（`| None = None`）。

        后者正是本轮分级要的收口：不传 `count` 时请求里**根本不会出现**这个键，
        服务端按自己的默认行为回（NITRO 下就是返回完整列表）—— 比逼调用方猜一个值好。
        docstring 里仍用非技术话术说明「取值会改变返回内容」。
        """
        session = _write_minimal_capture(lab, "s1", [
            {"url": f"https://{HOST}/api/lbvserver?pageno=1&count=yes&pagesize=25"},
            {"url": f"https://{HOST}/api/lbvserver?pageno=2&count=yes&pagesize=25"},
        ])
        await lab.web.analyze_traffic(session)
        project = lab.make_project()
        assert (await lab.web.merge_capture(project, session))["success"] is True
        await lab.web.regenerate_server(project)

        src = (Path(project) / "server.py").read_text(encoding="utf-8")
        # 工具名由路径推导，别写死：按「哪一段工具代码里出现了这条路径」定位。
        tools = [block for block in src.split("@mcp.tool()")
                 if '"/api/lbvserver"' in block]
        assert len(tools) == 1, f"没找到 /api/lbvserver 的工具（找到 {len(tools)} 个）"
        signature = tools[0].split("async def ")[1].split(") ->")[0].split("(", 1)[1]
        doc = tools[0].split('"""')[1]

        assert "count: str = 'yes'" not in src        # 快照值不再烘
        assert "pagesize: int = 25" not in src
        for ident, py_type in (("count", "str"), ("pagesize", "int")):
            # 仍在签名里（没被凭空丢弃）、可选无默认值（不是烘死的默认值、也不是必填）
            assert re.search(
                rf"\b{ident}: {py_type} \| None = None(?:,|$)", signature), signature
        assert "pageno: int" in signature             # variable → 必填（旧行为，保持）
        assert "取值会改变返回内容" in doc
        assert "不填时服务端会用它自己的默认值" in doc
        compile(src, "server.py", "exec")


class TestUpdateEndpointProvenance:
    """F7：`update_endpoint` 改过的描述必须打上「人写的」标记，之后 merge 不再覆盖它。"""

    async def test_user_edited_description_survives_later_merges(self, lab):
        project = lab.make_project()
        session = lab.write_session("s1", [_ep("pets", endpoint_id="ep_001",
                                               description="抓包描述")])

        updated = await lab.web.update_endpoint(session, "ep_001", description="我手写的描述")
        assert updated["description"] == "我手写的描述"
        assert updated["description_source"] == "user"

        await lab.web.merge_capture(project, session)
        assert load_registry(project)["endpoints"][0]["description"] == "我手写的描述"

        later = lab.write_session("s2", [_ep("pets", endpoint_id="ep_001",
                                             description="后来抓到的文本")])
        await lab.web.merge_capture(project, later)
        stored = load_registry(project)["endpoints"][0]
        assert stored["description"] == "我手写的描述"
        assert stored["description_source"] == "user"

    async def test_notes_stay_independent_of_description(self, lab):
        project = lab.make_project()
        session = lab.write_session("s1", [_ep("pets", endpoint_id="ep_001")])
        await lab.web.update_endpoint(session, "ep_001", notes="人工备注")
        await lab.web.merge_capture(project, session)

        stored = load_registry(project)["endpoints"][0]
        assert stored["notes"] == "人工备注"
        assert stored["description"] is None

    async def test_param_provenance_is_recorded_and_survives_merge(self, lab):
        """规则 5：逐参数记录「来源 + 影响」，并随 registry 落盘。

        记录后 merge 不得抹掉（用户写的溯源优先于抓包），生成器再从 registry 读出
        写进工具文档字符串。
        """
        project = lab.make_project()
        session = lab.write_session("s1", [_ep("pets", endpoint_id="ep_001")])
        updated = await lab.web.update_endpoint(
            session, "ep_001",
            param_provenance={"page": {"origin": "前端翻页控件",
                                       "impact": "决定返回第几页"}})
        assert updated["param_provenance"]["page"]["origin"] == "前端翻页控件"

        await lab.web.merge_capture(project, session)
        stored = load_registry(project)["endpoints"][0]
        assert stored["param_provenance"]["page"]["impact"] == "决定返回第几页"

    async def test_param_provenance_is_merged_per_parameter(self, lab):
        """分多次补充不会互相覆盖：第二次只补另一个参数，第一个仍在。"""
        session = lab.write_session("s1", [_ep("pets", endpoint_id="ep_001")])
        await lab.web.update_endpoint(
            session, "ep_001", param_provenance={"page": {"origin": "翻页"}})
        updated = await lab.web.update_endpoint(
            session, "ep_001", param_provenance={"status": {"origin": "筛选器"}})

        assert updated["param_provenance"]["page"]["origin"] == "翻页"
        assert updated["param_provenance"]["status"]["origin"] == "筛选器"


# --------------------------------------------------------------------------- #
# Defect A / D / E：会话身份、失败启动的收尾、确认旁证
#
# `start_capture` 一律用 monkeypatch 顶掉真正的启动（本机有一个长期运行的
# 服务进程，且测试绝不能真的拉起 Playwright / 开浏览器）。
# --------------------------------------------------------------------------- #
LOGIN_URL = "https://oa.example.com/login/login.jsp"

# `sanitize_path_segment("my session")` 的输出，并且它自身又是合法 id
# （再净化一次不变）——正是「两个键、一个目录」那组别名。
ALIAS_RAW_ID = "my session"
ALIAS_CANONICAL_ID = "my_session_b405683d"


@pytest.fixture()
def capture_registry(web):
    """`capture_sessions` 是模块级全局：每个用例前后清空，避免用例之间互相污染。"""
    sessions = web.capture_sessions
    saved = dict(sessions)
    sessions.clear()
    try:
        yield sessions
    finally:
        sessions.clear()
        sessions.update(saved)


@pytest.fixture()
def no_browser(web, monkeypatch):
    """顶掉真正的启动：等价于「浏览器已打开」，但一个进程都不拉。"""
    async def _noop(capture) -> None:
        capture.status = "capturing" if capture.auth_ready else "authenticating"

    monkeypatch.setattr(web, "_start_capture", _noop)
    return _noop


class TestSessionIdentityIsTheOnDiskDirectory:
    """Defect A：`capture_sessions` 的键必须与磁盘目录是同一个东西。

    修复前键是**调用方原样给的** id，而目录名经过 `sanitize_path_segment`：
    `start_capture("my session")` 与 `start_capture("my_session_b405683d")` 是两个
    不同的键（重复检查与 max_sessions 双双放行），却是**同一个目录**——两个
    CaptureSession 往同一份 capture.jsonl / session.json 追加，analyze_traffic 对
    任一 id 都会把两份流量一起分析。反过来，走 capture_sessions 的工具
    （stop_capture / resume_capture / confirm_login_ready / request_capture_confirm_dialog）
    对净化后的拼写一律回 capture_session_not_found——而走 store 的工具
    （analyze_traffic / update_endpoint / generate_mcp_server / diff_capture）却认得。
    """

    async def test_the_alias_gets_rejected_instead_of_sharing_one_directory(
            self, lab, capture_registry, no_browser):
        first = await lab.web.start_capture(LOGIN_URL, session_id=ALIAS_RAW_ID)
        assert first["session_id"] == ALIAS_CANONICAL_ID

        second = await lab.web.start_capture(LOGIN_URL, session_id=ALIAS_CANONICAL_ID)

        assert second["success"] is False
        assert second["error"] == "session_already_exists"
        assert second["session_id"] == ALIAS_CANONICAL_ID
        assert len(capture_registry) == 1, "别名不得再开一个会话"
        # 只有一个目录：不可能有两个 CaptureSession 往同一份 capture.jsonl 追加
        assert [d.name for d in lab.sessions.iterdir()] == [ALIAS_CANONICAL_ID]

    async def test_metadata_keeps_the_requested_spelling_for_audit(
            self, lab, capture_registry, no_browser):
        await lab.web.start_capture(LOGIN_URL, session_id=ALIAS_RAW_ID)

        metadata = json.loads(
            (lab.sessions / ALIAS_CANONICAL_ID / "session.json").read_text(encoding="utf-8"))

        assert metadata["session_id"] == ALIAS_CANONICAL_ID
        assert metadata["requested_session_id"] == ALIAS_RAW_ID

    async def test_the_reported_id_is_accepted_by_the_session_bound_tools(
            self, lab, capture_registry, no_browser):
        """摘要里报出去的 id，必须能被 stop_capture / get_capture_status 认下来。"""
        await lab.web.start_capture(LOGIN_URL, session_id=ALIAS_RAW_ID)

        status = await lab.web.get_capture_status(ALIAS_RAW_ID)
        assert status["session_id"] == ALIAS_CANONICAL_ID

        digest = await lab.web.analyze_traffic(ALIAS_RAW_ID)
        assert digest["session_id"] == ALIAS_CANONICAL_ID
        # 摘要里的 id 与 full_result_path 的目录名必须是同一个字符串
        assert Path(digest["full_result_path"]).parent.name == ALIAS_CANONICAL_ID
        assert Path(digest["full_result_path"]).exists()

        stopped = await lab.web.stop_capture(digest["session_id"])
        assert stopped["status"] == "stopped", "修复前这里回 capture_session_not_found"
        assert stopped["session_id"] == ALIAS_CANONICAL_ID

    async def test_default_session_id_is_a_no_op_through_the_sanitiser(
            self, lab, capture_registry, no_browser):
        """默认路径不受影响：`new_session_id()` 过净化器是 byte-identical 的。"""
        started = await lab.web.start_capture(LOGIN_URL)
        session_id = started["session_id"]

        assert lab.web.store.session_path(session_id).name == session_id
        assert (lab.sessions / session_id / "session.json").exists()

        digest = await lab.web.analyze_traffic(session_id)
        assert digest["session_id"] == session_id
        assert (await lab.web.stop_capture(session_id))["status"] == "stopped"


class TestInstanceOwnershipIsRecordedAtTheToolLayer:
    """S8：会话的 owner 与实例身份必须在**工具层**就写下去。

    库层（storage）判得再准，只要 `start_capture` 忘了写 owner，别的实例就会把
    这个**正在抓取**的会话当旧版孤儿回收；实例身份文件缺失则连「谁还活着」都
    无从判定。故这里从工具入口验一遍。
    """

    async def test_start_capture_records_the_owning_instance(
            self, lab, capture_registry, no_browser):
        started = await lab.web.start_capture(LOGIN_URL, session_id=ALIAS_CANONICAL_ID)

        owner = json.loads(
            (lab.sessions / started["session_id"] / "owner.json").read_text(encoding="utf-8"))
        assert owner["instance_token"] == lab.web.instance.token
        assert owner["pid"] == lab.web.instance.pid
        assert owner["start_fingerprint"] == lab.web.instance.start_fingerprint
        # 本进程的实例身份 + 心跳（数据根下 instances/<token>.json）也要在
        assert lab.web.instance.path.exists()
        heartbeat = json.loads(lab.web.instance.path.read_text(encoding="utf-8"))
        assert heartbeat["heartbeat_at"]

    async def test_a_peer_instance_does_not_recover_this_live_session(
            self, lab, capture_registry, no_browser):
        """另一个实例（同一个数据根）启动时，本进程正在抓的会话必须原样不动。"""
        started = await lab.web.start_capture(LOGIN_URL, session_id=ALIAS_CANONICAL_ID)
        peer = lab.web.InstanceRegistry(lab.web.instance.instances_dir)
        peer.register()

        assert lab.web.store.recover_orphans(peer) == []

        meta = lab.web.store.read_metadata(started["session_id"])
        assert meta["status"] == "authenticating"
        assert "recovered" not in meta


class TestIdlePauseIsVisibleThroughTools:
    """S22：空闲暂停这件事必须在 Agent 能看到的摘要里可见（原因 + 数据还在）。"""

    async def test_get_capture_status_reports_reason_and_data(self, lab, capture_registry):
        capture = lab.web.CaptureSession(
            ALIAS_CANONICAL_ID, LOGIN_URL, lab.web.store, 1024, 300, None)
        capture.status = "capturing"
        capture.directory.mkdir(parents=True, exist_ok=True)
        capture.event_queue.put_nowait({"type": "request", "requestId": "r1"})
        capture_registry[ALIAS_CANONICAL_ID] = capture

        await capture.pause("idle_timeout")
        status = await lab.web.get_capture_status(ALIAS_CANONICAL_ID)

        assert status["status"] == "paused"
        assert status["pause_reason"] == "idle_timeout"
        assert status["captured_bytes"] > 0, "已抓到的数据没落盘"
        assert "analyze_traffic" in status["pause_hint"]
        # list_sessions 读磁盘 —— 修复前它仍报 capturing（暂停是静默的）
        listed = await lab.web.list_sessions()
        assert [s["status"] for s in listed["sessions"]] == ["paused"]


class TestActiveSessionLimit:
    """`max_sessions` 的「活的」定义必须与 storage.ACTIVE_STATES 一致。

    等用户登录（authenticating）的会话同样占着一个真浏览器，必须计入上限；
    此前 server.py 自抄了一份少了 authenticating 的字面量，两边一分叉就可以
    无限开浏览器。
    """

    async def test_awaiting_login_sessions_count_toward_the_limit(
            self, lab, capture_registry, no_browser):
        for index in range(lab.web.settings.max_sessions):
            directory = lab.sessions / f"pending-{index}"
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "session.json").write_text(
                json.dumps({"session_id": f"pending-{index}", "status": "authenticating"}),
                encoding="utf-8")

        result = await lab.web.start_capture(LOGIN_URL)

        assert result["success"] is False
        assert result["error"] == "session_limit_reached"
        assert len(result["active_sessions"]) == lab.web.settings.max_sessions


class TestFailedStartLeavesNoZombie:
    """Defect D：`start()` 抛异常时不得留僵尸会话，更不得回「浏览器已打开，请去登录」。

    用户机器上没装 Playwright 浏览器时：每次重试都会先创建 writer / idle / login
    三个后台任务，再在 launch 处抛异常。writer 的唯一出口是 `status == "stopping"`，
    这条路径永远不会走到——它在后台空转一辈子，会话还留在 `capture_sessions` 里被
    当成活的，而 `start_capture` 的返回值仍在叫用户去登录。
    """

    async def test_failure_is_reported_and_everything_is_released(
            self, lab, capture_registry, monkeypatch):
        started: list[Any] = []
        closed: list[bool] = []
        stopped: list[bool] = []

        class _Browser:
            async def close(self) -> None:
                closed.append(True)

        class _Playwright:
            async def stop(self) -> None:
                stopped.append(True)

        async def _half_start(self) -> None:
            # 与 capture.py:start() 一致：后台任务先于浏览器启动被创建
            self.writer_task = asyncio.create_task(asyncio.Event().wait())
            started.append(self)
            self.browser = _Browser()
            self.playwright = _Playwright()
            raise RuntimeError("Executable doesn't exist at C:/ms-playwright/chrome.exe")

        monkeypatch.setattr(lab.web.CaptureSession, "start", _half_start)

        result = await lab.web.start_capture(LOGIN_URL, session_id="s-dead")

        assert result["success"] is False
        assert result["error"] == "capture_start_failed"
        assert "Executable doesn't exist" in result["detail"]
        assert "登录" not in result["message"], "启动失败还叫用户去登录，用户会对着不存在的窗口发呆"
        assert "s-dead" not in capture_registry, "失败的会话不得留在 capture_sessions"
        # (a) 后台任务必须被取消/收掉（writer 否则空转一辈子，每次重试多一份）
        assert started and started[0].writer_task.done()
        # (b) 半启动的浏览器与 node 驱动必须关掉
        assert closed == [True] and stopped == [True]
        metadata = json.loads(
            (lab.sessions / "s-dead" / "session.json").read_text(encoding="utf-8"))
        assert metadata["status"] == "failed"
        assert metadata["stop_reason"] == "startup_failed"
        assert "Executable doesn't exist" in metadata["error"]


class TestConfirmationEvidenceIsAdvisory:
    """Defect E：确认动作只做**旁证记录 + 提示**，绝不改变既有字段与成功语义。"""

    async def test_confirm_login_without_any_request_still_succeeds(
            self, lab, capture_registry):
        lab.web.login_manager.sessions["login_quiet"] = LoginSession(
            "login_quiet", LOGIN_URL, 300, lab.tmp_path)

        result = await lab.web.confirm_login("login_quiet")

        assert result["success"] is True and result["status"] == "completed"
        assert result["confirmation_evidence"] == "none"
        assert result["confirmation_warning"] == "no_confirmation_request_recorded"
        # 既有字段一个都不能少、也不能被顶掉
        assert result["warning"] == "no_credential_evidence"
        assert result["login_session_id"] == "login_quiet"

    async def test_open_browser_login_is_what_records_the_request(
            self, lab, capture_registry, monkeypatch):
        async def _fake_open(self, url, timeout_seconds=300):
            return {"login_session_id": "login_open", "status": "waiting", "message": "…"}

        monkeypatch.setattr(lab.web.LoginManager, "open", _fake_open)
        lab.web.login_manager.sessions["login_open"] = LoginSession(
            "login_open", LOGIN_URL, 300, lab.tmp_path)

        await lab.web.open_browser_login(LOGIN_URL)
        result = await lab.web.confirm_login("login_open")

        assert result["confirmation_evidence"] == "requested"
        assert "confirmation_warning" not in result

    async def test_start_capture_counts_as_asking_the_user(
            self, lab, capture_registry, no_browser):
        """`start_capture` 的提示语就是「请用户确认已登录」，等价于一次确认请求。"""
        started = await lab.web.start_capture(LOGIN_URL, session_id="s-conf")

        confirmed = await lab.web.confirm_login_ready(started["session_id"])

        assert confirmed["success"] is True
        assert confirmed["confirmation_evidence"] == "requested"
        assert "confirmation_warning" not in confirmed

    async def test_confirm_login_ready_warns_when_nothing_ever_asked_the_user(
            self, lab, capture_registry):
        lab.web.capture_sessions["s-quiet"] = lab.web.CaptureSession(
            "s-quiet", LOGIN_URL, lab.web.store, 1024, 999)

        result = await lab.web.confirm_login_ready("s-quiet")

        assert result["success"] is True, "只是提示，不得拒绝"
        assert result["status"] == "capturing"
        assert result["confirmation_evidence"] == "none"
        assert result["confirmation_warning"] == "no_confirmation_request_recorded"


class TestGenerateToolIncludeEndpointIds:
    """Feature（工具层）：`generate_mcp_server(include_endpoint_ids=[...])`。

    用户复核完 `not_generated` 之后此前**无路可走**：`endpoint_ids` 对会被跳过的端点
    fail-loud（这是对的），而内部那个 `include_noise` 又没暴露到工具层。
    """

    async def test_tool_layer_accepts_the_opt_in(self, lab):
        session = lab.write_session("s1", [
            _ep("track", endpoint_id="ep_001", noise=True),
            _ep("orders", endpoint_id="ep_002"),
        ])
        out = lab.tmp_path / "out"

        result = await lab.web.generate_mcp_server(
            session, str(out), include_endpoint_ids=["ep_001"])

        assert result["endpoint_count"] == 2
        assert result["forced_include"] == ["ep_001"]
        server = (out / "server.py").read_text(encoding="utf-8")
        assert "/api/track" in server and "/api/orders" in server
        readme = (out / "README.md").read_text(encoding="utf-8")
        assert "显式点名" in readme and "get_api_track" in readme

    async def test_without_the_opt_in_a_skipped_id_still_fails_loud(self, lab):
        session = lab.write_session("s1", [_ep("track", endpoint_id="ep_001", noise=True)])

        result = await lab.web.generate_mcp_server(
            session, str(lab.tmp_path / "out"), endpoint_ids=["ep_001"])

        assert result["success"] is False
        assert "ep_001" in result["error"]

    async def test_generate_tool_still_guards_the_analysis(self, lab):
        """新参数不能把既有的前置检查挤掉（没分析过就生成 = 静默空项目）。

        S28：这道检查与 `diff_capture` / `merge_capture` / `extract_crypto_logic`
        必须是**同一句可行动的话**。此前 `generate_mcp_server` 是四个读 analysis.json
        的工具里唯一没有前置检查的：它把 `FileNotFoundError: [Errno 2] No such file or
        directory: '…\\analysis.json'` 直接回给调用方（中文路径还显示成乱码），
        使用者既看不懂、也不知道下一步该调 `analyze_traffic`。
        """
        result = await lab.web.generate_mcp_server(
            "s-never-analyzed", str(lab.tmp_path / "out"), include_endpoint_ids=["ep_001"])

        assert result["success"] is False
        assert result["error"] == "analysis_not_found"
        assert "analyze_traffic" in result["message"]
        assert "FileNotFoundError" not in result.get("message", "")


class TestGenerateToolOverAnExistingProject:
    """工具层：对已有项目生成**不再失败**，而是自动备份 + 覆盖 + 告知备份路径。

    Agent 若拿到 traceback 只会当成 bug 去重试或放弃；而「拒绝 + 报错」对不懂目录语义的
    使用者等于死路。改成：整份备份到旁边、照常覆盖、把备份路径明确回给调用方。
    不新增工具（工具数仍是 21）。
    """

    async def test_backup_path_is_reported_and_old_data_survives(self, lab):
        session = lab.write_session("s1", [_ep("pets")])
        project = Path(lab.make_project())
        await lab.web.merge_capture(str(project), session)      # 项目里先真有端点

        result = await lab.web.generate_mcp_server(session, str(project))

        assert result.get("success") is not False
        backup = Path(result["backup_path"])
        assert backup.is_dir()
        assert result["backup_path"] in result["message"]
        # 旧数据在备份里，一个都没丢
        assert len(load_registry(backup)["endpoints"]) == 1
        # 覆盖**真的发生了**：新项目按这次抓包生成
        assert (project / "server.py").exists()

    async def test_a_fresh_output_dir_still_succeeds_without_backup(self, lab):
        """空目录照旧：不产生备份、不生成 message。"""
        session = lab.write_session("s1", [_ep("pets")])
        out = lab.tmp_path / "out"

        result = await lab.web.generate_mcp_server(session, str(out))

        assert result["endpoint_count"] == 1
        assert (out / "registry.json").exists()
        assert "backup_path" not in result


class TestFileResponseThroughTheToolLayer:
    """Fix 1 端到端：CSV 导出端点必须真的被生成（修复前 0 个端点进 registry）。"""

    async def test_csv_endpoint_is_generated_and_flagged(self, lab):
        session = self._csv_session(lab)
        out = lab.tmp_path / "out"
        # 与真实流程一致：先 analyze_traffic（它写出 generate_mcp_server 要读的 analysis.json）
        await lab.web.analyze_traffic(session)

        result = await lab.web.generate_mcp_server(session, str(out))

        assert result["endpoint_count"] == 1
        assert result["file_response"] == ["get_api_report_csv"]
        server = (out / "server.py").read_text(encoding="utf-8")
        compile(server, "server.py", "exec")
        assert "raw=True" in server
        readme = (out / "README.md").read_text(encoding="utf-8")
        assert "[FILE]" in readme and "文件 / 流式响应工具" in readme

    async def test_digest_flags_file_endpoints_and_does_not_drop_them(self, lab):
        """摘要里也要能认出文件端点，且它**不是** not_generated。"""
        session = self._csv_session(lab)

        digest = await lab.web.analyze_traffic(session)

        entry = next(e for e in digest["endpoints"] if e["path"] == "/api/report.csv")
        assert entry["file_response"] is True
        assert digest["not_generated"] == []
        assert digest["stats"]["file_response"] == 1

    def _csv_session(self, lab) -> str:
        # analyze_traffic / generate_mcp_server 都从 capture.jsonl 出发（各自会先跑分析）
        directory = lab.sessions / "csv1"
        directory.mkdir(parents=True, exist_ok=True)
        events = [
            {"type": "request", "requestId": "r1",
             "url": f"https://{HOST}/api/report.csv", "method": "GET",
             "headers": {}, "resourceType": "XHR"},
            {"type": "response", "requestId": "r1", "status": 200,
             "headers": {"Content-Type": "text/csv"}},
            {"type": "response_body", "requestId": "r1", "body": "id,name\n1,bob", "size": 13},
        ]
        (directory / "capture.jsonl").write_text(
            "\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
        (directory / "session.json").write_text(
            json.dumps({"session_id": "csv1", "status": "stopped"}), encoding="utf-8")
        return "csv1"


class TestStartCaptureResponseLimit:
    """S24：``start_capture(response_limit_bytes=…)`` —— 抓包时就指定响应体上限。

    背景：响应体超限会被**整条丢弃**，这件事已经报在会话元数据与 `analyze_traffic` 摘要里，
    但改动前提示语把使用者指向一个环境变量 —— 对「服务完全不懂 HTTP、不会用命令行」的用户，
    那是一件他做不到的事。本参数让 **Agent 替用户**「调大上限后重抓一轮」变成一次普通调用。
    这三条守的是：非法值在**调用入口**被挡住、合法值真的贯穿到抓包侧、不传时行为与改动前一致。
    """

    class _FakeCapture:
        """只记录构造参数，不碰浏览器（真起 Playwright/Chromium 不在单测范围内）。"""

        def __init__(self, session_id, url, store, response_limit, idle_timeout,
                     auth_state_path=None, proxy_mode=None,
                     response_limit_explicit=False):
            self.session_id = session_id
            self.status = "capturing" if auth_state_path else "authenticating"
            self.proxy_fallback = None
            self.response_limit = response_limit
            self.response_limit_explicit = response_limit_explicit
            self.started = False
            TestStartCaptureResponseLimit.seen = {
                "response_limit": response_limit,
                "explicit": response_limit_explicit,
                "session_id": session_id,
            }

        async def start(self) -> None:
            self.started = True

    async def test_illegal_value_is_rejected_before_any_side_effect(self, lab, monkeypatch):
        """非法值必须当场报错 —— 不能开浏览器、建会话，也不能等到抓包中途才炸。"""
        from webapi_extractor.config import MAX_RESPONSE_LIMIT_BYTES

        def _boom(*args, **kwargs):        # 真去建抓包会话就说明校验没拦住
            raise AssertionError("非法参数竟然走到了 CaptureSession()")

        monkeypatch.setattr(lab.web, "CaptureSession", _boom)
        for bad in (0, -1, MAX_RESPONSE_LIMIT_BYTES + 1):
            result = await lab.web.start_capture("https://oa.example.com/",
                                                 response_limit_bytes=bad)

            assert result["success"] is False
            assert result["error"] == "invalid_response_limit_bytes"
            assert str(bad) in result["message"], "错误句里要点出收到的坏值"
            assert str(MAX_RESPONSE_LIMIT_BYTES) in result["message"], \
                "错误句里要写出合法范围的上限"
            assert str(MAX_RESPONSE_LIMIT_BYTES) in str(result["limit_range"])
        assert lab.web.capture_sessions == {}
        assert list(lab.sessions.iterdir()) == [], "非法参数不该留下任何会话目录"

    async def test_value_is_carried_into_the_capture_session(self, lab, monkeypatch):
        """参数要真的贯穿到抓包侧（CaptureSession 的 response_limit），不只是改签名。"""
        monkeypatch.setattr(lab.web, "CaptureSession", self._FakeCapture)
        result = await lab.web.start_capture(
            "https://oa.example.com/", session_id="s-limit",
            auth_state_path=str(lab.tmp_path / "state.json"),
            response_limit_bytes=4 * 1024 * 1024)

        assert result["session_id"] == "s-limit"
        assert self.seen["response_limit"] == 4 * 1024 * 1024
        assert self.seen["explicit"] is True
        # 会话元数据里也要留下这次真正生效的上限（analyze_traffic 是无状态的，只能靠它）
        meta = lab.web.store.read_metadata("s-limit")
        assert meta["response_limit_bytes"] == 4 * 1024 * 1024
        lab.web.capture_sessions.pop("s-limit", None)

    async def test_not_passing_it_changes_nothing(self, lab, monkeypatch):
        """不传时沿用 Settings 的值，且元数据形状与改动前一字不差。"""
        monkeypatch.setattr(lab.web, "CaptureSession", self._FakeCapture)
        await lab.web.start_capture("https://oa.example.com/", session_id="s-default",
                                    auth_state_path=str(lab.tmp_path / "state.json"))

        assert self.seen["response_limit"] == lab.web.settings.response_body_limit
        assert self.seen["explicit"] is False
        meta = lab.web.store.read_metadata("s-default")
        assert "response_limit_bytes" not in meta
        lab.web.capture_sessions.pop("s-default", None)

    async def test_analyze_hint_quotes_the_limit_of_that_session(self, lab):
        """显式调大过上限的会话，提示语里的「当前上限」必须是那次真正生效的值。"""
        directory = lab.sessions / "s-big"
        directory.mkdir(parents=True, exist_ok=True)
        events = [
            {"type": "request", "requestId": "r1", "url": f"https://{HOST}/api/big",
             "method": "GET", "headers": {}, "resourceType": "XHR"},
            {"type": "response", "requestId": "r1", "status": 200,
             "headers": {"Content-Type": "application/json"}},
            {"type": "response_body", "requestId": "r1", "body": None, "size": 5_000_000,
             "body_dropped": True},
        ]
        (directory / "capture.jsonl").write_text(
            "\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
        (directory / "session.json").write_text(json.dumps(
            {"session_id": "s-big", "status": "stopped",
             "response_limit_bytes": 768 * 1024}), encoding="utf-8")

        result = await lab.web.analyze_traffic("s-big")

        hint = result["dropped_response_bodies_hint"]
        assert "768 KB" in hint, f"提示语没有引用该会话生效的上限：{hint}"
