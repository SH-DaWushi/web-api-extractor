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

import importlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

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
