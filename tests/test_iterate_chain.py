# -*- coding: utf-8 -*-
"""迭代链路（diff / merge / regenerate / export / locked / 用户态隔离）。

`runbook/06-iterate.md` 把这条链路写成 Agent 的固定动作：再抓一轮 → `diff_capture`
→ `merge_capture` → `regenerate_server` → `export_project`。此前它**只有实现、没有验证**，
于是下面这些承诺从来没被复查过：

- merge **只增不减** —— 旧端点只标 `unseen_since`，永不自动删除；
- 鉴权 scheme 漂移**默认拒绝合并**，防止鉴权方式被静默改写；
- `locked` 项目拒绝 merge 与 regenerate；
- regenerate **不碰 `registry.json`**（registry 归 merge 管，渲染只管代码）；
- 用户态分发包**物理上不含**任何 registry 写入 / 再生成代码。

「说了但没测」正是最该上测试的地方 —— 这五条一旦破，表现为**数据丢失或权限被改写**，
且不会立刻报错。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from webapi_extractor.generator import generate, regenerate, render_server
from webapi_extractor.project import (
    diff_hosts,
    diff_registry,
    export_user_package,
    init_project,
    load_project,
    load_registry,
    merge_registry,
    save_registry,
    session_to_registry_entries,
)

HOST = "oa.example.com"


# --------------------------------------------------------------------------- #
# 夹具：analysis.json 的形状与 analyzer 的产出保持一致
# --------------------------------------------------------------------------- #
def _ep(name: str, **extra) -> dict:
    endpoint = {"method": "GET", "host": HOST, "path": f"/api/{name}", "query_params": {},
                "sample_count": 2, "request_schema": None, "response_schema": None,
                "auth_required": False, "description": None, "notes": None,
                "url": f"https://{HOST}/api/{name}"}
    endpoint.update(extra)
    return endpoint


def _hosts(scheme: str | None = "cookie") -> dict:
    return {HOST: {"scheme": scheme, "cookie_names": ["JSESSIONID"]}}


def _analysis(endpoints: list[dict], scheme: str | None = "cookie") -> dict:
    return {"endpoints": endpoints, "auth_metadata": {"auth_schemes": _hosts(scheme)}}


def _entries(endpoints: list[dict], session_id: str = "s1", scheme: str | None = "cookie", **kwargs):
    """→ (entries, hosts)。注意返回的是元组，别整只塞给 diff_registry。"""
    return session_to_registry_entries(_analysis(endpoints, scheme), session_id, **kwargs)


def _registry(endpoints: list[dict], version: int = 1) -> dict:
    return {"site_name": "portal", "registry_version": version, "hosts": _hosts(),
            "endpoints": endpoints, "auth_login": None}


def _stored(**updates) -> dict:
    """写成磁盘上的端点条目（merge 之后的样子）。"""
    entry = {"tool_name": "get_api_pets", "method": "GET", "host": HOST, "path": "/api/pets",
             "query_params": {}, "request_body_params": {}, "status": "active",
             "unseen_since": None, "source_sessions": ["s0"]}
    entry.update(updates)
    return entry


def _project(tmp_path: Path, registry: dict | None = None, name: str = "proj") -> Path:
    directory = tmp_path / name
    init_project(directory, "portal")
    if registry is not None:
        save_registry(directory, registry)
    return directory


def _session_dir(tmp_path: Path, analysis: dict, sid: str = "20260925_120000_oa.example.com_a1b2") -> Path:
    directory = tmp_path / "sessions" / sid
    directory.mkdir(parents=True)
    (directory / "analysis.json").write_text(
        json.dumps(analysis, ensure_ascii=False), encoding="utf-8")
    return directory


# --------------------------------------------------------------------------- #
# diff：只读，且只报三类差异
# --------------------------------------------------------------------------- #
class TestDiffRegistry:
    def test_new_endpoint_reported(self):
        report = diff_registry(_registry([_stored()]), _entries([_ep("pets"), _ep("orders")])[0])
        assert [e["path"] for e in report["new_endpoints"]] == ["/api/orders"]
        assert report["counts"]["new"] == 1

    def test_known_endpoint_not_reported_as_new(self):
        report = diff_registry(_registry([_stored()]), _entries([_ep("pets")])[0])
        assert report["counts"] == {"new": 0, "changed": 0, "unseen": 0}

    def test_query_param_nameset_change_reported(self):
        registry = _registry([_stored(query_params={"page": ["1"]})])
        report = diff_registry(registry, _entries([_ep("pets", query_params={"page": ["1"], "size": ["20"]})])[0])
        assert report["changed_endpoints"] == [{"tool_name": "get_api_pets", "change": "query_params",
                                                "registry": ["page"], "capture": ["page", "size"]}]

    def test_value_change_not_reported(self):
        """文档写明「不报值变化」：参数值随抓包变是常态，报出来只会是噪音。"""
        registry = _registry([_stored(query_params={"page": ["1"]})])
        report = diff_registry(registry, _entries([_ep("pets", query_params={"page": ["7"]})])[0])
        assert report["changed_endpoints"] == []

    def test_unseen_endpoint_listed_and_still_in_registry(self):
        registry = _registry([_stored(), _stored(tool_name="get_api_orders", path="/api/orders")])
        report = diff_registry(registry, _entries([_ep("pets")])[0])
        assert [e["path"] for e in report["unseen_endpoints"]] == ["/api/orders"]
        # 只读：registry 对象本身不被改动
        assert len(registry["endpoints"]) == 2
        assert registry["endpoints"][1]["unseen_since"] is None

    def test_deprecated_endpoint_not_counted_unseen(self):
        """已废弃的端点不再报「本轮未见」，否则报告里会永远挂着一批噪音。"""
        registry = _registry([_stored(), _stored(tool_name="get_api_old", path="/api/old",
                                                  status="deprecated")])
        report = diff_registry(registry, _entries([_ep("pets")])[0])
        assert report["unseen_endpoints"] == []


class TestDiffHosts:
    def test_scheme_drift_detected(self):
        changes = diff_hosts({HOST: {"scheme": "cookie"}}, {HOST: {"scheme": "bearer"}})
        assert changes == [{"host": HOST, "registry_scheme": "cookie", "capture_scheme": "bearer"}]

    def test_same_scheme_is_not_drift(self):
        assert diff_hosts({HOST: {"scheme": "cookie"}}, {HOST: {"scheme": "cookie"}}) == []

    def test_new_host_is_not_drift(self):
        """新主机只是新增，不是漂移 —— 否则每次扩站点都会被判成鉴权变化而拒绝合并。"""
        assert diff_hosts({}, {HOST: {"scheme": "bearer"}}) == []

    def test_unknown_scheme_on_either_side_is_not_drift(self):
        """scheme 可能是 None（纯 Cookie 站点靠 cookie_names 鉴权），不能拿它当漂移。"""
        assert diff_hosts({HOST: {"scheme": None}}, {HOST: {"scheme": "cookie"}}) == []
        assert diff_hosts({HOST: {"scheme": "cookie"}}, {HOST: {"scheme": None}}) == []


# --------------------------------------------------------------------------- #
# merge：只增不减
# --------------------------------------------------------------------------- #
class TestMergeAdditive:
    def test_version_bumps_and_endpoint_added(self, tmp_path):
        project = _project(tmp_path)
        entries, hosts = _entries([_ep("pets")])
        result = merge_registry(project, entries, hosts, "s1")

        assert result["success"] is True
        assert result["registry_version"] == 1
        assert (result["added"], result["updated"]) == (1, 0)
        stored = load_registry(project)
        assert stored["endpoints"][0]["source_sessions"] == ["s1"]
        # project.json 与 registry.json 的版本号必须同步，否则 diff 会拿旧版本判断
        assert load_project(project)["registry_version"] == 1

    def test_provenance_note_written(self, tmp_path):
        project = _project(tmp_path)
        entries, hosts = _entries([_ep("pets")])
        merge_registry(project, entries, hosts, "sess-42")
        note = json.loads((project / "captures" / "sess-42.json").read_text(encoding="utf-8"))
        assert note["version"] == 1 and note["added"] == 1 and note["session_id"] == "sess-42"

    def test_absent_endpoint_marked_unseen_not_deleted(self, tmp_path):
        project = _project(tmp_path, _registry([_stored()]))
        entries, hosts = _entries([_ep("orders")])
        result = merge_registry(project, entries, hosts, "s2")

        assert result["marked_unseen"] == 1
        stored = {e["path"]: e for e in load_registry(project)["endpoints"]}
        assert set(stored) == {"/api/pets", "/api/orders"}      # 没有删除
        # 标的是本次合并产生的版本号（本次由 v1 升到 v2）
        assert stored["/api/pets"]["unseen_since"] == result["registry_version"] == 2

    def test_unseen_marker_cleared_when_endpoint_reappears(self, tmp_path):
        project = _project(tmp_path, _registry([_stored(unseen_since=1)], version=2))
        entries, hosts = _entries([_ep("pets")])
        result = merge_registry(project, entries, hosts, "s3")

        assert load_registry(project)["endpoints"][0]["unseen_since"] is None
        assert result["updated"] == 1
        assert "s3" in load_registry(project)["endpoints"][0]["source_sessions"]

    def test_query_param_merge_is_additive(self, tmp_path):
        """旧默认值不能被新抓包覆盖 —— 新抓包里那个参数可能只是没填。"""
        project = _project(tmp_path, _registry([_stored(query_params={"page": ["1"]})]))
        entries, hosts = _entries([_ep("pets", query_params={"page": ["9"], "size": ["20"]})])
        merge_registry(project, entries, hosts, "s2")

        params = load_registry(project)["endpoints"][0]["query_params"]
        assert params["page"] == ["1"]
        assert params["size"] == ["20"]

    def test_body_param_merge_is_additive(self, tmp_path):
        project = _project(tmp_path, _registry([_stored(request_body_params={"a": ["1"]})]))
        entries, hosts = _entries([_ep("pets", request_body_params={"a": ["2"], "b": ["3"]})])
        merge_registry(project, entries, hosts, "s2")

        params = load_registry(project)["endpoints"][0]["request_body_params"]
        assert params == {"a": ["1"], "b": ["3"]}

    def test_endpoint_keys_limit_what_is_merged(self, tmp_path):
        """runbook 承诺可只合并选定端点（用户在 diff 报告上挑）。"""
        project = _project(tmp_path)
        entries, hosts = _entries([_ep("pets"), _ep("orders")])
        result = merge_registry(project, entries, hosts, "s1",
                               endpoint_keys=[("GET", HOST, "/api/orders")])

        assert result["added"] == 1
        assert [e["path"] for e in load_registry(project)["endpoints"]] == ["/api/orders"]

    def test_deprecated_endpoint_is_not_marked_unseen(self, tmp_path):
        """废弃端点在 registry 里留着，但不再被标记 unseen（否则报告里永远挂着它）。"""
        project = _project(tmp_path, _registry([_stored(status="deprecated"),
                                                _stored(tool_name="get_api_live", path="/api/live")]))
        entries, hosts = _entries([_ep("live")])
        result = merge_registry(project, entries, hosts, "s2")

        assert result["marked_unseen"] == 0
        stored = {e["path"]: e for e in load_registry(project)["endpoints"]}
        assert stored["/api/pets"]["unseen_since"] is None       # 已废弃：不标
        assert stored["/api/live"]["unseen_since"] is None       # 本轮见过：不标


class TestMergeRefusesAuthSchemeDrift:
    """鉴权方式被静默改写 = 生成的子 MCP 突然全 401，故默认硬停。"""

    def _drift_project(self, tmp_path: Path) -> Path:
        return _project(tmp_path, _registry([_stored()]))

    def test_refused_by_default(self, tmp_path):
        project = self._drift_project(tmp_path)
        entries, hosts = _entries([_ep("pets")], scheme="bearer")
        result = merge_registry(project, entries, hosts, "s2")

        assert result["success"] is False
        assert result["error"] == "auth_scheme_changed"
        assert result["auth_changes"] == [{"host": HOST, "registry_scheme": "cookie",
                                           "capture_scheme": "bearer"}]

    def test_nothing_is_written_when_refused(self, tmp_path):
        project = self._drift_project(tmp_path)
        before = (project / "registry.json").read_text(encoding="utf-8")
        entries, hosts = _entries([_ep("pets")], scheme="bearer")
        merge_registry(project, entries, hosts, "s2")

        assert (project / "registry.json").read_text(encoding="utf-8") == before
        assert load_project(project)["registry_version"] == 0
        assert not list((project / "captures").iterdir())     # 连 provenance 都不留

    def test_merged_when_explicitly_allowed(self, tmp_path):
        project = self._drift_project(tmp_path)
        entries, hosts = _entries([_ep("pets")], scheme="bearer")
        result = merge_registry(project, entries, hosts, "s2", allow_auth_change=True)

        assert result["success"] is True
        assert load_registry(project)["hosts"][HOST]["scheme"] == "bearer"


# --------------------------------------------------------------------------- #
# locked：拒绝一切改写动作
# --------------------------------------------------------------------------- #
class TestLockedProject:
    def _locked(self, tmp_path: Path) -> Path:
        project = _project(tmp_path, _registry([_stored()]))
        data = load_project(project)
        data["locked"] = True
        (project / "project.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return project

    def test_merge_refused(self, tmp_path):
        project = self._locked(tmp_path)
        entries, hosts = _entries([_ep("orders")])
        result = merge_registry(project, entries, hosts, "s2")

        assert (result["success"], result["error"]) == (False, "project_locked")
        assert len(load_registry(project)["endpoints"]) == 1

    def test_regenerate_refused(self, tmp_path):
        project = self._locked(tmp_path)
        result = regenerate(project)

        assert (result["success"], result["error"]) == (False, "project_locked")
        assert not (project / "server.py").exists()

    def test_unlocking_restores_both_actions(self, tmp_path):
        """解锁是人工改 project.json（没有 unlock 工具）—— 改完必须真的能继续干活。"""
        project = self._locked(tmp_path)
        data = load_project(project)
        data["locked"] = False
        (project / "project.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

        entries, hosts = _entries([_ep("pets")])
        assert merge_registry(project, entries, hosts, "s2")["success"] is True
        assert regenerate(project)["success"] is True


# --------------------------------------------------------------------------- #
# regenerate：只管重渲代码，registry 归 merge
# --------------------------------------------------------------------------- #
class TestRegenerate:
    def _with_endpoint(self, tmp_path: Path) -> Path:
        """合并一个端点并渲染出文件 —— merge 只写 registry，server.py 归 regenerate。"""
        project = _project(tmp_path)
        entries, hosts = _entries([_ep("pets")])
        merge_registry(project, entries, hosts, "s1")
        regenerate(project)
        return project

    def test_renders_without_touching_registry(self, tmp_path):
        project = self._with_endpoint(tmp_path)
        before = (project / "registry.json").read_text(encoding="utf-8")
        result = regenerate(project)

        assert result["success"] is True
        assert "registry.json" not in result["files"]        # 渲染产物里没有它
        assert (project / "registry.json").read_text(encoding="utf-8") == before
        assert load_registry(project)["registry_version"] == 1

    def test_previous_render_kept_as_bak(self, tmp_path):
        project = self._with_endpoint(tmp_path)
        first = (project / "server.py").read_text(encoding="utf-8")
        (project / "server.py").write_text("# 人工改坏了\n", encoding="utf-8")

        regenerate(project)

        assert (project / "server.py.bak").read_text(encoding="utf-8") == "# 人工改坏了\n"
        assert (project / "server.py").read_text(encoding="utf-8") == first

    def test_renders_endpoints_from_registry(self, tmp_path):
        project = self._with_endpoint(tmp_path)
        server = (project / "server.py").read_text(encoding="utf-8")
        assert "/api/pets" in server
        # 新增端点后重渲，新端点出现、旧端点仍在（只增不减）
        entries, hosts = _entries([_ep("orders")])
        merge_registry(project, entries, hosts, "s2")
        regenerate(project)
        server = (project / "server.py").read_text(encoding="utf-8")
        assert "/api/pets" in server and "/api/orders" in server

    def test_endpoint_count_skips_deprecated(self, tmp_path):
        project = self._with_endpoint(tmp_path)
        registry = load_registry(project)
        registry["endpoints"].append(_stored(tool_name="get_api_old", path="/api/old",
                                             status="deprecated"))
        save_registry(project, registry)

        assert regenerate(project)["endpoint_count"] == 1


# --------------------------------------------------------------------------- #
# generate：analysis.json → 全新项目
# --------------------------------------------------------------------------- #
class TestGenerate:
    def test_creates_project_and_renders(self, tmp_path):
        session = _session_dir(tmp_path, _analysis([_ep("pets"), _ep("orders")]))
        result = generate(session, tmp_path / "out")

        assert result["registry_version"] == 1
        assert result["endpoint_count"] == 2
        assert set(result["files"]) >= {"server.py", "README.md", "requirements.txt",
                                        ".env.example", "smoke_test.py"}
        assert (tmp_path / "out" / "registry.json").exists()

    def test_requires_auth_setup_flag(self, tmp_path):
        session = _session_dir(tmp_path, _analysis([_ep("pets", auth_required=True)]))
        assert generate(session, tmp_path / "out")["requires_auth_setup"] is True

    def test_noise_endpoints_are_not_generated(self, tmp_path):
        session = _session_dir(tmp_path, _analysis([_ep("pets"), _ep("track", noise=True)]))
        result = generate(session, tmp_path / "out")

        assert result["endpoint_count"] == 1
        assert "/api/track" not in (tmp_path / "out" / "server.py").read_text(encoding="utf-8")

    def test_endpoint_ids_select_subset(self, tmp_path):
        session = _session_dir(tmp_path, _analysis([_ep("pets"), _ep("orders")]))
        result = generate(session, tmp_path / "out", endpoint_ids=["ep_002"])

        assert result["endpoint_count"] == 1
        server = (tmp_path / "out" / "server.py").read_text(encoding="utf-8")
        assert "/api/orders" in server and "/api/pets" not in server

    def test_unknown_endpoint_id_raises(self, tmp_path):
        session = _session_dir(tmp_path, _analysis([_ep("pets")]))
        with pytest.raises(ValueError, match="ep_999"):
            generate(session, tmp_path / "out", endpoint_ids=["ep_999"])


# --------------------------------------------------------------------------- #
# export：用户态分发包不含写入能力
# --------------------------------------------------------------------------- #
class TestExportUserPackage:
    def _generated(self, tmp_path: Path) -> Path:
        session = _session_dir(tmp_path, _analysis([_ep("pets")]))
        out = tmp_path / "out"
        generate(session, out)
        return out

    def test_copies_the_runtime_subset(self, tmp_path):
        out = self._generated(tmp_path)
        result = export_user_package(out, tmp_path / "dist")

        assert result["success"] is True
        assert set(result["files"]) == {"server.py", "requirements.txt", ".env.example",
                                        "README.md", "smoke_test.py", "registry.json",
                                        "project.json"}

    def test_missing_files_are_skipped_not_faked(self, tmp_path):
        out = self._generated(tmp_path)
        (out / "smoke_test.py").unlink()
        result = export_user_package(out, tmp_path / "dist")

        assert "smoke_test.py" not in result["files"]
        assert not (tmp_path / "dist" / "smoke_test.py").exists()

    def test_captures_and_baks_are_not_shipped(self, tmp_path):
        out = self._generated(tmp_path)
        (out / "server.py.bak").write_text("旧渲染", encoding="utf-8")
        export_user_package(out, tmp_path / "dist")

        shipped = {p.name for p in (tmp_path / "dist").iterdir()}
        assert "server.py.bak" not in shipped
        assert "captures" not in shipped

    def test_user_package_has_no_registry_write_capability(self, tmp_path):
        """这是整条链路的用户态隔离承诺：分发包里没有任何能改 registry 的代码。"""
        out = self._generated(tmp_path)
        export_user_package(out, tmp_path / "dist")
        server = (tmp_path / "dist" / "server.py").read_text(encoding="utf-8")

        # 判据是「有没有这个能力的**调用**」，不是文中出现这个词：
        # 生成物的 docstring 本就写着一句「cannot modify or regenerate itself」。
        for capability in ("save_registry", "merge_registry", "diff_registry", "init_project",
                           "set_auth_login", "session_to_registry_entries", "regenerate",
                           "render_server", "export_user_package"):
            assert not re.search(rf"\b{capability}\s*\(", server), \
                f"用户态 server.py 调用了 {capability}（不该有 registry 写入能力）"
        # 不依赖本包（注释里提到包名没关系，真正的判据是没有 import）
        assert not re.search(r"^\s*(?:import|from)\s+webapi_extractor", server, re.M)

        # registry.json 只被诊断工具读取（tool_catalog），不得被写入
        assert '"registry.json"' in server
        assert not re.search(r"registry_path\s*\.\s*write", server)
        assert not re.search(r"registry\.json[\"']\s*,\s*[\"']w", server)


class TestRenderedFilesAreComplete:
    """渲染产物本身的自洽性：缺一个文件，生成的项目就跑不起来。"""

    FILES = {"server.py", "requirements.txt", ".env.example", ".gitignore",
             "README.md", "smoke_test.py"}

    def test_render_server_returns_exact_file_set(self):
        assert set(render_server(_registry([_stored()]))) == self.FILES

    def test_rendered_server_is_a_standalone_deployment_unit(self):
        """server.py 是独立部署单元：只依赖 httpx/fastmcp/stdlib，不 import 本包。"""
        server = render_server(_registry([_stored()]))["server.py"]
        assert not re.search(r"^\s*(?:import|from)\s+webapi_extractor", server, re.M)
        assert re.search(r"^import httpx$", server, re.M)
