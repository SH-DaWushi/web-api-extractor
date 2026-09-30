# -*- coding: utf-8 -*-
"""迭代链路（diff / merge / regenerate / export / locked / 用户态隔离）。

`runbook/06-iterate.md` 把这条链路写成 Agent 的固定动作：再抓一轮 → `diff_capture`
→ `merge_capture` → `regenerate_server` → `export_project`。此前它**只有实现、没有验证**，
于是下面这些承诺从来没被复查过：

- merge **只增不减** —— 旧端点只标 `unseen_since`，永不自动删除；
- 鉴权 scheme 漂移**默认拒绝合并**，防止鉴权方式被静默改写；
- `locked` 项目拒绝 merge 与 regenerate；
- regenerate **不碰 `registry.json`**（registry 归 merge 管，渲染只管代码）；
- 用户态分发包**物理上不含**任何 registry 写入 / 再生成代码；
- `generate()` 指向已有项目时**先自动备份再覆盖**：一次性生成走 `init_project`，会把已有
  registry 重建（端点 + 用户写的元数据一起没），所以覆盖前必须把整个目录复制到旁边 ——
  数据一个不丢，且返回消息里指明备份在哪（不拦、不静默删除）。

「说了但没测」正是最该上测试的地方 —— 这几条一旦破，表现为**数据丢失或权限被改写**，
且不会立刻报错。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from webapi_extractor.analyzer import analyze_capture
from webapi_extractor.generator import _stable_default_value, generate, regenerate, render_server
from webapi_extractor.project import (
    DESCRIPTION_SOURCE_USER,
    diff_hosts,
    diff_registry,
    endpoint_registry_id,
    export_user_package,
    init_project,
    is_conflict_change,
    load_project,
    load_registry,
    match_key,
    merge_registry,
    sanitize_sample_url,
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

    def test_seen_but_filtered_endpoint_is_not_reported_unseen(self):
        """S29：见过、但被跳过规则滤掉的端点不是「未见」。

        `entries` 是过滤后的（默认丢噪音 / 非 JSON），拿它当「见过的全集」会把这次
        明明抓到的端点报成「本轮未见」。调用方（diff_capture）交 analysis 的全部端点键，
        报告就只统计「抓包里根本没有的端点」。
        """
        registry = _registry([_stored(), _stored(tool_name="get_api_track", path="/api/track")])
        analysis = _analysis([_ep("pets"), _ep("track", noise=True)])
        entries, _ = session_to_registry_entries(analysis, "s1")

        without = diff_registry(registry, entries)
        assert [e["path"] for e in without["unseen_endpoints"]] == ["/api/track"]

        with_seen = diff_registry(registry, entries,
                                  seen_keys={match_key(e) for e in analysis["endpoints"]})
        assert with_seen["unseen_endpoints"] == []

    def test_absent_endpoint_still_reported_unseen_with_seen_keys(self):
        """seen_keys 只排除「见过但被滤掉」的，真没出现的照旧报。"""
        registry = _registry([_stored(), _stored(tool_name="get_api_gone", path="/api/gone")])
        analysis = _analysis([_ep("pets")])
        entries, _ = session_to_registry_entries(analysis, "s1")

        report = diff_registry(registry, entries,
                               seen_keys={match_key(e) for e in analysis["endpoints"]})
        assert [e["path"] for e in report["unseen_endpoints"]] == ["/api/gone"]


class TestDiffHosts:
    def test_scheme_drift_detected(self):
        changes = diff_hosts({HOST: {"scheme": "cookie"}}, {HOST: {"scheme": "bearer"}})
        assert changes == [{"host": HOST, "registry_scheme": "cookie", "capture_scheme": "bearer"}]

    def test_same_scheme_is_not_drift(self):
        assert diff_hosts({HOST: {"scheme": "cookie"}}, {HOST: {"scheme": "cookie"}}) == []

    def test_new_host_is_not_drift(self):
        """新主机只是新增，不是漂移 —— 否则每次扩站点都会被判成鉴权变化而拒绝合并。"""
        assert diff_hosts({}, {HOST: {"scheme": "bearer"}}) == []

    def test_learning_a_scheme_is_not_drift(self):
        """原来 scheme 未知、这次认出来了：只是信息变多，不是漂移。"""
        assert diff_hosts({HOST: {"scheme": None}}, {HOST: {"scheme": "cookie"}}) == []

    def test_losing_a_scheme_is_reported_as_downgrade(self):
        """修复前这里是**静默**的：scheme 被悄悄降级成 None，生成物于是不再发
        Authorization，Bearer 站点的工具合并后全部 401，而任何输出里都看不到这件事
        发生过。现在它必须报出来（``capture_scheme=None`` ＝ 这一轮一条 Authorization
        都没再抓到）。
        """
        assert diff_hosts({HOST: {"scheme": "cookie"}},
                          {HOST: {"scheme": None}}) == [
            {"host": HOST, "registry_scheme": "cookie", "capture_scheme": None}]

    def test_mixed_schemes_on_one_host_are_reported_and_not_drift(self):
        """同一域名混用多种方式：要报告（免得以为抓包串了），但它**不是漂移**、不拦合并。

        S13 起生成物按端点各自取用凭据，混用是受支持的形态；`merge_registry` 只对
        `is_conflict_change` 为假的变化硬停。
        """
        capture = {HOST: {"scheme": "Bearer", "schemes": ["Bearer", "Basic"]}}
        changes = diff_hosts({HOST: {"scheme": "Bearer"}}, capture)
        assert changes == [{"host": HOST, "registry_scheme": "Bearer",
                            "capture_scheme": "Bearer",
                            "conflict_schemes": ["Basic", "Bearer"]}]
        assert is_conflict_change(changes[0]) is True


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

    def test_seen_but_skipped_endpoint_is_neither_marked_nor_kept_unseen(self, tmp_path):
        """S29：`seen_keys` 把「见过但被跳过规则滤掉」的端点从两端都修正回来。

        没有它时：`entries` 里没有 /api/pets（本轮被判成噪音）→ 会被标成
        ``unseen_since``；而它明明就在这次抓包里。
        """
        project = _project(tmp_path, _registry([_stored(unseen_since=1)], version=2))
        analysis = _analysis([_ep("pets", noise=True)])
        entries, hosts = session_to_registry_entries(analysis, "s1")
        result = merge_registry(project, entries, hosts, "s3",
                                seen_keys={match_key(e) for e in analysis["endpoints"]})

        stored = {e["path"]: e for e in load_registry(project)["endpoints"]}
        assert result["marked_unseen"] == 0
        assert result["added"] == 0 and result["updated"] == 0
        assert stored["/api/pets"]["unseen_since"] is None      # 见过：旧标记也被清掉
        assert stored["/api/pets"]["status"] == "active"        # 不删、不改状态

    def test_without_seen_keys_the_library_behaviour_is_unchanged(self, tmp_path):
        """缺省（seen_keys=None）时「见过 = entries」：库层的老行为一字不变。"""
        project = _project(tmp_path, _registry([_stored(unseen_since=None)]))
        entries, hosts = _entries([_ep("orders")])
        result = merge_registry(project, entries, hosts, "s2")

        assert result["marked_unseen"] == 1

    def test_query_param_merge_is_additive(self, tmp_path):
        """旧样本值不能被新抓包覆盖 —— 新抓包里那个参数可能只是没填。

        F7 改的是另一半：**新样本要并进来**（此前 `page` 永远只剩第一次的 ["1"]），
        参数名照旧只增不减。
        """
        project = _project(tmp_path, _registry([_stored(query_params={"page": ["1"]})]))
        entries, hosts = _entries([_ep("pets", query_params={"page": ["9"], "size": ["20"]})])
        merge_registry(project, entries, hosts, "s2")

        params = load_registry(project)["endpoints"][0]["query_params"]
        assert params["page"] == ["1", "9"]
        assert params["size"] == ["20"]

    def test_body_param_merge_is_additive(self, tmp_path):
        project = _project(tmp_path, _registry([_stored(request_body_params={"a": ["1"]})]))
        entries, hosts = _entries([_ep("pets", request_body_params={"a": ["2"], "b": ["3"]})])
        merge_registry(project, entries, hosts, "s2")

        params = load_registry(project)["endpoints"][0]["request_body_params"]
        assert params == {"a": ["1", "2"], "b": ["3"]}

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


class TestMergeAccumulatesSamples:
    """F7：合并要**累积**参数样本、更新 `sample_count`。

    修复前合并只把新参数名加进去，已有参数的值列表一动不动、`sample_count` 也不涨：
    「>=2 个样本、且样本值唯一」这条默认值闸门于是被第一次抓包的单个值**永久**满足 ——
    后面几轮抓包明明看到该参数会变，也照样把抓包当时的真实值烘进生成的代码。
    """

    def test_sample_values_accumulate_across_merges(self, tmp_path):
        project = _project(tmp_path, _registry([_stored(query_params={"page": ["1"]})]))
        entries, hosts = _entries([_ep("pets", query_params={"page": ["9"]})])
        merge_registry(project, entries, hosts, "s2")

        assert load_registry(project)["endpoints"][0]["query_params"]["page"] == ["1", "9"]

    def test_repeated_merges_keep_accumulating_without_duplicates(self, tmp_path):
        project = _project(tmp_path, _registry([_stored(query_params={"page": ["1"]})]))
        for session_id, values in (("s2", ["1", "9"]), ("s3", ["9", "10"])):
            entries, hosts = _entries([_ep("pets", query_params={"page": values})])
            merge_registry(project, entries, hosts, session_id)

        assert load_registry(project)["endpoints"][0]["query_params"]["page"] == ["1", "9", "10"]

    def test_sample_count_grows_with_each_merge(self, tmp_path):
        project = _project(tmp_path, _registry([_stored(sample_count=2,
                                                        query_params={"page": ["1"]})]))
        entries, hosts = _entries([_ep("pets", sample_count=3, query_params={"page": ["1"]})])
        merge_registry(project, entries, hosts, "s2")

        assert load_registry(project)["endpoints"][0]["sample_count"] == 5

    def test_a_value_shown_to_vary_stops_being_a_default(self, tmp_path):
        """这就是 F7 要保住的后果：累积到两个不同值后，闸门不再放行默认值。

        本次重做后「闸门」看的是参数证据（`query_param_evidence`），不再看
        `sample_count`。这里模拟两轮抓包各自给出的分类：第一轮只有一个值 →
        `fixed`，第二轮看到第二个值 → `variable`；合并后必须仍是 `variable`，
        于是默认值被挡下。
        """
        project = _project(tmp_path, _registry([_stored(
            sample_count=2, query_params={"page": ["1"]},
            query_param_evidence={"page": {
                "class": "fixed", "values": ["1"], "present_in": 2, "requests": 2,
                "switch_risk": False, "behaviour_switch": None, "verified": True}})]))
        entries, hosts = _entries([_ep(
            "pets", query_params={"page": ["9"]},
            query_param_evidence={"page": {
                "class": "variable", "values": ["9"], "present_in": 2, "requests": 2,
                "switch_risk": False, "behaviour_switch": None, "verified": True}})])
        merge_registry(project, entries, hosts, "s2")

        stored = load_registry(project)["endpoints"][0]
        assert stored["query_params"]["page"] == ["1", "9"]
        merged = (stored.get("query_param_evidence") or {}).get("page") or {}
        assert merged.get("class") == "variable", "合并后应判为 variable"
        assert _stable_default_value("page", stored["query_params"]["page"],
                                     merged) is None


class TestMergeKeepsUserEditedDescription:
    """F7：用户手写的 `description` 不能被下一轮 merge 静默抹掉。

    来源标记（`description_source`）跟着条目一起写进 registry.json，重新加载后仍然
    有效 —— 用户改过的描述跨 merge、跨进程、跨重渲都活着。
    """

    def test_capture_description_is_refreshed_while_not_user_edited(self, tmp_path):
        project = _project(tmp_path, _registry([_stored(description="旧抓包描述",
                                                        description_source="capture")]))
        entries, hosts = _entries([_ep("pets", description="新抓包描述")])
        merge_registry(project, entries, hosts, "s2")

        stored = load_registry(project)["endpoints"][0]
        assert stored["description"] == "新抓包描述"
        assert stored["description_source"] == "capture"

    def test_legacy_entry_without_marker_is_still_refreshable(self, tmp_path):
        """老 registry 没有来源标记 → 视为抓包来源（否则升级后描述永远冻住）。"""
        project = _project(tmp_path, _registry([_stored(description="旧抓包描述")]))
        entries, hosts = _entries([_ep("pets", description="新抓包描述")])
        merge_registry(project, entries, hosts, "s2")

        assert load_registry(project)["endpoints"][0]["description"] == "新抓包描述"

    def test_user_edited_description_survives_merge(self, tmp_path):
        project = _project(tmp_path, _registry([_stored(description="我手写的描述",
                                                        description_source="user")]))
        entries, hosts = _entries([_ep("pets", description="抓包文本")])
        merge_registry(project, entries, hosts, "s2")

        stored = load_registry(project)["endpoints"][0]
        assert stored["description"] == "我手写的描述"
        assert stored["description_source"] == DESCRIPTION_SOURCE_USER

    def test_marker_survives_many_merges(self, tmp_path):
        project = _project(tmp_path, _registry([_stored(description="我手写的描述",
                                                        description_source="user")]))
        for index in range(3):
            entries, hosts = _entries([_ep("pets", description=f"第 {index} 轮抓包文本")])
            merge_registry(project, entries, hosts, f"s{index}")

        stored = load_registry(project)["endpoints"][0]
        assert stored["description"] == "我手写的描述"
        assert stored["description_source"] == DESCRIPTION_SOURCE_USER

    def test_user_description_arriving_from_the_capture_marks_the_entry(self, tmp_path):
        """update_endpoint 把 description_source=user 写进 analysis.json，
        合并后 registry 条目必须带上该标记，之后的抓包不再覆盖它。"""
        project = _project(tmp_path, _registry([_stored(description="旧抓包描述")]))
        entries, hosts = _entries([_ep("pets", description="用户写的",
                                       description_source=DESCRIPTION_SOURCE_USER)])
        merge_registry(project, entries, hosts, "s2")
        assert load_registry(project)["endpoints"][0]["description"] == "用户写的"

        later, hosts = _entries([_ep("pets", description="后来的抓包文本")])
        merge_registry(project, later, hosts, "s3")

        stored = load_registry(project)["endpoints"][0]
        assert stored["description"] == "用户写的"
        assert stored["description_source"] == DESCRIPTION_SOURCE_USER

    def test_notes_are_untouched_by_merge(self, tmp_path):
        """notes 是人工备注，语义不变：merge 不读也不写。"""
        project = _project(tmp_path, _registry([_stored(notes="人工备注")]))
        entries, hosts = _entries([_ep("pets", notes=None)])
        merge_registry(project, entries, hosts, "s2")

        assert load_registry(project)["endpoints"][0]["notes"] == "人工备注"


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

    def test_export_style_endpoints_are_generated(self, tmp_path):
        """F5 端到端：带扩展名的导出端点（此前被误判成 OData 绑定函数）真的会被生成。"""
        session = _session_dir(tmp_path, _analysis([
            _ep("report", path="/api/export/report.pdf", endpoint_id="ep_001"),
        ]))
        result = generate(session, tmp_path / "out")

        assert result["endpoint_count"] == 1
        assert "/api/export/report.pdf" in (tmp_path / "out" / "server.py").read_text(encoding="utf-8")

    def test_endpoint_ids_select_subset(self, tmp_path):
        """F6：衔接键按端点**自带**的 `endpoint_id` 解释，不是「过滤后列表里的第几个」。

        修复前 `generate` 用 `ep_{i+1:03d}` 按位置重编号：噪声端点排在最前面时被过滤掉，
        位置整体前移，摘要里给出的 `ep_002`（= orders）会被解析到另一个路径——同一个键
        在分析与生成两处指向不同端点。这里让噪声端点占住 `ep_001`，正是复现条件。
        """
        session = _session_dir(tmp_path, _analysis([
            _ep("track", endpoint_id="ep_001", noise=True),
            _ep("orders", endpoint_id="ep_002"),
        ]))
        result = generate(session, tmp_path / "out", endpoint_ids=["ep_002"])

        assert result["endpoint_count"] == 1
        server = (tmp_path / "out" / "server.py").read_text(encoding="utf-8")
        assert "/api/orders" in server, (
            "ep_002 是 analyze_traffic 摘要给出的衔接键，必须解析到 orders；"
            "若此处失败且 generate() 仍按位置编号 endpoint_ids，说明「按 registry 的 "
            "endpoint_id 解析」这一处还没落地")
        assert "/api/track" not in server

    def test_endpoint_ids_of_a_dropped_endpoint_are_rejected(self, tmp_path):
        """被生成阶段跳过的端点（这里是噪音）不是可生成目标：宁可报「不认识」，
        也不能把它**误解析成别的端点**。"""
        session = _session_dir(tmp_path, _analysis([
            _ep("track", endpoint_id="ep_001", noise=True),
            _ep("orders", endpoint_id="ep_002"),
        ]))
        with pytest.raises(ValueError, match="ep_001"):
            generate(session, tmp_path / "out", endpoint_ids=["ep_001"])

    def test_unknown_endpoint_id_raises(self, tmp_path):
        session = _session_dir(tmp_path, _analysis([_ep("pets", endpoint_id="ep_001")]))
        with pytest.raises(ValueError, match="ep_999"):
            generate(session, tmp_path / "out", endpoint_ids=["ep_999"])

    def test_legacy_analysis_without_endpoint_id_still_works(self, tmp_path):
        """F6 向后兼容：改动之前写下的 analysis.json 没有 endpoint_id，
        用 (method, host, path) 派生一个确定性衔接键，老项目照常生成。"""
        analysis = _analysis([_ep("pets")])
        session = _session_dir(tmp_path, analysis)
        assert generate(session, tmp_path / "out")["endpoint_count"] == 1

        stored = load_registry(tmp_path / "out")["endpoints"][0]
        expected = endpoint_registry_id(analysis["endpoints"][0])
        assert stored["endpoint_id"] == expected

    def test_legacy_digest_key_and_generate_agree_with_a_noise_endpoint(self, tmp_path):
        """F6 核心断言：**旧** analysis.json（没有 endpoint_id）上，摘要给出的键与
        `generate` 认的键必须是同一个。

        派生算法只有一份（`project.endpoint_registry_id`）：摘要用它，写进 registry 条目
        也用它。噪声端点排在前面时按位置编号会让两者错位——本用例把这种错位钉死：
        派生键必须唯一，且拿它当 `endpoint_ids` 必须选中**对应那条**路径。
        """
        analysis = _analysis([_ep("track", noise=True), _ep("orders")])
        session = _session_dir(tmp_path, analysis)
        track_id = endpoint_registry_id(analysis["endpoints"][0])
        orders_id = endpoint_registry_id(analysis["endpoints"][1])
        assert track_id != orders_id, "确定性派生也必须唯一，否则两个端点会共用一个衔接键"

        result = generate(session, tmp_path / "out", endpoint_ids=[orders_id])

        assert result["endpoint_count"] == 1
        server = (tmp_path / "out" / "server.py").read_text(encoding="utf-8")
        assert "/api/orders" in server and "/api/track" not in server
        # 被丢弃的那个端点的键是同一个派生算法算出来的，但它不是可生成目标：
        # 宁可报「不认识」，也不能把它解析成别的端点。
        with pytest.raises(ValueError, match=track_id):
            generate(session, tmp_path / "out2", endpoint_ids=[track_id])


class TestGenerateBacksUpAnExistingProject:
    """一次性生成**不再拦**已有项目：先整份备份到旁边，再照常覆盖，并告知备份路径。

    修复前（第一版）是「拒绝 + 报错」，对不懂这套目录语义的使用者等于死路：他判断不出
    「已有项目」意味着什么，也不知道该换哪个目录。现在的性质是「**绝不静默删除**」：
    覆盖前把整个目录复制成可读的兄弟目录 `<dir>.bak-<时间戳>`，旧数据一个不丢。
    """

    def _project_with_user_metadata(self, tmp_path: Path) -> Path:
        """一个「已经被人养过」的项目：端点 + 用户写的描述/备注/逐参数溯源。"""
        return _project(tmp_path, _registry([_stored(
            description="人写的描述", notes="人工备注",
            param_provenance={"page": {"origin": "分页", "impact": "只影响列表页"}},
        )]))

    def test_backup_exists_and_holds_the_old_project(self, tmp_path):
        session = _session_dir(tmp_path, _analysis([_ep("pets")]))
        project = self._project_with_user_metadata(tmp_path)

        result = generate(session, project)

        backup = Path(result["backup_path"])
        assert backup.is_dir()
        assert backup.parent == project.parent, "备份要放在旁边（兄弟目录），便于人找"
        assert backup.name.startswith(project.name + ".bak-"), backup.name
        # 旧数据**逐字段**还在备份里：版本、端点、用户写的元数据
        old = load_registry(backup)
        assert old["registry_version"] == 1
        assert [e["path"] for e in old["endpoints"]] == ["/api/pets"]
        assert old["endpoints"][0]["description"] == "人写的描述"
        assert old["endpoints"][0]["notes"] == "人工备注"
        assert old["endpoints"][0]["param_provenance"]["page"]["origin"] == "分页"

    def test_the_message_names_the_backup_path(self, tmp_path):
        session = _session_dir(tmp_path, _analysis([_ep("pets")]))
        project = self._project_with_user_metadata(tmp_path)

        result = generate(session, project)

        message = result["message"]
        assert str(project) in message or project.name in message
        assert result["backup_path"] in message, "必须告诉使用者备份在哪"
        assert "备份" in message
        # 覆盖是**真的发生了**：新项目按新抓包生成（这里 1 个端点）
        assert result["endpoint_count"] == 1

    def test_a_project_json_alone_is_also_backed_up(self, tmp_path):
        """只剩 project.json（registry.json 被人工删了）也算项目目录，同样先备份。"""
        project = tmp_path / "half"
        init_project(project, "portal")
        (project / "registry.json").unlink()
        session = _session_dir(tmp_path, _analysis([_ep("pets")]))

        result = generate(session, project)

        assert Path(result["backup_path"]).is_dir()
        assert load_project(project)["site_name"] is not None
        assert load_registry(project)["endpoints"], "覆盖后必须真按新抓包生成"

    def test_a_fresh_run_produces_the_same_file_set(self, tmp_path):
        """空目录照旧（文件集合与修复前一致）：备份逻辑不能顺手改变正常产物。"""
        session = _session_dir(tmp_path, _analysis([_ep("pets")]))
        out = tmp_path / "out"

        result = generate(session, out)

        rendered = {"server.py", "requirements.txt", ".env.example",
                    "README.md", "smoke_test.py", ".gitignore"}
        assert set(result["files"]) == rendered
        assert {p.name for p in out.iterdir()} == rendered | {"registry.json", "project.json",
                                                             "captures"}
        assert load_registry(out)["endpoints"][0]["path"] == "/api/pets"
        # 空目录**不产生**备份，也不会有 backup_path / message
        assert "backup_path" not in result and "message" not in result
        assert not list(tmp_path.glob("out.bak-*"))

    def test_a_pre_created_but_empty_directory_still_generates(self, tmp_path):
        """目录先被 mkdir 出来（甚至放了个无关文件）不算项目 —— 照常生成、不备份。"""
        session = _session_dir(tmp_path, _analysis([_ep("pets")]))
        out = tmp_path / "empty"
        out.mkdir()
        (out / "scratch.txt").write_text("临时文件", encoding="utf-8")

        result = generate(session, out)

        assert result["endpoint_count"] == 1
        assert (out / "scratch.txt").read_text(encoding="utf-8") == "临时文件"
        assert not list(tmp_path.glob("empty.bak-*"))

    def test_backup_directories_do_not_collide_within_the_same_second(self, tmp_path):
        """同一秒内连跑两次不能把第一份备份覆盖掉（否则等于静默删数据）。"""
        session = _session_dir(tmp_path, _analysis([_ep("pets")]))
        project = self._project_with_user_metadata(tmp_path)

        first = Path(generate(session, project)["backup_path"])
        second = Path(generate(session, project)["backup_path"])

        assert first != second
        assert first.is_dir() and second.is_dir()
        assert load_registry(first)["registry_version"] == 1


class TestEndpointIdIsAssignedOnce:
    """F6：`endpoint_id` 只分配一次，合并不许按位置重编号。

    合并（两个 ID 段收敛到同一个参数化路径）会让端点数量变少；修复前这里紧接着有一
    遍 `ep_{i:03d}` 重编号，把后面端点的键整体前移，于是「分析与生成对同一个键的理解」
    永远差一位。
    """

    def _analyze(self, tmp_path: Path) -> dict:
        """一次抓包：遥测端点 + 三个 /api/orders/* 请求（其中两个会合并成一个端点）。"""
        session = tmp_path / "sessions" / "cap"
        session.mkdir(parents=True)
        urls = [("https://vortex.data.microsoft.com/collect/v1", "POST"),
                ("https://oa.example.com/api/orders/1001", "GET"),
                ("https://oa.example.com/api/orders/1002", "GET"),
                ("https://oa.example.com/api/orders/latest", "GET")]
        events = []
        for index, (url, method) in enumerate(urls):
            events.append({"type": "request", "requestId": f"r{index}", "url": url,
                           "method": method, "headers": {}, "resourceType": "XHR"})
        (session / "capture.jsonl").write_text(
            "\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
        return analyze_capture(session)

    def test_ids_are_not_renumbered_by_the_merge_pass(self, tmp_path):
        result = self._analyze(tmp_path)
        # /api/orders/1001 与 /api/orders/1002 合并为一个端点：保留**先分配**的 ep_002，
        # ep_003 随之消失，后面的端点仍是 ep_004（不是被重编号成 ep_003）。
        assert [e["endpoint_id"] for e in result["endpoints"]] == ["ep_001", "ep_002", "ep_004"]
        assert [e["path"] for e in result["endpoints"]] == [
            "/collect/v1", "/api/orders/{orders_id}", "/api/orders/latest"]

    def test_registry_entry_carries_the_digest_id(self, tmp_path):
        """衔接键一路原样带到 registry：摘要里给哪个键，registry 里就是哪个键。"""
        result = self._analyze(tmp_path)
        entries, _ = session_to_registry_entries(result, "s1")

        assert [e["endpoint_id"] for e in entries] == ["ep_002", "ep_004"]
        # 被丢弃的噪声端点（ep_001）的键不能被别的端点占用，否则就是「键指向了别人」
        assert "ep_001" not in [e["endpoint_id"] for e in entries]
        assert "ep_003" not in [e["endpoint_id"] for e in entries]   # 合并掉的那个也不复用

        project = _project(tmp_path)
        merge_registry(project, entries, _hosts(), "s1")
        stored = {e["path"]: e["endpoint_id"] for e in load_registry(project)["endpoints"]}
        assert stored == {"/api/orders/{orders_id}": "ep_002", "/api/orders/latest": "ep_004"}


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


# --------------------------------------------------------------------------- #
# registry 里的 sample_url 不得带 query 凭据
#
# 抓包 URL 不脱敏是**有意**的（captures 是本地溯源），但 registry.json 是产品产物
# 且随 export_user_package 原样交给同事 —— token / signature / session id 一旦落进
# 去就等于把凭据分发给第三方。这里锁死：registry 与分发包里没有任何 query 取值。
# --------------------------------------------------------------------------- #
class TestSampleUrlCarriesNoCredential:
    CRED_URL = f"https://{HOST}/api/orders?token=SUPERSECRET123&user=alice&page=1"

    def _capture_session(self, tmp_path: Path, url: str) -> Path:
        session = tmp_path / "sessions" / "cap"
        session.mkdir(parents=True)
        events = [
            {"type": "request", "requestId": "r1", "url": url, "method": "GET",
             "headers": {}, "resourceType": "XHR"},
            {"type": "response", "requestId": "r1", "status": 200,
             "headers": {"Content-Type": "application/json"}},
            {"type": "response_body", "requestId": "r1", "body": '{"ok":true}', "size": 11},
        ]
        (session / "capture.jsonl").write_text(
            "\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
        return session

    def test_capture_credential_never_reaches_registry(self, tmp_path: Path) -> None:
        entries, hosts = session_to_registry_entries(
            analyze_capture(self._capture_session(tmp_path, self.CRED_URL)), "s1")
        project = _project(tmp_path)
        merge_registry(project, entries, hosts, "s1")

        raw = (project / "registry.json").read_text(encoding="utf-8")
        assert "SUPERSECRET123" not in raw, "抓包 query 取值被写进了 registry.json"
        assert "alice" not in raw

        stored = load_registry(project)["endpoints"][0]["sample_url"]
        # 仍认得出是哪条请求：scheme+host+path+参数名都在，只有取值变成占位符
        assert stored.startswith(f"https://{HOST}/api/orders?")
        assert "token=" in stored and "user=" in stored and "page=" in stored

    def test_exported_package_carries_no_credential(self, tmp_path: Path) -> None:
        """端到端：整个分发包（registry/README/server/smoke_test）都没有 query 取值。"""
        # 真实链路：抓包 → registry 条目 → 合并 → 渲染 → 导出
        entries, hosts = session_to_registry_entries(
            analyze_capture(self._capture_session(tmp_path, self.CRED_URL)), "s1")
        project = _project(tmp_path)
        merge_registry(project, entries, hosts, "s1")
        regenerate(project)
        export_user_package(project, tmp_path / "dist")

        for path in (tmp_path / "dist").rglob("*"):
            if path.is_file():
                text = path.read_text(encoding="utf-8")
                assert "SUPERSECRET123" not in text, f"{path.name} 夹带了凭据"
                assert "alice" not in text, f"{path.name} 夹带了凭据"

        # 结构不变：收件人仍能读到端点，只是 sample_url / query 样本已去凭据
        shipped = json.loads((tmp_path / "dist" / "registry.json").read_text(encoding="utf-8"))
        endpoint = shipped["endpoints"][0]
        assert endpoint["host"] == HOST
        assert "token=" in endpoint["sample_url"] and "SUPERSECRET123" not in endpoint["sample_url"]
        assert set(endpoint["query_params"]) == {"token", "user", "page"}   # 参数名保留
        assert endpoint["query_params"]["token"] == ["***"]

    def test_legacy_registry_loads_and_is_sanitised_on_next_write(self, tmp_path: Path) -> None:
        project = _project(tmp_path)
        legacy = _registry([_stored(
            sample_url=self.CRED_URL,
            query_params={"token": ["SUPERSECRET123"], "user": ["alice"], "page": ["1"]})])
        (project / "registry.json").write_text(json.dumps(legacy), encoding="utf-8")

        # 老文件照常 load（不崩），盘上仍是原始值（读路径不动它）
        loaded = load_registry(project)
        assert loaded["endpoints"][0]["sample_url"] == self.CRED_URL

        # 下一次写盘（merge 结束也会经过这里）就把老值洗掉
        save_registry(project, loaded)
        saved = (project / "registry.json").read_text(encoding="utf-8")
        assert "SUPERSECRET123" not in saved and "alice" not in saved
        reloaded = load_registry(project)["endpoints"][0]
        assert reloaded["sample_url"] == (
            f"https://{HOST}/api/orders?token=REDACTED&user=REDACTED&page=REDACTED")
        assert reloaded["query_params"] == {"token": ["***"], "user": ["***"], "page": ["1"]}

    def test_url_redaction_does_not_create_diff_noise(self) -> None:
        """diff 只看 (method, host, path) 与 query **参数名集合**；取值被遮蔽不该报差异。"""
        stored = _stored(sample_url=self.CRED_URL,
                         query_params={"token": ["SUPERSECRET123"],
                                       "user": ["alice"], "page": ["1"]})
        fresh = _entries([_ep("pets", query_params={"token": ["***"], "user": ["***"],
                                                    "page": ["1"]})])[0]
        report = diff_registry(_registry([stored]), fresh)

        assert report["counts"] == {"new": 0, "changed": 0, "unseen": 0}

    def test_sanitiser_keeps_host_path_and_param_names(self) -> None:
        cleaned = sanitize_sample_url(self.CRED_URL)
        assert cleaned == f"https://{HOST}/api/orders?token=REDACTED&user=REDACTED&page=REDACTED"
        # 无凭据的 URL 原样保留（不制造 diff 噪音）
        plain = f"https://{HOST}/api/orders"
        assert sanitize_sample_url(plain) == plain
        assert sanitize_sample_url(None) is None


class TestGeneratedLoginReportsCacheFailure:
    """Fix 3：加密缓存写失败必须在 `login()` 结果里可见，不能静默当成功。

    生成物里的 `_cache_save` 吞掉一切异常（缓存坏了不该中断登录），但 `login()`
    以前照样返回 `{'success': True}`，而 README 承诺「重启自动恢复」——用户以为
    凭据已存好，实际没有，且 error.log 之外没有任何信号。现在 `_do_login` 用
    `_cache_save_checked` 回读验证，并把结果如实写进返回值的
    `token_cache` / `credential_cache` 字段（**原有键与含义不变**）。
    """

    AUTH_LOGIN = {"method": "POST", "host": HOST, "path": "/api/login",
                  "account_field": "username", "password_field": "password",
                  "token_path": ["data", "token"], "query_params": {}}

    def _server(self) -> str:
        registry = _registry([_stored()])
        registry["auth_login"] = self.AUTH_LOGIN
        return render_server(registry)["server.py"]

    @staticmethod
    def _function_source(src: str, name: str) -> str:
        import ast
        tree = ast.parse(src)
        node = next(n for n in tree.body
                    if isinstance(n, ast.FunctionDef) and n.name == name)
        segment = ast.get_source_segment(src, node)
        assert segment, f"{name} 不在生成物里"
        return segment

    def _run_check_under(self, *, loadable: bool):
        """在桩函数下执行生成物里的 `_cache_save_checked`。"""
        calls: list = []
        namespace = {
            "_cache_save": lambda path, obj: calls.append(("save", path.name)),
            "_cache_load": lambda path: ({"ok": True} if loadable else None),
            "_log_error": lambda msg: calls.append(("log", msg)),
        }
        exec(compile(self._function_source(self._server(), "_cache_save_checked"),
                     "<generated>", "exec"), namespace)
        ok = namespace["_cache_save_checked"](Path("cred_cache.bin"), {"account": "a"})
        return ok, calls

    def test_unwritable_cache_is_reported_as_not_saved(self):
        ok, calls = self._run_check_under(loadable=False)
        assert ok is False
        assert [kind for kind, _ in calls] == ["save", "log"]
        assert "cred_cache.bin" in calls[1][1]

    def test_successful_cache_is_saved_without_noise(self):
        ok, calls = self._run_check_under(loadable=True)
        assert ok is True
        assert [kind for kind, _ in calls] == ["save"]

    def test_do_login_surfaces_the_cache_state(self):
        src = self._server()
        # 不再裸调 `_cache_save`（那会吞掉失败），两条缓存都经回读验证。
        assert "_cache_save_checked(TOKEN_CACHE" in src
        assert "_cache_save_checked(CRED_CACHE" in src
        assert "_cache_save(TOKEN_CACHE" not in src
        assert "'token_cache': 'saved' if token_saved else 'not_saved'" in src
        assert "'credential_cache': 'saved' if cred_saved else 'not_saved'" in src
        # 原有结果键与语义不变，只是多带了缓存状态。
        assert "'success': True, 'account': _mask(account)," in src
        assert "重启后需重新 login" in src


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


# --------------------------------------------------------------------------- #
# Feature：显式点名包含「本该被跳过」的端点
#
# `generate_mcp_server(endpoint_ids=[...])` 对会被跳过的端点 fail-loud（**这是对的**：
# 键不许静默别名），于是用户复核完 `not_generated`、决定「我就是要它」时**无路可走** ——
# 内部那个 `include_noise` 又没暴露到工具层。`include_endpoint_ids` 就是那条路：
# 列在这里的键绕过全部跳过规则照常生成，并在 registry 与生成的 README 里留痕
# （同事要知道这条噪音端点为什么会在）。
# --------------------------------------------------------------------------- #
class TestIncludeEndpointIds:
    def _session(self, tmp_path: Path) -> Path:
        return _session_dir(tmp_path, _analysis([
            _ep("track", endpoint_id="ep_001", noise=True),
            _ep("orders", endpoint_id="ep_002"),
            _ep("page", endpoint_id="ep_003", non_json_response=True),
        ]))

    def test_noise_endpoint_can_be_included_explicitly(self, tmp_path):
        session = self._session(tmp_path)
        out = tmp_path / "out"

        result = generate(session, out, include_endpoint_ids=["ep_001"])

        assert result["forced_include"] == ["ep_001"]
        assert "/api/track" in (out / "server.py").read_text(encoding="utf-8")
        entry = next(e for e in load_registry(out)["endpoints"] if e["path"] == "/api/track")
        assert entry["forced_include"] is True

    def test_the_generated_readme_says_why_it_is_there(self, tmp_path):
        session = self._session(tmp_path)
        out = tmp_path / "out"

        generate(session, out, include_endpoint_ids=["ep_001"])

        readme = (out / "README.md").read_text(encoding="utf-8")
        assert "显式点名" in readme
        assert "get_api_track" in readme
        assert "include_endpoint_ids" in readme

    def test_non_json_endpoint_can_be_included_explicitly(self, tmp_path):
        session = self._session(tmp_path)
        out = tmp_path / "out"

        result = generate(session, out, include_endpoint_ids=["ep_003"])

        assert result["forced_include"] == ["ep_003"]
        assert "/api/page" in (out / "server.py").read_text(encoding="utf-8")

    def test_endpoint_ids_still_fails_loud_without_the_opt_in(self, tmp_path):
        """`endpoint_ids` 的语义一个字都不能变：跳过端点仍然报「不认识」。"""
        session = self._session(tmp_path)

        with pytest.raises(ValueError, match="ep_001"):
            generate(session, tmp_path / "out", endpoint_ids=["ep_001"])
        with pytest.raises(ValueError, match="ep_003"):
            generate(session, tmp_path / "out2", endpoint_ids=["ep_003"])

    def test_unknown_forced_id_is_ignored_but_reported(self, tmp_path):
        """拼错的键不报错，但也不能声称它被包含了（返回值如实反映实际生效的键）。"""
        session = self._session(tmp_path)
        result = generate(session, tmp_path / "out", include_endpoint_ids=["ep_999"])

        assert result["forced_include"] == []
        assert result["endpoint_count"] == 1     # 只有 orders（其余仍被跳过）

    def test_forced_ids_are_union_with_the_selection(self, tmp_path):
        session = self._session(tmp_path)
        out = tmp_path / "out"

        result = generate(session, out, endpoint_ids=["ep_002"],
                          include_endpoint_ids=["ep_001"])

        assert result["endpoint_count"] == 2
        server = (out / "server.py").read_text(encoding="utf-8")
        assert "/api/track" in server and "/api/orders" in server

    def test_a_later_merge_does_not_erase_the_forced_flag(self, tmp_path):
        """下一次抓包合并（条目里没有这个标记）不能把它抹掉 ——
        否则 README 上「为什么这条噪音端点在这儿」的解释会凭空消失。"""
        project = _project(tmp_path)
        forced, hosts = session_to_registry_entries(
            _analysis([_ep("track", endpoint_id="ep_001", noise=True)]), "s1",
            include_endpoint_ids=["ep_001"])
        merge_registry(project, forced, hosts, "s1")
        assert load_registry(project)["endpoints"][0]["forced_include"] is True

        # 对照组：普通抓包条目（没有 forced_include）——也不能把它变成 False
        plain, hosts2 = session_to_registry_entries(
            _analysis([_ep("track", endpoint_id="ep_001", noise=True)]), "s2",
            include_noise=True)
        assert plain[0]["forced_include"] is False

        merge_registry(project, plain, hosts2, "s2")

        assert load_registry(project)["endpoints"][0]["forced_include"] is True
