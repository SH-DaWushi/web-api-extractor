# -*- coding: utf-8 -*-
"""Issue #18：MCP 工具名必须压到 128 字符以内。

`_tool_name()` 从路径机械拼接名字（动词 + 各路径段）。D365 的 OData 绑定函数
调用会把**完整参数列表写进路径**，单段就能贡献 80+ 字符：

    /api/data/v9.0/activitypointers/Microsoft.Dynamics.CRM.RetrieveTimelineWallRecords
        (FetchXml=@xml,Target=@id,RollupType=@rollupType)

机械拼接后达 130 字符，超过 MCP 规范（SEP-986）的 128 上限，fastmcp 在注册
阶段告警。压缩必须**确定性**，否则同一端点在每轮生成时名字会漂移。
"""
from __future__ import annotations

import re

import pytest

from webapi_extractor.project import (
    MCP_TOOL_NAME_MAX,
    _shorten_tool_name,
    _tool_name,
    session_to_registry_entries,
)


# 实际抓到的那条路径（D365 OData 绑定函数，超长主因是复合函数名）。
LONG_PATH = ("/api/data/v9.0/activitypointers/Microsoft.Dynamics.CRM."
             "RetrieveTimelineWallRecords(FetchXml=@xml,Target=@id,RollupType=@rollupType)")

IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
HASH_TAIL_RE = re.compile(r"_[0-9a-f]{8}$")


def _endpoint(path: str, method: str = "GET") -> dict:
    return {"method": method, "host": "example.com", "path": path, "query_params": {}}


class TestShorten:
    def test_short_name_untouched(self):
        assert _shorten_tool_name("get_orders") == "get_orders"

    def test_exactly_at_limit_untouched(self):
        name = "a" * MCP_TOOL_NAME_MAX
        assert _shorten_tool_name(name) == name

    def test_over_limit_is_shortened(self):
        name = "a" * 500
        out = _shorten_tool_name(name)
        assert len(out) <= MCP_TOOL_NAME_MAX
        assert len(out) < len(name)

    def test_has_hash_tail(self):
        out = _shorten_tool_name("x" * 200)
        assert HASH_TAIL_RE.search(out), "压缩结果应带内容哈希后缀"

    def test_deterministic(self):
        """同一输入必须每次得到同一结果（不能用内置 hash()，它按进程随机化）。"""
        name = "segment_" * 40
        assert _shorten_tool_name(name) == _shorten_tool_name(name)

    def test_different_names_do_not_collide(self):
        base = "/api/data/v9.0/things/Microsoft.Dynamics.CRM.Retrieve" + "X" * 200
        a = _shorten_tool_name(base + "Alpha")
        b = _shorten_tool_name(base + "Beta")
        assert a != b
        assert len(a) <= MCP_TOOL_NAME_MAX and len(b) <= MCP_TOOL_NAME_MAX

    def test_cuts_on_word_boundary(self):
        """尽量在 `_` 处截断，不切出半截标识符段。"""
        name = "_".join(f"seg{i:03d}" for i in range(60))
        out = _shorten_tool_name(name)
        head = out[: HASH_TAIL_RE.search(out).start()]
        # 头部去掉末尾可能残留的半段后，每一段都应是完整的 segNNN
        assert all(seg == "" or re.fullmatch(r"seg\d{3}", seg) for seg in head.split("_"))

    def test_tiny_limit_does_not_crash(self):
        assert len(_shorten_tool_name("abcdefghij", limit=12)) <= 12


class TestToolNameEndToEnd:
    def test_real_long_endpoint_within_limit(self):
        name = _tool_name(_endpoint(LONG_PATH), set())
        assert len(name) <= MCP_TOOL_NAME_MAX

    def test_real_long_endpoint_was_actually_over_limit(self):
        """哨兵：确认这条路径机械拼出来确实超限（否则用例失去意义）。"""
        parts = [p for p in LONG_PATH.split("/") if p and not p.startswith("{")]
        mechanical = "get_" + "_".join(re.sub(r"[^a-zA-Z0-9]+", "_", p).strip("_")
                                       for p in parts)
        assert len(mechanical) > MCP_TOOL_NAME_MAX

    def test_result_is_valid_identifier(self):
        name = _tool_name(_endpoint(LONG_PATH), set())
        assert IDENT_RE.fullmatch(name)

    def test_deterministic_across_calls(self):
        assert _tool_name(_endpoint(LONG_PATH), set()) == _tool_name(_endpoint(LONG_PATH), set())

    def test_collision_suffix_still_within_limit(self):
        used: set[str] = set()
        first = _tool_name(_endpoint(LONG_PATH), used)
        second = _tool_name(_endpoint(LONG_PATH), used)
        assert first != second
        assert len(first) <= MCP_TOOL_NAME_MAX
        assert len(second) <= MCP_TOOL_NAME_MAX

    def test_short_endpoint_name_unchanged(self):
        assert _tool_name(_endpoint("/api/orders"), set()) == "get_api_orders"


class TestRegistryEntries:
    def test_all_generated_names_within_limit(self):
        analysis = {
            "endpoints": [
                {"method": "GET", "host": "example.com", "path": LONG_PATH,
                 "query_params": {}, "sample_count": 2, "url": f"https://example.com{LONG_PATH}"},
                {"method": "GET", "host": "example.com", "path": "/api/orders",
                 "query_params": {}, "sample_count": 2, "url": "https://example.com/api/orders"},
            ],
            "auth_metadata": {"auth_schemes": {}},
        }
        entries, _ = session_to_registry_entries(analysis, "s1")
        assert entries
        over = [e["tool_name"] for e in entries if len(e["tool_name"]) > MCP_TOOL_NAME_MAX]
        assert over == []
