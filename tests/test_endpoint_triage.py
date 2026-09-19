# -*- coding: utf-8 -*-
"""Issue #15：端点可独立生成性判定。

两类端点不适合直接生成工具（修复前被 401 掩盖，鉴权修好后才暴露）：
  1. OData 绑定函数 —— 依赖父请求上下文参数，独立调用必失败
  2. 依赖「查询即内容」参数的端点 —— 该参数省略即退化为无界查询
"""
from __future__ import annotations

import pytest

from webapi_extractor.analyzer import (
    has_pagination,
    is_odata_bound_function,
    is_single_record_path,
    query_defining_param,
    require_query_param_suggestion,
    suggest_pagination,
)
from webapi_extractor.generator import _safe_default_query


class TestOdataBoundFunction:
    @pytest.mark.parametrize("path,expected", [
        # 真实抓到的两个绑定函数
        ("/api/data/v9.0/systemusers(000000aa)/Microsoft.Dynamics.CRM.RetrievePrincipalAccess", True),
        ("/api/data/v9.0/activitypointers/Microsoft.Dynamics.CRM.RetrieveTimelineWallRecords", True),
        # 普通集合端点
        ("/api/data/v9.0/annotations", False),
        ("/api/data/v9.0/cr_sampleitems", False),
        ("/api/data/v9.0/cr_sampleitems(00000000-0000)", False),
        # 静态资源不应误判（含点号）
        ("/uclient/blank.htm", False),
        ("/_static/blank.htm", False),
        ("/api/data/v9.0/dashboard.aspx", False),
        ("/AppWebServices/SampleService.asmx/Report", False),
        ("/res/x.js", False),
    ])
    def test_detection(self, path, expected):
        assert is_odata_bound_function(path) is expected


class TestSingleRecord:
    @pytest.mark.parametrize("path,expected", [
        ("/api/data/v9.0/cr_sampleitems(00000000-0000)", True),
        ("/api/data/v9.0/cr_samplelogs(00000000-0001)", True),
        ("/api/data/v9.0/annotations", False),
        ("/api/data/v9.0/reports", False),
    ])
    def test_detection(self, path, expected):
        assert is_single_record_path(path) is expected

    def test_no_pagination_hint_for_single_record(self):
        """单条查询不该被建议分页。"""
        assert suggest_pagination({}, True, "/api/data/v9.0/entities(abc)") is None


class TestPagination:
    @pytest.mark.parametrize("qp,expected", [
        ({"$top": ["10"]}, True),
        ({"fetchXml": ["<fetch/>"]}, True),
        ({"page": ["1"]}, True),
        ({"$skip": ["0"]}, True),
        ({}, False),
        (None, False),
        ({"keyword": ["x"]}, False),
    ])
    def test_has_pagination(self, qp, expected):
        assert has_pagination(qp) is expected

    def test_suggest_only_for_batch_collection(self):
        # batch 还原 + 无分页 + 集合 → 建议
        assert suggest_pagination({}, True, "/api/data/v9.0/things") is not None
        # 非 batch → 不建议
        assert suggest_pagination({}, False, "/api/data/v9.0/things") is None
        # 已有分页 → 不建议
        assert suggest_pagination({"$top": ["1"]}, True, "/api/data/v9.0/things") is None


class TestRequiredQueryParam:
    @pytest.mark.parametrize("qp,expected", [
        ({"fetchXml": ["x"]}, "fetchXml"),
        ({"query": ["x"]}, "query"),
        ({"$top": ["1"]}, None),
        ({}, None),
    ])
    def test_query_defining_param(self, qp, expected):
        assert query_defining_param(qp) == expected

    def test_suggestion_mentions_evidence(self):
        s = require_query_param_suggestion({"fetchXml": ["x"]})
        assert s and s["param"] == "fetchXml"
        assert "超时" in s["evidence"]


class TestSafeDefaultQuery:
    """生成的默认查询必须：结构保留、身份数据剥离、带分页上限。"""

    RAW = ('<fetch version="1.0" mapping="logical" page="1" count="10">'
           '<entity name="annotation">'
           '<attribute name="annotationid"/><attribute name="subject"/>'
           '<link-entity name="systemuser" from="systemuserid" to="modifiedby">'
           '<attribute name="entityimage_url"/><attribute name="fullname"/>'
           '</link-entity>'
           '<filter><condition attribute="objectid" operator="eq" value="00000000-0000"/></filter>'
           '</entity></fetch>')

    def test_strips_link_entity_attributes(self):
        """关联实体字段不属于主实体，混入会 400（实测）。"""
        out = _safe_default_query("fetchXml", [self.RAW])
        assert 'entityimage_url' not in out, "link-entity 字段未剥离"
        assert 'fullname' not in out

    def test_strips_filter(self):
        """不带 filter：不泄漏抓包时的筛选条件。"""
        out = _safe_default_query("fetchXml", [self.RAW])
        assert "<filter" not in out
        assert "00000000" not in out, "身份数据未剥离"

    def test_has_pagination_limit(self):
        out = _safe_default_query("fetchXml", [self.RAW])
        assert 'count="50"' in out
        assert 'page="1"' in out

    def test_preserves_entity_and_attrs(self):
        out = _safe_default_query("fetchXml", [self.RAW])
        assert '<entity name="annotation">' in out
        assert 'name="annotationid"' in out

    def test_valid_xml(self):
        import xml.etree.ElementTree as ET
        out = _safe_default_query("fetchXml", [self.RAW])
        ET.fromstring(out)   # 不应抛异常

    def test_no_attributes_falls_back(self):
        raw = '<fetch><entity name="thing"><filter/></entity></fetch>'
        out = _safe_default_query("fetchXml", [raw])
        assert "<all-attributes/>" in out
        import xml.etree.ElementTree as ET
        ET.fromstring(out)

    def test_order_uses_first_attribute(self):
        out = _safe_default_query("fetchXml", [self.RAW])
        import xml.etree.ElementTree as ET
        ET.fromstring(out)   # order 指向有效字段才合法
        assert '<order attribute="annotationid"' in out
