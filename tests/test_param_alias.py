# -*- coding: utf-8 -*-
"""Issue #8 回归测试：站点专属参数别名不得污染通用分析器。

修复前 PARAM_ALIAS 全局硬编码 {"is_my": "article_id", "content_meta": "content_meta_id",
"read": "message_id", ...}，对所有站点生效。修复后这些别名移出通用层，
通用层只保留 id/page；站点专属语义只能由**该站点自己的档案**提供。

注：本文件原先用某个具体站点的档案做「命名与基线逐字一致」的对照。该档案已从
仓库移除，那两个用例随之删除；站点专属别名是否生效，改由下面基于通用档案的
用例覆盖，不再绑定任何真实站点。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from webapi_extractor.analyzer import (  # noqa: E402
    PARAM_ALIAS,
    parameterize,
)

OTHER_HOST = "other.example.com:8443"
SITE_HOST = "site.example.com"

# 这些路径形态取自真实抓包（连字符、下划线数字、层次较深的长段），
# 用来确保通用命名在这些形态下稳定——但不再指向任何具体站点。
SAMPLE_PATHS = [
    "/api/article/favorites/is-my/12782/achievement",
    "/api/article/favorites/is-my/12782/bps",
    "/api/article/favorites/is-my/12782/collection",
    "/api/next2/userdata/commit-history/content-meta/6463/commit/history",
    "/api/next2/userdata/messages/read/998",
    "/api/node/item/12782",
    "/api/node/achievement/521/relations",
    "/api/summary-any/item-10_773/stat",
    "/api/next2/community/discussion/topic/item/5566/reply/list",
    "/api/cms/user/9527/info",
    "/api/cms/post/8/post/authors",
]


def test_generic_alias_has_no_site_specific_names() -> None:
    assert "is_my" not in PARAM_ALIAS
    assert "content_meta" not in PARAM_ALIAS
    assert "read" not in PARAM_ALIAS
    assert PARAM_ALIAS == {"id": "id", "page": "page"}


def test_generic_naming_is_stable_across_sample_paths() -> None:
    """通用命名在这些路径形态上稳定：重复调用结果一致，且只产出通用名。"""
    for path in SAMPLE_PATHS:
        first = parameterize(path, OTHER_HOST)
        assert parameterize(path, OTHER_HOST) == first, path
        assert all(re.fullmatch(r"[a-z0-9_]+", name) for name in first[1]), (path, first)


def test_site_specific_semantics_no_longer_leak_into_other_sites() -> None:
    """核心回归：曾经被误命名的路径，对无关站点只能得到通用名。"""
    assert parameterize("/api/article/favorites/is-my/12782/achievement",
                        OTHER_HOST)[1] == ["is_my_id"]
    assert parameterize("/api/next2/userdata/messages/read/998",
                        OTHER_HOST)[1] == ["read_id"]
    assert parameterize("/api/next2/userdata/commit-history/content-meta/6463/commit/history",
                        OTHER_HOST)[1] == ["content_meta_id"]


def test_unrelated_site_not_misnamed() -> None:
    """无关站点不得再被命名为站点专属语义。"""
    new_path, names = parameterize("/api/article/favorites/is-my/12782/achievement",
                                   OTHER_HOST)
    assert "article_id" not in names, names
    assert names == ["is_my_id"], names
    assert new_path == "/api/article/favorites/is-my/{is_my_id}/achievement"
    assert parameterize("/api/next2/userdata/messages/read/998", OTHER_HOST)[1] == ["read_id"]


def test_generic_mapping_still_works_without_host() -> None:
    """不传 host（纯通用层）时路径前段仍按 <segment>_id 命名。"""
    assert parameterize("/api/item/123")[1] == ["item_id"]
    assert parameterize("/api/id/123")[1] == ["id"]
    assert parameterize("/api/page/2")[1] == ["page"]


def test_site_can_override_and_extend_generic_alias() -> None:
    from webapi_extractor.site_profiles import merge_param_alias

    merged = merge_param_alias({"id": "id", "read": "read"},
                               {"param_alias": {"id": "custom_id", "extra": "extra_id"}})
    assert merged["id"] == "custom_id"   # 站点可覆盖
    assert merged["read"] == "read"      # 通用项保留
    assert merged["extra"] == "extra_id"  # 站点可扩展


def test_every_registered_site_profile_actually_exists() -> None:
    """注册表里的每个档案模块都必须真的存在。

    否则 get_profile() 抛 ModuleNotFoundError，而调用方
    （analyzer._load_site_profile）把它吞成 None —— 站点档案功能静默失效，
    外面完全看不出问题。
    """
    import importlib

    from webapi_extractor.site_profiles import _REGISTRY

    for module_name in _REGISTRY.values():
        importlib.import_module(f".{module_name}", package="webapi_extractor.site_profiles")


def test_profile_lookup_is_safe_without_profiles() -> None:
    """没有档案注册时，任意 host 都应安全地走通用路径。"""
    from webapi_extractor.site_profiles import get_profile

    assert get_profile(SITE_HOST) is None
    assert get_profile("") is None


# --------------------------------------------------------------------------- #
# 两种此前认不出来的 ID 形态：OData 记录键 与 UUID 段
# --------------------------------------------------------------------------- #
GUID = "638ca21c-1111-4a2b-9c3d-000000000001"
GUID2 = "638ca21c-2222-4a2b-9c3d-000000000002"
ODATA_ENTITY = "/xrmservices/2011/OrganizationData.svc/new_serviceeventses"


class TestODataRecordKeys:
    """``实体(键)`` 是 OData v4 的标准寻址语法（Dynamics 365 / CRM、SharePoint REST、
    SAP Gateway / NetWeaver、各类 WCF Data Service 都在用），不是某个站的怪癖。

    修复前：实体名 + 括号 + GUID 粘成一段，整段既不是数字也不是 UUID → 不参数化
    → 抓包时那条记录的 GUID 被写死进路径与工具名；同一实体访问过的每条记录还会
    **各自变成一个工具**（一份抓包能产出几十个「只能改那一条」的工具，且调用不报错）。
    """

    def test_key_is_parameterized_and_entity_name_kept(self):
        new_path, names = parameterize(f"{ODATA_ENTITY}({GUID})", OTHER_HOST)
        assert new_path == ("/xrmservices/{xrmservices_id}/OrganizationData.svc/"
                            "new_serviceeventses({new_serviceeventses_id})")
        assert names == ["xrmservices_id", "new_serviceeventses_id"]

    def test_two_records_of_one_entity_normalize_identically(self):
        """同一实体的两条记录必须归一到同一路径 —— 否则会被拆成两个工具。"""
        assert (parameterize(f"{ODATA_ENTITY}({GUID})", OTHER_HOST)[0]
                == parameterize(f"{ODATA_ENTITY}({GUID2})", OTHER_HOST)[0])

    def test_quoted_string_key_keeps_its_quotes(self):
        """OData 的字符串键带单引号：替换后引号必须还在，否则生成的 URL 是错的。"""
        new_path, names = parameterize("/odata/Products('12345')", OTHER_HOST)
        assert new_path == "/odata/Products('{products_id}')"
        assert names == ["products_id"]

    def test_literal_key_is_left_alone(self):
        """键不是 ID 形态（字面量键）→ 整段原样，不猜。"""
        assert parameterize("/odata/Products('Widget')", OTHER_HOST) == \
            ("/odata/Products('Widget')", [])

    def test_expression_with_nested_parens_is_left_alone(self):
        """括号里还有括号（``GetMetadata(...)`` 那类表达式）不认。"""
        path = "/odata/GetMetadata(invocation=@i)"
        assert parameterize(path, OTHER_HOST) == (path, [])


class TestUuidSegments:
    """UUID 独占一段：``/api/tickets/<guid>``。

    修复前 ``_is_id_segment`` 只认纯数字与 ``<type>-<数字>``，带连字符的 UUID 一个都不
    匹配 —— 于是详情 / 修改接口把抓包那条记录的 GUID 写死，同一接口访问多条记录还会
    各生成一个工具。``[a-z_]+-\\d+`` 也救不了：GUID 以数字开头，后面几段还混有字母。
    """

    def test_uuid_segment_is_parameterized(self):
        assert parameterize(f"/api/tickets/{GUID}", OTHER_HOST) == \
            ("/api/tickets/{tickets_id}", ["tickets_id"])

    def test_two_uuids_normalize_to_the_same_path(self):
        assert (parameterize(f"/api/tickets/{GUID}", OTHER_HOST)[0]
                == parameterize(f"/api/tickets/{GUID2}", OTHER_HOST)[0]
                == "/api/tickets/{tickets_id}")

    def test_non_id_literals_are_still_preserved(self):
        """保守性不能被这次放宽冲掉：字面量段照旧原样保留。"""
        for path in ("/api/community/list", "/api/next2/item", "/api/v2/report",
                     "/api/item_merged.summary"):
            assert parameterize(path, OTHER_HOST) == (path, []), path


def test_odata_endpoint_keeps_its_key_as_a_registry_parameter(tmp_path: Path) -> None:
    """端到端：同一实体的两条记录 → **一个**端点，且键进得了 ``path_params``。

    这里钉的是两个不同层的配合：
    * ``analyzer.parameterize`` 负责把键折成具名参数；
    * ``project.session_to_registry_entries`` 负责从路径里**取出**参数名 ——
      它此前只认「整段以 ``{`` 开头」，嵌在段中间的占位符被漏掉，生成物于是拿不到
      这个参数，``_emit_path`` 会把 ``{…}`` 当普通字符转义，发出的 URL 里带着字面量花括号。
    """
    import json

    from webapi_extractor.analyzer import analyze_capture
    from webapi_extractor.project import session_to_registry_entries

    host = "crm.example.com"
    lines = []
    for index, guid in enumerate((GUID, GUID2), start=1):
        url = f"https://{host}{ODATA_ENTITY}({guid})"
        lines += [
            {"type": "request", "requestId": f"r{index}", "url": url, "method": "GET",
             "headers": {"Accept": "application/json"}, "resourceType": "XHR"},
            {"type": "response", "requestId": f"r{index}", "status": 200,
             "headers": {"Content-Type": "application/json"}},
            {"type": "response_body", "requestId": f"r{index}", "body": '{"ok":true}', "size": 12},
        ]
    (tmp_path / "capture.jsonl").write_text(
        "\n".join(json.dumps(line, ensure_ascii=False) for line in lines), encoding="utf-8")

    entries, _hosts = session_to_registry_entries(analyze_capture(tmp_path), "s1")

    assert len(entries) == 1, f"同一实体的两条记录被拆成了多个端点：{entries}"
    entry = entries[0]
    assert entry["path"].endswith("new_serviceeventses({new_serviceeventses_id})")
    assert "new_serviceeventses_id" in entry["path_params"], entry
    assert GUID[:8] not in entry["path"], "GUID 不该出现在路径里"
    assert GUID[:8] not in entry["tool_name"], "GUID 不该出现在工具名里"
