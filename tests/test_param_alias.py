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
