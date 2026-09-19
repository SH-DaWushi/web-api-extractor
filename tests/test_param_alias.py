# -*- coding: utf-8 -*-
"""Issue #8 回归测试：站点专属参数别名不得污染通用分析器。

修复前 PARAM_ALIAS 全局硬编码 {"is_my": "article_id", "content_meta": "content_meta_id",
"read": "message_id", ...}，对所有站点生效。修复后这些别名移入 example 档案，
通用层只保留 id/page。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from webapi_extractor.analyzer import (  # noqa: E402
    _is_id_segment,
    PARAM_ALIAS,
    parameterize,
)

JX3BOX_HOST = "api.example.com"
OTHER_HOST = "other.example.com:8443"

# 修复前的通用别名（git 基线原值），用于等价性对照。
LEGACY_ALIAS = {"is_my": "article_id", "content_meta": "content_meta_id",
                "read": "message_id", "id": "id", "page": "page"}


def legacy_parameterize(path: str) -> tuple[str, list[str]]:
    """逐字复刻修复前的 parameterize()，仅别名表用 LEGACY_ALIAS。"""
    segs = path.split("/")
    out: list[str] = []
    names: list[str] = []
    for i, seg in enumerate(segs):
        if not (_is_id_segment(seg) or re.fullmatch(r"\{[^}]+\}", seg)):
            out.append(seg)
            continue
        if re.fullmatch(r"\{[^}]+\}", seg):
            out.append(seg)
            continue
        prev = segs[i - 1] if i > 0 else ""
        base = re.sub(r"[^a-z0-9]+", "_", prev.lower()).strip("_")
        name = LEGACY_ALIAS.get(base) or (base + "_id" if base else "id")
        if name in names:
            name = f"{name}_{names.count(name) + 1}"
        names.append(name)
        out.append(f"{{{name}}}")
    return "/".join(out), names


JX3BOX_PATHS = [
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


def test_example_naming_unchanged_vs_baseline() -> None:
    """已收录站点的命名结果与修复前逐字符一致。"""
    for path in JX3BOX_PATHS:
        assert parameterize(path, JX3BOX_HOST) == legacy_parameterize(path), path


def test_example_site_specific_aliases_apply() -> None:
    assert parameterize("/api/article/favorites/is-my/12782/achievement",
                        JX3BOX_HOST)[1] == ["article_id"]
    assert parameterize("/api/next2/userdata/messages/read/998",
                        JX3BOX_HOST)[1] == ["message_id"]
    assert parameterize("/api/next2/userdata/commit-history/content-meta/6463/commit/history",
                        JX3BOX_HOST)[1] == ["content_meta_id"]


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
