# -*- coding: utf-8 -*-
"""站点档案（site profiles）。

语义化命名、中文描述与站点专属噪音规则外置于此——技能核心保持通用，
换站点时核心逻辑零改动，只需（可选地）新增一个档案模块。

get_profile(host) 按域名匹配返回档案 dict：
    {"describe": callable(host, path) -> (tool_name, description) | None,
     "drop_hosts": set, "drop_path_patterns": [regex],
     "param_alias": {路径前段: 参数名}}   # 可选，见下

param_alias 用于「按站点覆盖/扩展」参数命名语义（Issue #8）：站点专属语义
（如 article_id / message_id）只应出现在该站点的档案里，绝不进通用分析器。
机制与 merge_param_alias() 见文件末尾。
"""

from __future__ import annotations

import re
from typing import Any, Callable

# 域名关键词 -> 档案模块名（小写）
_REGISTRY: dict[str, str] = {
    "jtest": "jtest",
}

# 已加载档案缓存
_LOADED: dict[str, dict[str, Any]] = {}


def get_profile(host: str) -> dict[str, Any] | None:
    """按 host 匹配站点档案；无匹配返回 None（通用路径）。"""
    host = (host or "").lower()
    for keyword, module_name in _REGISTRY.items():
        if keyword in host:
            if module_name not in _LOADED:
                import importlib
                module = importlib.import_module(f".{module_name}", package=__name__)
                _LOADED[module_name] = module.PROFILE  # type: ignore[attr-defined]
            return _LOADED[module_name]
    return None


def build_profile(rules: list[tuple[str, str, str, str]],
                  drop_hosts: set[str] | None = None,
                  drop_path_patterns: list[str] | None = None,
                  param_alias: dict[str, str] | None = None) -> dict[str, Any]:
    """由 (host_regex, path_regex, tool_name, description) 规则表构建档案。

    param_alias：站点专属的「路径前段 -> 参数名」映射，覆盖/扩展通用默认
    （``<segment>_id``）。不传则保持通用命名。
    """

    def describe(host: str, path: str) -> tuple[str, str] | None:
        for host_re, path_re, tool, desc in rules:
            if re.search(host_re, host) and re.fullmatch(path_re, path):
                return tool, desc
        return None

    return {"describe": describe,
            "drop_hosts": drop_hosts or set(),
            "drop_path_patterns": drop_path_patterns or [],
            "param_alias": dict(param_alias or {})}


def merge_param_alias(base: dict[str, str] | None,
                      profile: dict[str, Any] | None) -> dict[str, str]:
    """通用别名 + 站点档案别名（站点优先）——站点可覆盖亦可扩展，互不干扰。

    base 为通用映射（如 id/page）；profile 缺失或无 param_alias 时原样返回。
    """
    merged = dict(base or {})
    if profile:
        merged.update(profile.get("param_alias") or {})
    return merged
