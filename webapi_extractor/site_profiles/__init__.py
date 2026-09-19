# -*- coding: utf-8 -*-
"""站点档案（site profiles）。

语义化命名、中文描述与站点专属噪音规则外置于此——技能核心保持通用，
换站点时核心逻辑零改动，只需（可选地）新增一个档案模块。

get_profile(host) 按域名匹配返回档案 dict：
    {"describe": callable(host, path) -> (tool_name, description) | None,
     "drop_hosts": set, "drop_path_patterns": [regex]}
"""

from __future__ import annotations

import re
from typing import Any, Callable

# 域名关键词 -> 档案模块名（小写）
_REGISTRY: dict[str, str] = {
    "example": "example",
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
                  drop_path_patterns: list[str] | None = None) -> dict[str, Any]:
    """由 (host_regex, path_regex, tool_name, description) 规则表构建档案。"""

    def describe(host: str, path: str) -> tuple[str, str] | None:
        for host_re, path_re, tool, desc in rules:
            if re.search(host_re, host) and re.fullmatch(path_re, path):
                return tool, desc
        return None

    return {"describe": describe,
            "drop_hosts": drop_hosts or set(),
            "drop_path_patterns": drop_path_patterns or []}
