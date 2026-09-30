# -*- coding: utf-8 -*-
"""请求体解析：统一 JSON 与表单编码（application/x-www-form-urlencoded）。

表单编码在真实抓包里极常见（各类传统 Java / ASP 系统都用它），
而多个环节都要解析它：脱敏（#22）、密文判定（#21）、参数提取（#23）。

此前各写一份，容易「修一漏二」——正是 domain.py 踩过的坑，
故在此收敛为单一实现。
"""
from __future__ import annotations

import json
from urllib.parse import unquote_plus


def parse_form_urlencoded(payload: str | None) -> list[tuple[str, str]] | None:
    """解析表单编码体为 ``[(字段名, 原始值)]``；不像表单编码时返回 None。

    值保持**原始 URL 编码**（调用方按需 unquote）——脱敏需要原样回写。

    容忍**无值控制项**：真实登录表单普遍带 ``&submit`` / ``&remember`` 这类
    只有字段名、没有 ``=`` 的段。此前遇到它们直接判「非表单编码」返回 None，
    脱敏层于是原样放行整个请求体——**明文密码被完整写进 capture.jsonl**（D1）。
    现在把它们视作值为空（``("submit", "")``），字段名照常保留，
    下游的参数推断（analyzer #23）也因此不会丢字段。

    仍然不认 JSON / XML / HTML 体（``{`` / ``[`` / ``<`` 开头）与**完全不含 ``=``**
    的正文，避免把纯文本误当表单处理。
    """
    if not payload or payload.lstrip()[:1] in ("{", "[", "<"):
        return None
    if "=" not in payload:
        return None
    pairs: list[tuple[str, str]] = []
    for part in payload.split("&"):
        if not part:
            continue
        if "=" in part:
            name, value = part.split("=", 1)
        else:
            name, value = part, ""   # 无值控制项：保留字段名，值按空处理
        pairs.append((name, value))
    return pairs or None


def body_fields(payload: str | None) -> dict[str, str]:
    """把请求体解析成 ``{字段名: 解码后的值}``，支持 JSON 与表单编码。

    JSON 体只保留字符串值（与既有脱敏/密文判定的语义一致）。
    """
    if not payload:
        return {}
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        return {str(key): value for key, value in parsed.items() if isinstance(value, str)}
    pairs = parse_form_urlencoded(payload)
    if pairs is None:
        return {}
    return {unquote_plus(name): unquote_plus(value) for name, value in pairs}
