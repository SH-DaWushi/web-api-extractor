# -*- coding: utf-8 -*-
"""请求体解析：统一 JSON 与表单编码（application/x-www-form-urlencoded）。

表单编码在真实抓包里极常见（各类传统 Java / ASP 系统都用它），
而多个环节都要解析它：脱敏（#22）、密文判定（#21）、参数提取（#23）。

此前各写一份，容易「修一漏二」——正是 domain.py 踩过的坑，
故在此收敛为单一实现。
"""
from __future__ import annotations

import json
import re
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


# multipart/form-data：浏览器登录表单（以及带文件上传的表单）最常见的提交方式。
# CDP 给的 postData 是**原始 multipart 文本**——既不是 JSON，也不是表单编码，
# 但它的头部里带 ``=``（``name="password"``），于是会被 parse_form_urlencoded
# 当成表单硬拆：按 ``=`` 切出来的「字段名」是那一整段头部，凭据名判定自然落空，
# 值原样留下 —— **明文密码照样进 capture.jsonl**（与 D1 同一类洞，换了个编码）。
# 所以这里按「边界 + 字段名」切成段，让脱敏层能**就地**替换值而不动其它字节。
_MULTIPART_BOUNDARY_RE = re.compile(r"[ \t\r\n]*--([^\r\n]+)\r?\n")
_MULTIPART_NAME_RE = re.compile(
    r"""(?<![A-Za-z0-9_\-])name\s*=\s*"([^"]*)"|(?<![A-Za-z0-9_\-])name\s*=\s*([^;\r\n]*)""",
    re.I,
)
_PART_SEPARATORS = ("\r\n\r\n", "\n\n")


def split_multipart(payload: str | None) -> tuple[str, list[tuple[str | None, str]]] | None:
    """把 multipart 体切成 ``(boundary, [(字段名 or None, 段原文)])``；不是 multipart 返回 None。

    段原文**包含**紧跟边界之后的 ``\\r\\n`` 与全部头部，直到下一个边界为止，
    因此 ``boundary.join(段原文…)`` 与输入**逐字节一致**。调用方可以就地替换
    某一段的值再拼回去——边界、头部顺序、结尾的 ``--`` 都不会被动到（保真优先）。

    字段名为 ``None`` 的段是前导与结束分隔符（以及结束之后的一切），一律原样保留。
    """
    if not payload:
        return None
    match = _MULTIPART_BOUNDARY_RE.match(payload)
    if not match:
        return None
    boundary = "--" + match.group(1)
    chunks = payload.split(boundary)
    if len(chunks) < 2:
        return None
    parts: list[tuple[str | None, str]] = [(None, chunks[0])]
    for index in range(1, len(chunks)):
        chunk = chunks[index]
        if chunk.startswith("--"):
            # 结束分隔符及其后的一切都是尾部文本，不再当字段解析。
            parts.append((None, boundary.join(chunks[index:])))
            break
        parts.append((_multipart_field_name(chunk), chunk))
    return boundary, parts


def split_multipart_part(chunk: str) -> tuple[str, str] | None:
    """把一段 multipart 拆成 ``(头部含空行, 原始值)``；找不到头/体空行时返回 None。"""
    for separator in _PART_SEPARATORS:
        position = chunk.find(separator)
        if position != -1:
            cut = position + len(separator)
            return chunk[:cut], chunk[cut:]
    return None


def parse_multipart(payload: str | None) -> list[tuple[str, str]] | None:
    """解析 multipart 体为 ``[(字段名, 原始值)]``；不像 multipart 时返回 None。

    只认 ``Content-Disposition`` 里的字段名，**不做**完整 RFC 2046 解析
    （嵌套 multipart、Content-Transfer-Encoding 一概不处理）：脱敏只需要
    「按名字找到值并替换」，多解析一分就多一分与真实实现不一致的风险。
    """
    split = split_multipart(payload)
    if split is None:
        return None
    fields: list[tuple[str, str]] = []
    for name, chunk in split[1]:
        if name is None:
            continue
        part = split_multipart_part(chunk)
        if part is None:
            continue
        fields.append((name, part[1]))
    return fields or None


def _multipart_field_name(chunk: str) -> str | None:
    """从一段 multipart 的头部里取 ``Content-Disposition`` 的字段名。"""
    head = split_multipart_part(chunk)
    match = _MULTIPART_NAME_RE.search(head[0] if head else chunk)
    if not match:
        return None
    # 引号形式优先（``name="password"``）；无引号形式才可能带尾部空格。
    value = match.group(1) if match.group(1) is not None else (match.group(2) or "").strip()
    # 字段名在 multipart 里**不是** URL 编码的，不能 unquote（``+`` 是字面量）。
    return value or None


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
