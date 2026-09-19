# -*- coding: utf-8 -*-
"""代理环境变量清洗：绕开 httpx 对 NO_PROXY 方括号 IPv6 的解析缺陷。

背景
----
httpx 在**构造客户端**时（``httpx.Client()`` / ``httpx.AsyncClient()``）就会
解析环境里的代理配置，包括 ``NO_PROXY``。若 ``NO_PROXY`` 含**方括号形式的
IPv6 字面量**（如 ``[::1]``），解析直接抛::

    httpx.InvalidURL: Invalid port: ':1]'

注意两点：
  * 这是在构造阶段失败的 —— 即使请求根本不经过代理，客户端也建不起来；
  * **裸** ``::1`` 无此问题，``[::1]`` 才有。

Cherry Studio 默认写入的 ``NO_PROXY`` 两种形式都有::

    NO_PROXY=localhost,127.0.0.1,::1,windows10.corp.example,[::1]

于是任何用默认 ``trust_env=True`` 的客户端都会在构造时崩溃。

修法
----
把方括号剥掉还原为裸 IPv6（``[::1]`` → ``::1``）——既修好解析，又**保留代理
能力**（企业网络需经代理访问目标站时不受影响）。仅清洗解析不了的条目，
不改变其它代理语义。

用法
----
在构造 httpx 客户端之前调用一次 ``sanitize_no_proxy()``。幂等，可重复调用。

注意：仅连回环地址的客户端应直接用 ``trust_env=False``（见 ``mcp_call.py``），
那比清洗更彻底——回环流量本就不该经过任何代理。本模块针对的是**访问外部
站点**的客户端。
"""
from __future__ import annotations

import os


# httpx 读取的 no-proxy 变量名（大小写两套都要覆盖）。
_NO_PROXY_VARS = ("NO_PROXY", "no_proxy")


def _strip_brackets(entry: str) -> str:
    """``[::1]`` → ``::1``；非方括号条目原样返回。"""
    entry = entry.strip()
    if len(entry) >= 2 and entry.startswith("[") and entry.endswith("]"):
        return entry[1:-1].strip()
    return entry


def sanitize_no_proxy() -> bool:
    """就地把 ``NO_PROXY`` / ``no_proxy`` 中的方括号 IPv6 还原为裸形式。

    返回是否发生了修改（便于测试与诊断）。幂等：无方括号时直接返回 False。
    """
    changed = False
    for var in _NO_PROXY_VARS:
        raw = os.environ.get(var)
        if not raw or "[" not in raw:
            continue
        parts = [_strip_brackets(part) for part in raw.split(",")]
        cleaned = ",".join(part for part in parts if part)
        if cleaned != raw:
            os.environ[var] = cleaned
            changed = True
    return changed
