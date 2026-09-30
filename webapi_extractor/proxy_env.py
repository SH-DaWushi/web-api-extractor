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

    NO_PROXY=localhost,127.0.0.1,::1,<你的机器域名>,[::1]

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


# --------------------------------------------------------------------------- #
# 抓包浏览器（Chromium）的代理开关
# --------------------------------------------------------------------------- #
# 设置项名（`config.Settings.proxy_mode`）。取值只有三个，非法值必须给**明确错误**。
PROXY_MODE_ENV = "WEB_API_EXTRACTOR_PROXY_MODE"
# **默认 `auto`：先直连，遇到代理形态的失败自动改用系统代理重试一次。**
#
# 为什么默认不是「只直连」：直连是**正确的起点**（Chromium 不加任何代理参数会静默跟随
# 系统代理，非回环主机的请求被代理吃掉后只表现为 `net::ERR_EMPTY_RESPONSE`，极难归因；
# 实测加 `--no-proxy-server` 才通），但对「本来就要经系统代理才通的站点」等于直接判死。
# 默认 `auto` 两种站点都能通，且**不需要用户设任何东西**——这是本项的产品验收点。
#
# `direct` / `system` 是给「我要手动控制」的人的**严格**取值，失败**不回退**：
#   * `direct`：只直连（例如代理会篡改流量、必须绕开它时）；
#   * `system`：只跟随系统代理（例如所在网络只允许经代理出网时）。
PROXY_MODES = ("auto", "direct", "system")
BUILTIN_DIRECT_ARG = "--no-proxy-server"
DEFAULT_PROXY_MODE = "auto"


def browser_proxy_args(mode: str) -> list[str]:
    """按模式给出 Chromium 的**代理相关**启动参数。

    ``auto``（默认）→ ``["--no-proxy-server"]``：**从直连开始**，失败再自动回退。
    ``direct`` → 同上：直连，且失败不回退。
    ``system`` → ``[]``：不加任何参数，即「跟随系统代理」的行为。

    认不出的取值按「直连」处理（配置层已拦下非法值并报错，这里只兜底）。
    """
    return [] if mode == "system" else [BUILTIN_DIRECT_ARG]


def mode_label(mode: str) -> str:
    """模式的**人话**说法（写进诊断/告知文案，别让读者去猜枚举值）。"""
    if mode == "system":
        return "跟随系统代理"
    if mode == "direct":
        return "直连（不回退）"
    return "直连"


def fallback_proxy_mode(mode: str) -> str | None:
    """``mode`` 失败后要自动回退到的模式；**不该回退**时返回 ``None``。

    只做 ``auto`` → ``system`` 这一个方向：

    * ``auto`` 是「我不管，你让它通就行」——失败换一种方式重试正合其意；
    * ``direct`` / ``system`` 是显式的手动控制。把它们偷偷改成另一种等于**违抗用户的
      设置**（用户设 ``direct`` 往往正因为代理会篡改/拦截他的流量），那才是负优化。
    """
    return "system" if mode == DEFAULT_PROXY_MODE else None


def _one_line(value: object, limit: int = 300) -> str:
    """把一段可能很长的错误压成**一行**（诊断里两种模式的失败要并列，不能各占十行）。"""
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[:limit] + "…"


def auto_fallback_notice(from_mode: str, to_mode: str) -> str:
    """自动回退成功后的**告知**文案。

    必须说出来：用户只看到「成功了」，就无从知道服务在背后换了代理方式——下次换个
    站点失败时，他连「代理会被自动切换」这件事都不知道，也就无从排查。
    """
    return (
        f"注：首个页面按「{mode_label(from_mode)}」加载失败，服务已**自动改用"
        f"「{mode_label(to_mode)}」重试**，本次加载成功（只回退这一次，不会反复重试）。"
        f"你不需要做任何设置。"
    )


def both_modes_failed_detail(from_mode: str, to_mode: str,
                             first_error: object, second_error: object) -> str:
    """两种模式都失败时的诊断：**说清试过哪两种**、各自怎么失败的、接下来查什么。"""
    return (
        f"首个页面在两种代理模式下都无法加载；两种都试过了（直连失败后自动回退一次，"
        f"不会反复重试）：\n"
        f"  · {mode_label(from_mode)}：{_one_line(first_error)}\n"
        f"  · {mode_label(to_mode)}（自动回退后）：{_one_line(second_error)}\n"
        "两次都失败说明「必须走代理」和「必须直连」都解释不了这次失败，按这个顺序排查：\n"
        "  1) 目标站自身是否可达：用**普通浏览器**直接打开这个地址试一次"
        "（地址写错 / 站点宕机是最常见的原因）；\n"
        "  2) 系统代理是否真的通：代理软件在运行吗、端口对吗？（Chromium 跟随系统代理时"
        "**不会弹认证框**，需要认证的代理连不上）；\n"
        "  3) 内网 / 证书 / DNS 类问题：调 doctor 看诊断。\n"
        f"想手动控制代理行为，可设 {PROXY_MODE_ENV}=auto|direct|system（见 docs/reference.md）。"
    )


# Chromium 导航错误码里**一定**是代理（或代理配置）问题的那些。
_PROXY_CERTAIN_CODES = (
    "ERR_PROXY_CONNECTION_FAILED",
    "ERR_TUNNEL_CONNECTION_FAILED",
    "ERR_NO_SUPPORTED_PROXIES",
    "ERR_MANDATORY_PROXY_CONFIGURATION_FAILED",
    "ERR_PROXY_AUTH_UNSUPPORTED",
    "ERR_PROXY_CERTIFICATE_INVALID",
)
# 更常见的形态：**可能**是请求被代理吃掉，也可能是目标站自身不可达 —— 须给出提示，
# 但不能断言。`ERR_EMPTY_RESPONSE` 正是真机踩到的那个（极难归因）。
_PROXY_POSSIBLE_CODES = (
    "ERR_EMPTY_RESPONSE",
    "ERR_CONNECTION_RESET",
    "ERR_CONNECTION_CLOSED",
    "ERR_CONNECTION_REFUSED",
    "ERR_CONNECTION_TIMED_OUT",      # 真机实测：直连被拦截时的形态（别只认 ERR_TIMED_OUT）
    "ERR_CONNECTION_FAILED",
    "ERR_CONNECTION_ABORTED",
    "ERR_TIMED_OUT",
    "ERR_NAME_NOT_RESOLVED",
    "ERR_ADDRESS_UNREACHABLE",
)


def proxy_failure_kind(message: object) -> str | None:
    """这条失败信息更像代理问题吗？

    返回 ``"proxy"``（几乎确定是代理）/ ``"possible"``（可能是，也可能是目标站自身）/
    ``None``（看不出与代理有关）。认不出的失败**不**给代理提示 —— 否则会把真正的
    目标站故障误导成代理问题。
    """
    text = str(message or "").upper()
    if any(code in text for code in _PROXY_CERTAIN_CODES):
        return "proxy"
    if any(code in text for code in _PROXY_POSSIBLE_CODES):
        return "possible"
    return None


def proxy_failure_hint(message: object, *, mode: str = DEFAULT_PROXY_MODE) -> str | None:
    """把代理类失败翻译成**可行动**的一句话；与代理无关时返回 ``None``。

    ``mode`` 是**当前**的抓包浏览器代理模式（``auto`` / ``direct`` / ``system``），
    写进提示里，使用者据此知道现在是什么、以及该切成什么。
    """
    kind = proxy_failure_kind(message)
    if kind is None:
        return None
    current = {"system": "跟随系统代理", "direct": "直连（--no-proxy-server）"}.get(
        mode, "自动（先直连，失败自动改用系统代理重试一次）")
    cause = ("这是代理类错误码，基本可以确定是代理把请求拦下了"
             if kind == "proxy" else
             "这个错误码通常是请求被代理吃掉，也可能是目标站自身不可达")
    return (
        f"可能是代理问题：{cause}。当前抓包浏览器为「{current}」。"
        f"可切换设置 {PROXY_MODE_ENV}：auto（默认：先直连，代理类失败自动改用"
        f"系统代理重试一次）、direct（只直连，等价 {BUILTIN_DIRECT_ARG}）"
        f"或 system（只跟随系统代理），改完重启服务后重试。"
        f"若环境里设了 HTTP_PROXY / HTTPS_PROXY / ALL_PROXY，也请一并确认。"
    )


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
