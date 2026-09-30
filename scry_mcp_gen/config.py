"""Runtime configuration for the extractor."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .proxy_env import DEFAULT_PROXY_MODE, PROXY_MODES, browser_proxy_args

# 响应体/请求体/WebSocket 帧共用的体积上限环境变量名。**只在这里写一次**：
# 抓包侧（capture.py）与摘要侧（analyzer.py / server.py）必须指向同一个开关，
# 否则「建议调大上限」的提示会指错变量（用户改了也不生效）。
RESPONSE_LIMIT_ENV = "SCRY_RESPONSE_LIMIT"

# ``start_capture`` 的 ``response_limit_bytes`` 参数允许的最大值。
#
# 为什么必须有硬上限：``capture.jsonl`` **只追加、无轮转、无保留期**（见
# docs/reference.md「数据目录体积与响应上限语义」），而这个值决定每一条响应体 /
# 请求体 / WebSocket 帧要不要整条落盘。若允许一个「随手填的」巨大值（10 GB），
# **一条**响应就能把磁盘写满，且失败发生在抓包中途、使用者完全无从归因。
# 64 MB 已是默认上限（256 KB）的 256 倍，足以装下现实中会被抓的 JSON / 文档响应；
# 再往上只是单纯放大磁盘风险，换不来任何东西。
MAX_RESPONSE_LIMIT_BYTES = 64 * 1024 * 1024

# 提示语里给出的**具体**建议值（Agent 直接照抄即可，不必自己算 —— 使用者更不必
# 知道「有个上限」这件事）。取 4 MB：是默认值的 16 倍，能覆盖绝大多数被丢弃的响应，
# 又在硬上限之下留足余量。
SUGGESTED_RESPONSE_LIMIT_BYTES = 4 * 1024 * 1024


def _human_bytes(size: int) -> str:
    """把字节数写成人能读的形态（只在给用户看的提示语里用）。"""
    if size >= 1024 * 1024 and size % (1024 * 1024) == 0:
        return f"{size // (1024 * 1024)} MB"
    if size >= 1024 and size % 1024 == 0:
        return f"{size // 1024} KB"
    return f"{size} 字节"


def response_limit_error(value: object) -> str | None:
    """校验 ``start_capture(response_limit_bytes=…)``；返回**给人看的错误句**，合法则 ``None``。

    为什么在调用入口就挡住、而不是让抓包中途炸：这个值决定每一条响应体 / 请求体 /
    WebSocket 帧要不要落盘。非法值（0 / 负数 / 布尔 / 非整数 / 超过硬上限）若放过去，
    结果要么「整轮什么也不记」要么「一条响应把磁盘写满」，而失败会发生在**抓包中途**，
    使用者（和替他操作的 Agent）都无从归因。错误句必须同时说清「合法范围」和「怎么办」，
    并给出一个可照抄的合法值 —— 否则非技术使用者只知道「错了」，不知道改成什么。
    """
    if value is None:
        # 不传 = 沿用 Settings / 环境变量的值，与改动前完全一致（这才是默认路径）。
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        return (f"response_limit_bytes 必须是正整数（单位：字节），收到 {value!r}。"
                f"合法范围 1 ~ {MAX_RESPONSE_LIMIT_BYTES}"
                f"（例如 4194304 表示 {_human_bytes(SUGGESTED_RESPONSE_LIMIT_BYTES)}）。"
                "不确定就传 4194304，或者干脆不传这个参数（沿用默认上限 256 KB）。")
    if value <= 0:
        return (f"response_limit_bytes 必须是正整数（单位：字节），收到 {value}。"
                f"合法范围 1 ~ {MAX_RESPONSE_LIMIT_BYTES}；"
                "既然要调大上限，请传 4194304（4 MB）这类更大的正数，或者干脆不传"
                "（沿用默认上限 256 KB）。")
    if value > MAX_RESPONSE_LIMIT_BYTES:
        return (f"response_limit_bytes={value} 超过了允许的最大值 {MAX_RESPONSE_LIMIT_BYTES}"
                f"（{_human_bytes(MAX_RESPONSE_LIMIT_BYTES)}）。设这个上限是为了保护磁盘："
                "capture.jsonl 只追加、不轮转，单个响应体的上限开得越大，一条响应就能把磁盘写满的"
                f"风险越高。请传一个不超过 {MAX_RESPONSE_LIMIT_BYTES} 的值，"
                f"例如 4194304（{_human_bytes(SUGGESTED_RESPONSE_LIMIT_BYTES)}）。")
    return None


def _suggested_limit(limit: int) -> int | None:
    """提示语里建议调到的上限；当前已是硬上限时返回 ``None``（没法再调大）。"""
    if limit >= MAX_RESPONSE_LIMIT_BYTES:
        return None
    return min(max(limit * 4, SUGGESTED_RESPONSE_LIMIT_BYTES), MAX_RESPONSE_LIMIT_BYTES)


def dropped_response_bodies_hint(count: int, limit: int) -> str:
    """「有响应体被整条丢弃」的可行动提示。

    只说三件事：丢了多少、因此缺了什么、**下一步具体怎么做**。补救手段是
    ``start_capture`` 的 ``response_limit_bytes`` 参数（提示语里给一个可照抄的值），
    而**不是**让使用者去设环境变量 —— 提示的读者是服务与 Agent，非技术使用者做不了、
    也不需要做「设环境变量」这件事。因此这里对 Agent 说话：调哪个工具、传什么值。
    """
    if count <= 0:
        return ""
    suggested = _suggested_limit(limit)
    if suggested is None:
        remedy = (f"当前上限已经是允许的最大值（{_human_bytes(MAX_RESPONSE_LIMIT_BYTES)}），"
                  "没法再调大：这些接口的响应体本身就超过本工具的设计上限。"
                  "请如实告诉用户「这几个接口拿不到返回结构」。")
    else:
        remedy = ("如果这些接口对使用者重要，请重新抓一轮并把上限调大：重新调用 "
                  f"start_capture 时多传一个参数 response_limit_bytes={suggested}"
                  f"（{_human_bytes(suggested)}）即可，抓完再跑一次 analyze_traffic。")
    return (f"本次抓包有 {count} 个响应体超过大小上限（当前 {_human_bytes(limit)}），"
            "为了不撑爆磁盘被**整条丢弃**，因此这些接口的响应结构无法推断"
            f"（生成的工具可能缺少返回字段说明）。{remedy}用不到的接口可以忽略。")


def _env_int(name: str, default: int) -> int:
    """读取整数环境变量；未设置时用默认值。

    D4：``int(os.environ.get(...))`` 遇到 ``"abc"`` 会抛裸 ``ValueError``，
    在模块被 import 时就把 MCP 服务整死，且看不出是哪个变量写错了。这里改为
    抛出点名变量与坏值的清晰 ``ValueError``。
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except (TypeError, ValueError):
        raise ValueError(
            f"{name} must be an integer, got {raw!r} (default: {default})"
        ) from None


def _env_choice(name: str, default: str, allowed: tuple[str, ...]) -> str:
    """读取**取值受限于枚举**的环境变量；未设置时用默认值。

    与 ``_env_int`` 同一原则：非法值抛**点名变量、坏值与合法取值**的清晰
    ``ValueError``，而不是让它悄悄退化成一个猜出来的模式（抓包浏览器跟不跟系统代理
    会直接决定请求通不通，猜错极难归因）。大小写与首尾空白都容忍。
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value not in allowed:
        raise ValueError(
            f"{name} must be one of {list(allowed)}, got {raw!r} (default: {default})"
        )
    return value


@dataclass(frozen=True)
class Settings:
    data_root: Path
    response_body_limit: int = 256 * 1024
    idle_timeout_seconds: int = 5 * 60
    max_sessions: int = 3
    # Issue #2: 分析期的体积/频次启发式阈值（标记待复核，不删除）。
    noise_response_bytes: int = 1024 * 1024
    noise_sample_count: int = 50
    # 抓包浏览器（Chromium）的代理模式：auto（默认，先直连，代理类失败自动回退系统代理）
    # / direct（只直连）/ system（只跟随系统代理）。
    proxy_mode: str = DEFAULT_PROXY_MODE

    @classmethod
    def from_environment(cls) -> "Settings":
        root = Path(os.environ.get("SCRY_DATA", "~/.scry")).expanduser()
        response_limit = _env_int(RESPONSE_LIMIT_ENV, 256 * 1024)
        idle_timeout = _env_int("SCRY_IDLE_TIMEOUT", 5 * 60)
        max_sessions = _env_int("SCRY_MAX_SESSIONS", 3)
        noise_bytes = _env_int("SCRY_NOISE_RESPONSE_BYTES", 1024 * 1024)
        noise_samples = _env_int("SCRY_NOISE_SAMPLE_COUNT", 50)
        proxy_mode = _env_choice("SCRY_PROXY_MODE", DEFAULT_PROXY_MODE, PROXY_MODES)
        if response_limit <= 0 or idle_timeout <= 0 or max_sessions <= 0:
            raise ValueError("Extractor limits must be positive")
        if noise_bytes <= 0 or noise_samples <= 0:
            raise ValueError("Extractor noise thresholds must be positive")
        return cls(root, response_limit, idle_timeout, max_sessions, noise_bytes,
                   noise_samples, proxy_mode)

    @property
    def browser_proxy_args(self) -> list[str]:
        """Chromium 启动参数里与代理有关的部分（``auto`` / ``direct`` → 直连标志；``system`` → 空）。

        ``auto`` 是默认，与 ``direct`` 的**启动参数相同**（都从直连开始）：Chromium 不加
        这条就会静默跟随系统代理，非回环主机的请求被代理吃掉后只表现为难归因的
        ``net::ERR_EMPTY_RESPONSE``。两者的差别只在**失败之后**：``auto`` 会自动改用
        系统代理重试一次（见 ``proxy_env.fallback_proxy_mode``），``direct`` 不回退。
        """
        return browser_proxy_args(self.proxy_mode)

    @property
    def sessions_dir(self) -> Path:
        return self.data_root / "sessions"

    @property
    def auth_states_dir(self) -> Path:
        return self.data_root / "auth_states"

    @property
    def instances_dir(self) -> Path:
        """S8：运行中实例的身份/心跳目录（同一数据根可能被多个实例共享）。"""
        return self.data_root / "instances"

    @property
    def audit_path(self) -> Path:
        return self.data_root / "audit.log"

    def ensure_directories(self) -> None:
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.auth_states_dir.mkdir(parents=True, exist_ok=True)
        self.instances_dir.mkdir(parents=True, exist_ok=True)
        readme = self.auth_states_dir / "README.txt"
        if not readme.exists():
            readme.write_text(
                "This directory contains credentials. Do not commit, sync, or screenshot it.\n",
                encoding="utf-8",
            )
        gitignore = self.auth_states_dir / ".gitignore"
        if not gitignore.exists():
            gitignore.write_text("*\n!.gitignore\n!README.txt\n", encoding="utf-8")