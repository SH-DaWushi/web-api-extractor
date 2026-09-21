# -*- coding: utf-8 -*-
"""系统原生「是 / 否」确认对话框。

登录与抓包两个环节都需要「问用户一句是/否」，且都不该依赖注入目标页面的
脚本（CSP / iframe / 跨域弹窗都会让页内控件失效）。此处收敛为单一实现，
避免两处各自复制一份、再各自跑偏。

约定：

* **只在调用方明确请求时弹出。** 绝不在打开浏览器时自行弹出——用户那时还没
  登录，弹出来只会被点「否」；旧实现正是这样：点「否」不改变任何状态，
  对话框本身也再不会出现，等于白弹。
* 返回 ``True`` / ``False``；**无法显示对话框时返回 ``None``**（无图形环境、
  平台不支持、调用异常），调用方据此降级为「在对话里问用户」。
* 阻塞式，且在 **daemon** 线程上运行：用户永不作答也不会拖住事件循环退出
  （默认 executor 是非 daemon 的，会拖住）。
"""
from __future__ import annotations

import asyncio
import sys
from typing import Callable, TypeVar

_T = TypeVar("_T")

DEFAULT_TITLE = "WebAPIExtractor 确认"


def ask_yes_no(prompt: str, title: str = DEFAULT_TITLE) -> bool | None:
    """阻塞地弹出系统对话框。返回 True/False；无法显示时返回 None。"""
    try:
        if sys.platform == "win32":
            import ctypes

            # 4 = Yes/No，0x20 = question icon，0x40000 = topmost
            answer = ctypes.windll.user32.MessageBoxW(0, prompt, title, 4 | 0x20 | 0x40000)
            if answer == 6:  # IDYES
                return True
            if answer == 7:  # IDNO
                return False
            return None
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        try:
            return bool(messagebox.askyesno(title, prompt))
        finally:
            root.destroy()
    except Exception:
        return None


async def run_blocking(function: Callable[[], _T]) -> _T:
    """在 daemon 线程上跑一个阻塞函数，并 await 它的返回值。"""
    import threading

    loop = asyncio.get_running_loop()
    future: asyncio.Future[_T] = loop.create_future()

    def _worker() -> None:
        result = function()
        try:
            loop.call_soon_threadsafe(lambda: None if future.done() else future.set_result(result))
        except RuntimeError:
            pass  # 事件循环已关闭，没人再等这个结果

    threading.Thread(target=_worker, daemon=True, name="wae-confirm-dialog").start()
    return await future


async def ask_yes_no_async(prompt: str, title: str = DEFAULT_TITLE) -> bool | None:
    """``ask_yes_no`` 的协程版，便于直接 await 用户的点选。"""
    return await run_blocking(lambda: ask_yes_no(prompt, title))
