# -*- coding: utf-8 -*-
"""结构性守卫：产品代码里的每一个子进程都不得弹出黑色控制台窗口。

## 为什么需要这条守卫

Windows 上 `python.exe` / `pip` / `playwright` / `tasklist` / `netstat` /
`powershell` / `taskkill` 全是**控制台**程序。当父进程**自己也没有控制台**时
（宿主 Cherry Studio / Claude 静默拉起服务，正是本技能的常态），CreateProcess
默认会给子进程**新建一个控制台窗口** —— 用户看到的就是「一启动服务就弹黑框」
「一操作就闪过一个黑框」。

唯一的解法是给每个 spawn 传 `creationflags=CREATE_NO_WINDOW`（非 Windows 传 0，
POSIX 上非零会 ValueError）。这条守卫把「每个 spawn 都带了标志」钉死：
新写一处 `subprocess.run(...)` 而忘了标志，这里就会红。

判据只看**结构**（每个 spawn 调用的括号内是否出现 `creationflags=`），
不锁具体写法 —— 常量名、内联表达式、`flags=` 变量都算数。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# 会被用户直接跑到的入口：顶层脚本 + 包内会 spawn 的模块 + 生成物模板。
# 只有**真的 spawn** 的文件才进这张表：`bootstrap.ps1` 是 `& $py bootstrap.py`
# 的薄封装（跑在调用者自己的控制台里，不新建窗口），`run_http.py` / `mcp_call.py`
# 也不 spawn —— 把它们列进来只会让守卫空转。
GUARDED = (
    ROOT / "bootstrap.py",
    ROOT / "start_server.py",
    ROOT / "webapi_extractor" / "doctor.py",
    ROOT / "webapi_extractor" / "generator.py",
)

_SPAWN = re.compile(r"subprocess\.(run|call|check_call|check_output|Popen)\s*\(")


def _call_arguments(text: str, open_paren: int) -> str | None:
    """取出 ``open_paren`` 那对括号里的实参原文（含嵌套括号）；不配对返回 None。"""
    depth = 0
    for index in range(open_paren, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:index]
    return None


def _spawn_calls(path: Path) -> list[str]:
    """文件里所有 subprocess.spawn 调用的实参原文。"""
    text = path.read_text(encoding="utf-8")
    calls = []
    for match in _SPAWN.finditer(text):
        arguments = _call_arguments(text, match.end() - 1)
        if arguments is not None:
            calls.append(arguments)
    return calls


class TestEverySpawnIsWindowless:
    def test_guarded_files_all_spawn_something(self):
        """守卫本身不能空转：这些文件里必须真的有 spawn，否则等于没测。"""
        for path in GUARDED:
            assert _spawn_calls(path), f"{path.name} 里一个 subprocess 调用都没找到 —— 守卫失效了"

    def test_no_spawn_without_creationflags(self):
        offenders = []
        for path in GUARDED:
            for arguments in _spawn_calls(path):
                if "creationflags=" not in arguments:
                    head = " ".join(arguments.split())[:90]
                    offenders.append(f"{path.relative_to(ROOT)}: {head}")
        assert not offenders, (
            "这些子进程没带 creationflags —— Windows 上会弹出黑色控制台窗口：\n  "
            + "\n  ".join(offenders)
        )

    def test_generated_server_installs_are_windowless(self):
        """生成物模板里的 pip / playwright 补装也必须静默。

        `generator.py` 里那两段是**发到用户机器上**的代码：用户拿到的 MCP 服务在
        启动时会补装 playwright / Chromium，那正是「服务一启动就弹黑框」的来源。
        """
        template = (ROOT / "webapi_extractor" / "generator.py").read_text(encoding="utf-8")
        for needle in ('"-m", "pip", "install"', '"-m", "playwright", "install", "chromium"'):
            assert needle in template, f"生成物模板里找不到补装调用：{needle}"
        assert template.count("CREATE_NO_WINDOW") >= 2, \
            "生成物模板里的两处补装至少要有两处 CREATE_NO_WINDOW"

    def test_non_windows_passes_zero(self):
        """POSIX 上 creationflags 必须为 0，否则 subprocess 直接 ValueError。"""
        for path in (ROOT / "bootstrap.py", ROOT / "start_server.py",
                     ROOT / "webapi_extractor" / "doctor.py"):
            text = path.read_text(encoding="utf-8")
            assert 'if sys.platform == "win32" else 0' in text or \
                   'if IS_WIN else 0' in text, f"{path.name} 没有做非 Windows 归零"
