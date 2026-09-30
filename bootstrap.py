# -*- coding: utf-8 -*-
"""纯 Python 一键环境引导（E-1：不依赖 PowerShell/bash，受限环境可用）。

用法：
    python bootstrap.py [--with-tests] [--install]

做四件事：创建独立 venv → 装依赖 → 装 Playwright Chromium → 跑 doctor 自检。

venv 位置：**数据目录**下的 ``<data_root>/venv``，而不是技能目录里的 ``.venv``。
数据目录由 ``SCRY_DATA`` 指定，默认 ``~/.scry``（复用
``scry_mcp_gen.config`` 的权威定义）。技能目录由宿主应用管理，升级时会被重新
同步/替换 —— 把约 180 MB 的 venv 放在里面既可能被连带删除，又重新拉一次 Chromium。
已装过的部署若在技能目录里留有历史的 ``ROOT/.venv``，则直接**复用它**（打印提示），
不会再建第二份。

运行时依赖见 ``requirements.txt``（只有 fastmcp / httpx / playwright）；测试运行器
另放 ``requirements-dev.txt``，用 ``--with-tests`` 显式安装，普通使用者不会被装上 pytest。
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# 历史版本把 venv 建在技能目录内；检到就复用，避免同一台机器上出现两份环境。
LEGACY_VENV = ROOT / ".venv"

# 引导常由 Agent 代跑：那时父进程没有控制台，而 python -m pip / playwright 都是
# **控制台**程序，Windows 会为每一个子进程新建一个黑色窗口。加这个标志就不建。
# 输出照旧：子进程继承父进程的 std 句柄，pip 的进度仍然打在原处。
# 非 Windows 必须传 0 —— POSIX 上 subprocess 不接受非零 creationflags。
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0


def _data_root() -> Path:
    """数据目录：优先复用 ``scry_mcp_gen.config`` 的权威定义。

    仅当 config 不可导入（例如 bootstrap.py 被单独分发）或 ``from_environment``
    因**其它**数值型变量（response limit / idle timeout …）写坏而抛错时才退回默认值 ——
    一个坏掉的无关环境变量不该让引导脚本直接失败。
    """
    try:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from scry_mcp_gen.config import Settings

        return Settings.from_environment().data_root
    except Exception:
        return Path(os.environ.get("SCRY_DATA", "~/.scry")).expanduser()


def _venv_python(venv_dir: Path) -> Path:
    """venv 里解释器的路径（Windows 与 POSIX 目录名不同）。

    注意：不能写成 ``venv_dir / ("Scripts" / "python.exe" if ...)`` —— 括号内先求值的
    是字符串除法，Windows 下必抛 TypeError。必须分开拼接。
    """
    venv_bin = "Scripts" if sys.platform == "win32" else "bin"
    venv_exe = "python.exe" if sys.platform == "win32" else "python"
    return venv_dir / venv_bin / venv_exe


def main() -> int:
    argv = sys.argv[1:]
    do_install = "--install" in argv
    with_tests = "--with-tests" in argv

    if _venv_python(LEGACY_VENV).exists():
        venv_dir = LEGACY_VENV
        print(">> 检测到技能目录内的旧版 venv（历史遗留），直接复用，不再新建")
    else:
        venv_dir = _data_root() / "venv"
    venv_py = _venv_python(venv_dir)

    print(f">> [1/4] 虚拟环境目录：{venv_dir}（隔离全局 site-packages）")
    print(f"         解释器：{venv_py}")
    if not venv_py.exists():
        venv_dir.parent.mkdir(parents=True, exist_ok=True)
        subprocess.check_call([sys.executable, "-m", "venv", str(venv_dir)],
                              creationflags=NO_WINDOW)
    else:
        print("         已存在，跳过创建")

    print(">> [2/4] 安装运行依赖 (requirements.txt)")
    subprocess.check_call([str(venv_py), "-m", "pip", "install", "--disable-pip-version-check",
                           "--upgrade", "pip"], creationflags=NO_WINDOW)
    subprocess.check_call([str(venv_py), "-m", "pip", "install", "--disable-pip-version-check",
                           "-r", str(ROOT / "requirements.txt")], creationflags=NO_WINDOW)
    if with_tests:
        print(">> 追加安装测试依赖 (requirements-dev.txt)")
        subprocess.check_call([str(venv_py), "-m", "pip", "install", "--disable-pip-version-check",
                               "-r", str(ROOT / "requirements-dev.txt")], creationflags=NO_WINDOW)

    print(">> [3/4] 安装 Playwright Chromium 内核（较大，请稍候）")
    subprocess.check_call([str(venv_py), "-m", "playwright", "install", "chromium"],
                          creationflags=NO_WINDOW)

    print(">> [4/4] 运行环境自检 doctor")
    rc = subprocess.call([str(venv_py), "-m", "scry_mcp_gen", "doctor",
                          *(["--install"] if do_install else [])], cwd=str(ROOT),
                         creationflags=NO_WINDOW)

    print()
    print("引导完成。后续用法（请用上面那个解释器路径，不要用全局 python）：")
    print(f"  启动服务:  {venv_py} start_server.py")
    print(f"  调用工具:  {venv_py} mcp_call.py <tool_name> '<json-args>'")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
