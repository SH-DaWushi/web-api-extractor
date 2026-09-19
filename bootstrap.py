# -*- coding: utf-8 -*-
"""纯 Python 一键环境引导（E-1：不依赖 PowerShell/bash，受限环境可用）。

用法：
    python bootstrap.py [--install]

做四件事：创建独立 .venv → 装依赖 → 装 Playwright Chromium → 跑 doctor 自检。
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> int:
    do_install = "--install" in sys.argv[1:]
    venv_dir = ROOT / ".venv"
    venv_py = venv_dir / ("Scripts" / "python.exe" if sys.platform == "win32" else "bin" / "python")

    print(">> [1/4] 创建虚拟环境 .venv（隔离全局 site-packages）")
    if not venv_py.exists():
        subprocess.check_call([sys.executable, "-m", "venv", str(venv_dir)])
    else:
        print("   已存在，跳过")

    print(">> [2/4] 安装依赖 (requirements.txt)")
    subprocess.check_call([str(venv_py), "-m", "pip", "install", "--disable-pip-version-check",
                           "--upgrade", "pip"])
    subprocess.check_call([str(venv_py), "-m", "pip", "install", "--disable-pip-version-check",
                           "-r", str(ROOT / "requirements.txt")])

    print(">> [3/4] 安装 Playwright Chromium 内核（较大，请稍候）")
    subprocess.check_call([str(venv_py), "-m", "playwright", "install", "chromium"])

    print(">> [4/4] 运行环境自检 doctor")
    rc = subprocess.call([str(venv_py), "-m", "webapi_extractor", "doctor",
                          *(["--install"] if do_install else [])], cwd=str(ROOT))

    print()
    print("引导完成。后续用法：")
    print(f"  启动服务:  {venv_py} run_http.py")
    print(f"  调用工具:  {venv_py} mcp_call.py <tool_name> '<json-args>'")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
