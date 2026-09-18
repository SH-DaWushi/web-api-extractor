# -*- coding: utf-8 -*-
"""Environment self-check / bootstrap helper for web-api-extractor.

Usage:
    python -m webapi_extractor doctor            # only check, print a report
    python -m webapi_extractor doctor --install   # check, then install what's missing

Checks: Python version, required packages, Playwright Chromium kernel,
writable data dir, and whether the local HTTP port (8422) is free.
"""
from __future__ import annotations

import importlib.util
import socket
import subprocess
import sys
from pathlib import Path

REQUIRED = ["fastmcp", "httpx", "jinja2", "playwright"]
HTTP_PORT = 8422

OK = "[ OK ]"
BAD = "[FAIL]"
WARN = "[WARN]"


def _print(status: str, msg: str) -> None:
    print(f"{status} {msg}")


def check_python() -> bool:
    good = sys.version_info >= (3, 10)
    _print(OK if good else BAD, f"Python {sys.version.split()[0]} (需要 >= 3.10)")
    return good


def check_packages() -> list[str]:
    missing = []
    for mod in REQUIRED:
        if importlib.util.find_spec(mod) is None:
            missing.append(mod)
            _print(BAD, f"缺少依赖包: {mod}")
        else:
            _print(OK, f"依赖包已安装: {mod}")
    return missing


def check_chromium() -> bool:
    if importlib.util.find_spec("playwright") is None:
        _print(WARN, "playwright 未安装，跳过 Chromium 检查")
        return False
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            exe = Path(p.chromium.executable_path)
        if exe.exists():
            _print(OK, f"Chromium 内核已就绪: {exe.name}")
            return True
        _print(BAD, f"Chromium 内核缺失: {exe}")
        return False
    except Exception as exc:  # noqa: BLE001
        _print(BAD, f"Chromium 检查失败: {type(exc).__name__}: {exc}")
        return False


def check_data_dir() -> bool:
    from .config import Settings

    try:
        settings = Settings.from_environment()
        settings.ensure_directories()
        probe = settings.data_root / ".doctor_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        _print(OK, f"数据目录可写: {settings.data_root}")
        return True
    except Exception as exc:  # noqa: BLE001
        _print(BAD, f"数据目录不可用: {type(exc).__name__}: {exc}")
        return False


def check_port() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        in_use = sock.connect_ex(("127.0.0.1", HTTP_PORT)) == 0
    if in_use:
        _print(WARN, f"端口 {HTTP_PORT} 已被占用（可能服务已在运行，或需换端口）")
        return False
    _print(OK, f"端口 {HTTP_PORT} 空闲")
    return True


def install(missing: list[str], chromium_missing: bool) -> None:
    if missing:
        print(f"\n>>> 安装缺失依赖: {' '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", *missing])
    if chromium_missing:
        print("\n>>> 安装 Playwright Chromium 内核（较大，请耐心等待）")
        subprocess.check_call([sys.executable, "-m", "playwright", "install", "chromium"])


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    do_install = "--install" in argv
    print("=" * 56)
    print("web-api-extractor 环境自检 (doctor)")
    print("=" * 56)
    py_ok = check_python()
    missing = check_packages()
    chromium_ok = check_chromium()
    data_ok = check_data_dir()
    port_ok = check_port()

    if do_install and (missing or not chromium_ok):
        install(missing, not chromium_ok)
        print("\n--- 安装后复检 ---")
        missing = check_packages()
        chromium_ok = check_chromium()

    ready = py_ok and not missing and chromium_ok and data_ok
    print("=" * 56)
    if ready:
        print("环境就绪。下一步：python run_http.py 启动服务，再用 mcp_call.py 驱动工具。")
        print(f"（端口 {'空闲' if port_ok else '被占用，注意确认'}）")
        return 0
    print("环境未就绪。可运行: python -m webapi_extractor doctor --install 自动修复。")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
