# -*- coding: utf-8 -*-
"""脱离父进程启动 HTTP MCP 服务（Windows / POSIX 通用）。

## 为什么需要这个脚本

直接用「后台任务」方式启动 run_http.py 时，服务进程仍位于宿主 shell 的
**job object** 内。宿主回收该 shell 时，Windows 会连带终止 job 内的所有进程——
包括服务本身，以及它通过 Playwright 拉起的 Chromium 子进程。

症状：浏览器窗口**一闪即消失**，端口失去监听，而服务日志末尾完全正常
（属被外部终止，不是自身崩溃）。用户容易误判成"目标网站有问题"。

本脚本用 DETACHED_PROCESS + CREATE_NEW_PROCESS_GROUP + CREATE_BREAKAWAY_FROM_JOB
让服务彻底脱离，并把日志与 PID 落盘。

## 用法

    python start_server.py            # 启动（已在跑则跳过）
    python start_server.py --stop     # 停止
    python start_server.py --status   # 查看状态

    python start_server.py --port 8423    # 换端口
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOG = ROOT / "server.log"
PIDFILE = ROOT / ".server_pid"

# Windows 进程创建标志
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000

IS_WIN = sys.platform == "win32"


def _python() -> Path:
    """优先用技能自带的 .venv，回退到当前解释器。"""
    for rel in (("Scripts", "python.exe"), ("bin", "python")):
        candidate = ROOT / ".venv" / rel[0] / rel[1]
        if candidate.exists():
            return candidate
    return Path(sys.executable)


def _probe_url(port: int) -> str:
    return f"http://127.0.0.1:{port}/mcp"


def alive(port: int = 8422) -> bool:
    """服务是否在监听。任何 HTTP 响应（含 4xx）都说明活着。"""
    try:
        urllib.request.urlopen(_probe_url(port), timeout=2)
        return True
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False


def read_pid() -> int | None:
    if not PIDFILE.exists():
        return None
    try:
        return int(PIDFILE.read_text().strip())
    except (OSError, ValueError):
        return None


def pid_alive(pid: int) -> bool:
    """跨平台的进程存活判定。"""
    if IS_WIN:
        try:
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                                 capture_output=True, text=True, timeout=15).stdout
            return str(pid) in out
        except (OSError, subprocess.SubprocessError):
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def stop(port: int = 8422) -> int:
    pid = read_pid()
    if pid is None:
        print("没有记录的服务 PID（可能未经本脚本启动）")
        return 1
    if not pid_alive(pid):
        print(f"记录的进程 {pid} 已不存在，清理 PID 文件")
        PIDFILE.unlink(missing_ok=True)
        return 0

    if IS_WIN:
        subprocess.call(["taskkill", "/F", "/PID", str(pid)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        os.kill(pid, 15)
    time.sleep(1)
    if pid_alive(pid):
        print(f"进程 {pid} 未能终止")
        return 1
    PIDFILE.unlink(missing_ok=True)
    print(f"已停止服务 PID {pid}")
    return 0


def status(port: int = 8422) -> int:
    pid = read_pid()
    running = alive(port)
    print(f"端口 {port} 监听中: {'是' if running else '否'}")
    print(f"记录的 PID:     {pid if pid is not None else '（无）'}")
    if pid is not None:
        print(f"进程存活:       {'是' if pid_alive(pid) else '否'}")
    if LOG.exists():
        age = time.time() - LOG.stat().st_mtime
        print(f"日志:           {LOG}  (最后写入 {age / 60:.1f} 分钟前)")
    return 0 if running else 1


def start(port: int = 8422, wait: int = 30) -> int:
    if alive(port):
        print(f"端口 {port} 已有服务在监听，跳过启动")
        return 0

    py = _python()
    if not py.exists():
        raise SystemExit(f"找不到 Python 解释器：{py}（先跑 bootstrap.py）")

    flags = 0
    if IS_WIN:
        flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB

    log = LOG.open("ab")
    argv = [str(py), str(ROOT / "run_http.py")]
    if port != 8422:
        argv += ["--port", str(port)]

    def spawn(creationflags: int) -> subprocess.Popen:
        return subprocess.Popen(
            argv, cwd=str(ROOT), stdout=log, stderr=log, stdin=subprocess.DEVNULL,
            creationflags=creationflags, close_fds=True,
            start_new_session=not IS_WIN,   # POSIX 下等价于脱离父会话
        )

    try:
        proc = spawn(flags)
    except OSError as exc:
        # 某些环境不允许 breakaway（父 job 未设 JOB_OBJECT_LIMIT_BREAKAWAY_OK）
        print(f"breakaway 启动失败（{exc}），退化为普通 detach")
        proc = spawn(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)

    PIDFILE.write_text(str(proc.pid))

    for _ in range(max(1, wait * 2)):
        time.sleep(0.5)
        if alive(port):
            print(f"服务已启动 PID {proc.pid} -> {_probe_url(port)}")
            print(f"日志：{LOG}")
            return 0
    print(f"启动后 {wait} 秒仍未监听，请查看日志：{LOG}")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8422, help="监听端口（默认 8422）")
    ap.add_argument("--stop", action="store_true", help="停止服务")
    ap.add_argument("--status", action="store_true", help="查看状态")
    args = ap.parse_args()

    if args.stop:
        return stop(args.port)
    if args.status:
        return status(args.port)
    return start(args.port)


if __name__ == "__main__":
    raise SystemExit(main())
