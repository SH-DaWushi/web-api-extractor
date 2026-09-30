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
    python start_server.py --stop     # 停止（按进程树；先校验 PID 归属）
    python start_server.py --status   # 查看状态

    python start_server.py --stop --force   # 跳过 PID 归属校验（谨慎：确认过再用）

    python start_server.py --port 8423    # 换端口
"""
from __future__ import annotations

import argparse
import os
import re
import signal
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

# S2：停止服务后「端口真的空出来了」的有界等待与轮询间隔（秒）。
_PORT_FREE_TIMEOUT = 10.0
_PORT_FREE_INTERVAL = 0.5


def _python() -> Path:
    """按「数据目录 venv → 技能目录旧版 .venv → 当前解释器」的顺序挑一个解释器。

    bootstrap.py 现在把 venv 建在数据目录下（技能目录会被宿主应用重新同步），
    但仍兼容历史部署留在技能目录里的 ``ROOT/.venv``。
    """
    try:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from webapi_extractor.config import Settings

        data_root = Settings.from_environment().data_root
    except Exception:
        # config 不可导入，或某个无关的数值型环境变量写坏 —— 退回同一条默认规则。
        data_root = Path(os.environ.get("WEB_API_EXTRACTOR_DATA", "~/.webapiextractor")).expanduser()

    for venv_dir in (data_root / "venv", ROOT / ".venv"):
        for rel in (("Scripts", "python.exe"), ("bin", "python")):
            candidate = venv_dir / rel[0] / rel[1]
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


def _run_capture(argv: list[str]) -> str | None:
    """跑一条只读探测命令并取回 stdout；任何失败都返回 None（永不抛异常）。"""
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout or None


def _clean_process_listing(output: str | None) -> str | None:
    """去掉空行与表头（wmic 会打 ``CommandLine`` 表头）后的文本；空则 None。"""
    if not output:
        return None
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    lines = [line for line in lines if line.lower() != "commandline"]
    return " ".join(lines) or None


def _parse_netstat_listener(output: str | None, port: int) -> int | None:
    """从 ``netstat -ano`` 输出里找出监听 port 的 PID（纯函数，便于单测）。"""
    if not output:
        return None
    for line in output.splitlines():
        fields = line.split()
        # Proto  Local Address  Foreign Address  State  PID
        if len(fields) < 5 or fields[0].upper() != "TCP" or fields[3].upper() != "LISTENING":
            continue
        local = fields[1]
        if not local.rsplit(":", 1)[-1].isdigit() or int(local.rsplit(":", 1)[-1]) != port:
            continue
        if fields[4].isdigit():
            return int(fields[4])
    return None


def _parse_ss_listener(output: str | None, port: int) -> int | None:
    """从 ``ss -ltnp`` 输出里找出监听 port 的 PID（纯函数，便于单测）。"""
    if not output:
        return None
    for line in output.splitlines():
        fields = line.split()
        # State Recv-Q Send-Q Local:Port Peer:Port Process
        if len(fields) < 5 or fields[0].upper() != "LISTEN":
            continue
        if fields[3].rsplit(":", 1)[-1] != str(port):
            continue
        match = re.search(r"pid=(\d+)", line)
        if match:
            return int(match.group(1))
    return None


def port_holder_pid(port: int) -> int | None:
    """当前**真正**监听 port 的进程 PID；无法判定时返回 None（永不抛异常）。

    S2 的关键：``.server_pid`` 记的是启动器（父进程），真正的监听者往往是它的
    子进程。判定「谁还占着端口」必须直接问操作系统，而不是看记录的 PID。
    """
    if IS_WIN:
        return _parse_netstat_listener(_run_capture(["netstat", "-ano", "-p", "TCP"]), port)
    listing = _clean_process_listing(
        _run_capture(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"]))
    if listing:
        first = listing.split()[0]
        if first.isdigit():
            return int(first)
    return _parse_ss_listener(_run_capture(["ss", "-ltnp"]), port)


def process_command_line(pid: int) -> str | None:
    """尽力取回 pid 的命令行；取不到返回 None（永不抛异常，也不阻止流程）。"""
    if IS_WIN:
        attempts = (
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine"],
            ["wmic", "process", "where", f"processid={pid}", "get", "CommandLine"],
        )
        for argv in attempts:
            text = _clean_process_listing(_run_capture(argv))
            if text:
                return text
        return None
    return _clean_process_listing(_run_capture(["ps", "-p", str(pid), "-o", "command="]))


def is_project_server_command(command_line: str | None) -> bool | None:
    """该命令行是否属于本项目的服务（run_http.py）。

    True / False = 已确认；None = 无法确认（取不到命令行）——调用方此时**不得**
    盲杀。S2：陈旧的 ``.server_pid`` 加上 OS 复用 PID，会把 ``taskkill /F``
    指向一个无关进程。
    """
    if not command_line or not command_line.strip():
        return None
    lowered = command_line.lower().replace("\\", "/")
    root = str(ROOT).lower().replace("\\", "/")
    if root in lowered or "run_http.py" in lowered:
        return True
    return False


def verify_project_pid(pid: int) -> bool | None:
    """确认 pid 是不是本项目的服务进程；取不到命令行时返回 None。"""
    return is_project_server_command(process_command_line(pid))


def _signal_process_group(pid: int, sig: int) -> None:
    """POSIX：结束整个进程组（服务是用 start_new_session 起的组长）。"""
    try:
        pgid = os.getpgid(pid)
    except OSError:
        pgid = pid
    getpgrp = getattr(os, "getpgrp", None)
    own_group = getpgrp() if getpgrp else None
    try:
        if pgid > 0 and pgid != own_group:
            os.killpg(pgid, sig)
        else:
            os.kill(pid, sig)
    except OSError:
        try:
            os.kill(pid, sig)
        except OSError:
            pass


def _kill_tree(pid: int, *, force: bool = False) -> None:
    """终止 pid **及其子进程**；永不抛异常。

    S2：旧实现在 Windows 上只 ``taskkill /F /PID <launcher>``（**没有 /T**），
    子进程存活、端口照旧被占，函数却按「记录的 PID 是否还活着」判定成功。
    """
    try:
        if IS_WIN:
            subprocess.call(["taskkill", "/F", "/T", "/PID", str(pid)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            _signal_process_group(pid, signal.SIGKILL if force else signal.SIGTERM)
    except OSError:
        pass


def wait_port_free(port: int = 8422, timeout: float = _PORT_FREE_TIMEOUT,
                   interval: float = _PORT_FREE_INTERVAL) -> bool:
    """有界等待端口释放，返回它是否真的空了（成功与否的唯一判据）。"""
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        if not alive(port):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def _port_holder_lines(port: int, verb: str = "占用") -> list[str]:
    """告诉用户「谁占着端口、该怎么办」，而不是一句跳过启动。"""
    holder = port_holder_pid(port)
    if holder is None:
        return [f"  未能识别{verb}端口 {port} 的进程，可手动排查：",
                f"    Windows: netstat -ano | findstr :{port}",
                f"    macOS/Linux: lsof -nP -iTCP:{port} -sTCP:LISTEN"]
    recorded = read_pid()
    lines = [f"  {verb}端口 {port} 的进程 PID：{holder}"]
    if recorded is None:
        lines.append("  .server_pid 没有记录 —— 该服务可能不是用本脚本启动的。")
    elif recorded != holder:
        lines.append(f"  .server_pid 记录的是 {recorded}：那是启动器（父进程），"
                     f"{holder} 才是真正的监听者。")
    lines.append("  处理方式：先把占用者停下来（`python start_server.py --stop` 会按进程树"
                 "停止并校验 PID 归属），或换端口：`python start_server.py --port 8423`")
    return lines


def stop(port: int = 8422, *, force: bool = False) -> int:
    """停止服务；成功与否只看**端口是否真的释放**。

    S2：``.server_pid`` 记的是 launcher，真正的监听者是它的子进程，所以

      * Windows 上按**进程树**结束（``taskkill /F /T``），POSIX 上结束整个进程组；
      * 不再用「记录的 PID 还活着吗」判定成功——旧逻辑在子进程仍占着端口时
        打印「已停止服务」并删掉 PID 文件，用户随后既停不掉也起不来；
      * 强杀前先确认该 PID 确实在跑本项目的 ``run_http.py``，避免陈旧 PID 文件
        叠加 PID 复用误杀无关进程；无法确认时只报告、不盲杀（``--force`` 可越过）。
    """
    pid = read_pid()

    if pid is None:
        print("没有记录的服务 PID（可能未经本脚本启动）")
        if alive(port):
            print(f"但端口 {port} 仍被占用：")
            for line in _port_holder_lines(port):
                print(line)
        return 1

    if not pid_alive(pid):
        print(f"记录的进程 {pid} 已不存在，清理 PID 文件")
        PIDFILE.unlink(missing_ok=True)
        if alive(port):
            # 记录的 launcher 已死，但它的子进程还占着端口——旧实现此处报「成功」。
            print(f"但端口 {port} 仍被占用，停止未完成：")
            for line in _port_holder_lines(port):
                print(line)
            return 1
        return 0

    if not force:
        confirmed = verify_project_pid(pid)
        if confirmed is None:
            print(f"无法确认 PID {pid} 的身份（取不到它的命令行），为安全起见不执行强杀。")
            print("确认它确实是本项目服务后，可用：python start_server.py --stop --force")
            for line in _port_holder_lines(port):
                print(line)
            return 1
        if not confirmed:
            print(f"记录的 PID {pid} 不属于本项目（命令行里没有 run_http.py / {ROOT}），")
            print("拒绝终止它；已清理这个陈旧的 PID 文件。")
            for line in _port_holder_lines(port):
                print(line)
            PIDFILE.unlink(missing_ok=True)
            return 1

    _kill_tree(pid)
    freed = wait_port_free(port)
    if not freed and pid_alive(pid):
        # POSIX 下 SIGTERM 可能被忽略：升级为 SIGKILL（只在进程确实还活着时升级，
        # 避免对已被复用的 PID 补刀）。
        _kill_tree(pid, force=True)
        freed = wait_port_free(port)

    if not freed:
        holder = port_holder_pid(port)
        where = f"PID {holder}" if holder is not None else "未能识别占用者"
        print(f"PID {pid} 已终止，但端口 {port} 仍被占用（{where}）——停止未完成。")
        print("可手动结束该进程，或换端口：python start_server.py --port 8423")
        PIDFILE.unlink(missing_ok=True)
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
        # S2：不再只说「跳过启动」——用户可能正卡在「停不掉也起不来」的陷阱里，
        # 必须知道是谁占着端口、下一步怎么做。
        print(f"端口 {port} 已有服务在监听，跳过启动")
        for line in _port_holder_lines(port, verb="监听"):
            print(line)
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
    ap.add_argument("--force", action="store_true",
                    help="停止时跳过 PID 归属校验（仅在你已确认该 PID 是本项目服务时使用）")
    args = ap.parse_args()

    if args.stop:
        return stop(args.port, force=args.force)
    if args.status:
        return status(args.port)
    return start(args.port)


if __name__ == "__main__":
    raise SystemExit(main())
