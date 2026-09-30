# -*- coding: utf-8 -*-
"""`doctor` 环境自检（reference 的「测试」一节曾把它列为无测试模块）。

doctor 是**使用者/Agent 排障的第一入口**：它给出的结论决定了下一步是「装依赖」「装
Chromium」还是「去看别的问题」。这里覆盖的是它的判定与副作用边界：

- 缺依赖要按名字报出来（否则 `--install` 无从下手）；
- 数据目录必须**真的写一次**再删，不能只看 `exists()`（权限问题只有写才暴露）；
- 自检不得在数据目录留下垃圾文件。

不覆盖 `check_chromium()`（要拉起真实浏览器，且结果取决于本机环境）。

同一层（环境/进程判定）还放在这里的是 `start_server.py` 的 start/stop 决策：
它和 `check_port()` 一样靠「端口是否被占」下结论，故同样按**探针可替换**的方式测，
不真起服务、不真绑端口、不真 taskkill。
"""
from __future__ import annotations

import importlib.util
import time
from pathlib import Path

import pytest

from webapi_extractor import doctor
from webapi_extractor.config import Settings


class TestPackageCheck:
    def test_missing_module_is_reported_by_name(self, monkeypatch):
        monkeypatch.setattr(doctor, "REQUIRED", ["not_a_real_module_xyz"])
        assert doctor.check_packages() == ["not_a_real_module_xyz"]

    def test_stdlib_module_is_reported_as_present(self, monkeypatch):
        monkeypatch.setattr(doctor, "REQUIRED", ["json", "socket"])
        assert doctor.check_packages() == []


class TestDataDirCheck:
    def test_writable_data_dir_passes_and_leaves_no_probe(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WEB_API_EXTRACTOR_DATA", str(tmp_path / "data"))
        assert doctor.check_data_dir() is True
        assert not (tmp_path / "data" / ".doctor_probe").exists()

    def test_data_dir_pointing_at_a_file_fails(self, monkeypatch, tmp_path):
        """路径被文件占住时，ensure_directories 会失败 —— 必须报 FAIL 而不是崩。"""
        blocker = tmp_path / "data"
        blocker.write_text("not a directory", encoding="utf-8")
        monkeypatch.setenv("WEB_API_EXTRACTOR_DATA", str(blocker))
        assert doctor.check_data_dir() is False

    def test_auth_states_dir_is_created_with_gitignore(self, monkeypatch, tmp_path):
        """自检顺带建目录：auth_states 放登录态（Cookie 明文、账号密码 DPAPI 加密），必须自带 .gitignore。"""
        monkeypatch.setenv("WEB_API_EXTRACTOR_DATA", str(tmp_path / "data"))
        doctor.check_data_dir()
        auth_states = tmp_path / "data" / "auth_states"
        assert (auth_states / ".gitignore").read_text(encoding="utf-8").startswith("*")


class TestPortCheck:
    def test_returns_a_bool_without_raising(self):
        """端口占用只影响提示，不能让自检整体失败。"""
        assert isinstance(doctor.check_port(), bool)


class TestMainReport:
    @pytest.fixture(autouse=True)
    def _no_browser(self, monkeypatch):
        """Chromium 检查要真拉起浏览器（数秒），本文件明确不覆盖它。"""
        monkeypatch.setattr(doctor, "check_chromium", lambda: True)

    def test_report_runs_to_completion(self, monkeypatch, tmp_path, capsys):
        monkeypatch.setenv("WEB_API_EXTRACTOR_DATA", str(tmp_path / "data"))
        rc = doctor.main([])
        out = capsys.readouterr().out

        assert rc in (0, 1)                       # 结论只有「就绪」与「未就绪」两种
        assert "doctor" in out
        assert "Python" in out                    # 至少报出了解释器版本
        if rc == 1:
            assert "doctor --install" in out      # 未就绪时要告诉用户怎么修

    def test_install_is_not_triggered_without_the_flag(self, monkeypatch, tmp_path):
        """`--install` 才会动手装东西；裸跑必须只检查。"""
        monkeypatch.setenv("WEB_API_EXTRACTOR_DATA", str(tmp_path / "data"))
        calls: list = []
        monkeypatch.setattr(doctor, "install", lambda *a, **k: calls.append(a))

        doctor.main([])

        assert calls == []


@pytest.mark.parametrize("path_part", ["data", "nested/deeper/data"])
def test_data_dir_is_created_even_when_nested(monkeypatch, tmp_path, path_part):
    target = tmp_path / path_part
    monkeypatch.setenv("WEB_API_EXTRACTOR_DATA", str(target))
    assert doctor.check_data_dir() is True
    assert Path(target).is_dir()


class TestConfigEnvParsing:
    """D4：畸形环境变量不得抛裸 ``ValueError`` 把整个服务在 import 期整死。"""

    ENV_VARS = (
        "WEB_API_EXTRACTOR_RESPONSE_LIMIT",
        "WEB_API_EXTRACTOR_IDLE_TIMEOUT",
        "WEB_API_EXTRACTOR_MAX_SESSIONS",
        "WEB_API_EXTRACTOR_NOISE_RESPONSE_BYTES",
        "WEB_API_EXTRACTOR_NOISE_SAMPLE_COUNT",
    )

    def test_malformed_value_names_variable_and_bad_value(self, monkeypatch):
        monkeypatch.setenv("WEB_API_EXTRACTOR_MAX_SESSIONS", "notanint")
        with pytest.raises(ValueError) as exc:
            Settings.from_environment()
        message = str(exc.value)
        assert "WEB_API_EXTRACTOR_MAX_SESSIONS" in message
        assert "notanint" in message

    @pytest.mark.parametrize("name", ENV_VARS)
    def test_every_variable_gets_a_clear_error(self, monkeypatch, name):
        monkeypatch.setenv(name, "abc")
        with pytest.raises(ValueError, match=name):
            Settings.from_environment()

    def test_unset_uses_documented_default(self, monkeypatch):
        for name in self.ENV_VARS:
            monkeypatch.delenv(name, raising=False)
        settings = Settings.from_environment()
        assert settings.max_sessions == 3
        assert settings.response_body_limit == 256 * 1024

    def test_whitespace_is_tolerated(self, monkeypatch):
        monkeypatch.setenv("WEB_API_EXTRACTOR_MAX_SESSIONS", " 4 ")
        assert Settings.from_environment().max_sessions == 4

    def test_non_positive_still_rejected(self, monkeypatch):
        monkeypatch.setenv("WEB_API_EXTRACTOR_MAX_SESSIONS", "0")
        with pytest.raises(ValueError, match="positive"):
            Settings.from_environment()


START_SERVER_PATH = Path(__file__).resolve().parents[1] / "start_server.py"


class TestStartServerStop:
    """S2：`start_server.py --stop` 必须按「端口是否真的释放」判定成功。

    现场事实（真机实测）：``.server_pid`` 记的是 launcher（父进程），真正的
    监听者是它的**子进程**::

        .server_pid = 40404   <- .venv/Scripts/python.exe run_http.py（父）
          └─ 18060            <- uv 托管的 python，TCP 127.0.0.1:8422 LISTENING

    旧实现 ``taskkill /F /PID 40404``（**没有 /T**）后只看 40404 死没死 → 打印
    「已停止服务」并删掉 PID 文件，而 18060 仍占着端口；随后 start() 又因
    ``alive(port)`` 为真「跳过启动」——用户停不掉也起不来。

    这里 monkeypatch 掉进程/端口探针来钉住新判定：**不真的 taskkill、不真的绑端口**
    （本机 8422 上有正在运行的服务）。`start_server.py` 是仓库根脚本，按路径加载。
    """

    # 真机 netstat -ano -p TCP 的原文（含中文表头与 CRLF）。
    NETSTAT = (
        "活动连接\r\n"
        "  协议  本地地址          外部地址        状态           PID\r\n"
        "  TCP    127.0.0.1:8422         0.0.0.0:0              LISTENING       18060\r\n"
        "  TCP    127.0.0.1:8422         127.0.0.1:52310        ESTABLISHED     40404\r\n"
    )

    @pytest.fixture()
    def server(self):
        spec = importlib.util.spec_from_file_location("start_server_under_test", START_SERVER_PATH)
        assert spec and spec.loader, "加载 start_server.py 失败"
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    @pytest.fixture()
    def pidfile(self, tmp_path, server, monkeypatch):
        path = tmp_path / ".server_pid"
        monkeypatch.setattr(server, "PIDFILE", path)
        return path

    def test_netstat_parser_finds_the_listener_not_the_established_row(self, server):
        assert server._parse_netstat_listener(self.NETSTAT, 8422) == 18060
        assert server._parse_netstat_listener(self.NETSTAT, 8423) is None
        assert server._parse_netstat_listener("", 8422) is None

    def test_ss_parser_finds_the_listener(self, server):
        line = ('LISTEN 0 128 127.0.0.1:8422 0.0.0.0:* '
                'users:(("python",pid=18060,fd=7))')
        assert server._parse_ss_listener(line, 8422) == 18060
        assert server._parse_ss_listener(line, 9999) is None

    def test_only_run_http_commands_are_considered_ours(self, server):
        assert server.is_project_server_command(
            r'"D:\MCP\WebAPIExtractor\.venv\Scripts\python.exe" run_http.py') is True
        assert server.is_project_server_command(
            r'"C:\x\python.exe" /d/MCP/WebAPIExtractor/run_http.py') is True
        assert server.is_project_server_command(r"C:\Windows\System32\notepad.exe a.txt") is False
        # 取不到命令行 → None（调用方不得据此盲杀）。
        assert server.is_project_server_command(None) is None
        assert server.is_project_server_command("   ") is None

    def test_success_is_decided_by_the_port_not_by_the_recorded_pid(self, server, pidfile,
                                                                    monkeypatch, capsys):
        """核心回归：记录的 PID 死了但子进程还占着端口 → 必须报失败。

        旧实现这条路会打印「已停止服务 PID 40404」并返回 0。
        """
        pidfile.write_text("40404")
        monkeypatch.setattr(server, "pid_alive", lambda pid: False)     # launcher 已死
        monkeypatch.setattr(server, "alive", lambda port=8422: True)    # 18060 还占着
        monkeypatch.setattr(server, "port_holder_pid", lambda port: 18060)

        assert server.stop() == 1

        out = capsys.readouterr().out
        assert "18060" in out, "必须点名仍持有端口的 PID"
        assert "已停止服务" not in out, "端口没释放就不能报成功"
        assert not pidfile.exists(), "该记录已确定失效，应清理"

    def test_unrelated_stale_pid_is_never_killed(self, server, pidfile, monkeypatch, capsys):
        """陈旧的 .server_pid + PID 复用 → 绝不能 taskkill 一个无关进程。"""
        pidfile.write_text("40404")
        killed: list = []
        monkeypatch.setattr(server, "pid_alive", lambda pid: True)
        monkeypatch.setattr(server, "alive", lambda port=8422: True)
        monkeypatch.setattr(server, "verify_project_pid", lambda pid: False)
        monkeypatch.setattr(server, "port_holder_pid", lambda port: 18060)
        monkeypatch.setattr(server, "_kill_tree", lambda pid, *, force=False: killed.append(pid))

        assert server.stop() == 1

        assert killed == [], "未确认归属的 PID 不得被终止"
        out = capsys.readouterr().out
        assert "不属于本项目" in out

    def test_unverifiable_pid_is_reported_instead_of_killed(self, server, pidfile,
                                                            monkeypatch, capsys):
        """取不到命令行（探针不可用）→ 只报告，不盲杀；给出 --force 出路。"""
        pidfile.write_text("40404")
        killed: list = []
        monkeypatch.setattr(server, "pid_alive", lambda pid: True)
        monkeypatch.setattr(server, "alive", lambda port=8422: False)
        monkeypatch.setattr(server, "verify_project_pid", lambda pid: None)
        monkeypatch.setattr(server, "_kill_tree", lambda pid, *, force=False: killed.append(pid))

        assert server.stop() == 1

        assert killed == []
        out = capsys.readouterr().out
        assert "无法确认" in out
        assert "--force" in out

    def test_verified_pid_is_killed_as_a_tree_and_success_follows_the_port(self, server, pidfile,
                                                                          monkeypatch, capsys):
        pidfile.write_text("40404")
        state = {"port_busy": True, "kills": []}

        def fake_kill(pid, *, force=False):
            state["kills"].append((pid, force))
            state["port_busy"] = False          # 进程树整体结束，端口真的空了

        monkeypatch.setattr(server, "pid_alive", lambda pid: True)
        monkeypatch.setattr(server, "alive", lambda port=8422: state["port_busy"])
        monkeypatch.setattr(server, "verify_project_pid", lambda pid: True)
        monkeypatch.setattr(server, "_kill_tree", fake_kill)

        assert server.stop() == 0

        assert state["kills"] == [(40404, False)]     # 先按树结束，无需升级强杀
        assert not pidfile.exists()
        assert "已停止服务 PID 40404" in capsys.readouterr().out

    def test_force_skips_verification(self, server, pidfile, monkeypatch):
        """--force 是「我已经确认过」的出口，跳过命令行校验。"""
        pidfile.write_text("40404")
        state = {"port_busy": True}

        def fake_kill(pid, *, force=False):
            state["port_busy"] = False

        monkeypatch.setattr(server, "pid_alive", lambda pid: True)
        monkeypatch.setattr(server, "alive", lambda port=8422: state["port_busy"])
        monkeypatch.setattr(server, "verify_project_pid",
                            lambda pid: pytest.fail("--force 时不应再查命令行"))
        monkeypatch.setattr(server, "_kill_tree", fake_kill)

        assert server.stop(force=True) == 0

    def test_port_busy_after_kill_still_reports_failure_with_holder(self, server, pidfile,
                                                                    monkeypatch, capsys):
        """树杀完端口仍被别的进程占着 → 失败，并点名占用者。"""
        pidfile.write_text("40404")
        monkeypatch.setattr(server, "pid_alive", lambda pid: True)
        monkeypatch.setattr(server, "alive", lambda port=8422: True)
        monkeypatch.setattr(server, "verify_project_pid", lambda pid: True)
        monkeypatch.setattr(server, "_kill_tree", lambda *a, **k: None)
        monkeypatch.setattr(server, "wait_port_free", lambda *a, **k: False)
        monkeypatch.setattr(server, "port_holder_pid", lambda port: 18060)

        assert server.stop() == 1

        out = capsys.readouterr().out
        assert "18060" in out
        assert "停止未完成" in out

    def test_wait_port_free_is_bounded(self, server, monkeypatch):
        """等待必须**有界**——不能因为端口一直占着就永久挂住。"""
        monkeypatch.setattr(server, "alive", lambda port=8422: True)
        started = time.monotonic()
        assert server.wait_port_free(8422, timeout=0.2, interval=0.05) is False
        assert time.monotonic() - started < 2.0

        monkeypatch.setattr(server, "alive", lambda port=8422: False)
        assert server.wait_port_free(8422, timeout=0.2, interval=0.05) is True

    def test_start_names_the_port_holder_instead_of_bare_skip(self, server, pidfile,
                                                              monkeypatch, capsys):
        """卡在「停不掉也起不来」时，start 必须告诉用户谁占着端口、怎么办。"""
        pidfile.write_text("40404")
        monkeypatch.setattr(server, "alive", lambda port=8422: True)
        monkeypatch.setattr(server, "port_holder_pid", lambda port: 18060)

        assert server.start() == 0        # 已在监听 → 不重复启动，但仍要说明

        out = capsys.readouterr().out
        assert "跳过启动" in out
        assert "18060" in out, "必须点名持有端口的 PID"
        assert "40404" in out, "并说明记录的是父进程（launcher）"
        assert "--port 8423" in out, "给出换端口的出路"
