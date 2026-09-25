# -*- coding: utf-8 -*-
"""`doctor` 环境自检（reference 的「测试」一节曾把它列为无测试模块）。

doctor 是**使用者/Agent 排障的第一入口**：它给出的结论决定了下一步是「装依赖」「装
Chromium」还是「去看别的问题」。这里覆盖的是它的判定与副作用边界：

- 缺依赖要按名字报出来（否则 `--install` 无从下手）；
- 数据目录必须**真的写一次**再删，不能只看 `exists()`（权限问题只有写才暴露）；
- 自检不得在数据目录留下垃圾文件。

不覆盖 `check_chromium()`（要拉起真实浏览器，且结果取决于本机环境）。
"""
from __future__ import annotations

from pathlib import Path

import pytest

from webapi_extractor import doctor


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
        """自检顺带建目录：auth_states 里会放明文凭据，必须自带 .gitignore。"""
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
