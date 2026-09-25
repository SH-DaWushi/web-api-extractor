# -*- coding: utf-8 -*-
"""纯 Python 版技能打包（E-1：不依赖 PowerShell，受限环境可用）。

用法：
    python package-agent.py [-o web-api-extractor-agent.zip]

产出的是**技能导入包**：解压后必须自足。runbook/00 让 Agent 跑 bootstrap 与
start_server.py / mcp_call.py，SKILL.md 的硬规则也要求用 start_server.py。
这些文件此前漏在清单外，打出来的 zip 导入后按手册走会直接找不到脚本，
所以清单里少一项是**错误**，不能静默跳过。

INCLUDE 必须与 package-agent.ps1 的 $include 一致（两者都对使用者分发，
tests/test_package_agent.py 会逐项比对，防止只改一边）。
"""
from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# 与 package-agent.ps1 的 $include 一一对应（同一顺序）
INCLUDE = (
    "pyproject.toml",
    "requirements.txt",
    "README.md",
    "SKILL.md",
    "docs",
    "runbook",
    "LICENSE",
    "bootstrap.py",
    "bootstrap.ps1",
    "bootstrap.sh",
    "install-agent.ps1",
    "start_server.py",
    "run_http.py",
    "mcp_call.py",
    ".vscode",
    "webapi_extractor",
    "tests",
)

# 与 .ps1 里那段 `Where-Object { $_.FullName -match "(__pycache__|...)" }` 等价
EXCLUDE_DIRS = frozenset({"__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache",
                          ".venv", ".git"})
EXCLUDE_DIR_SUFFIXES = (".egg-info",)
EXCLUDE_FILE_SUFFIXES = (".pyc", ".pyo")


def iter_packaged(root: Path = ROOT):
    """按 INCLUDE 展开出待打包文件（相对 root 的 Path），已剔除运行产物。"""
    missing = [item for item in INCLUDE if not (root / item).exists()]
    if missing:
        # 绝不静默跳过：缺文件要在打包时炸掉，而不是等导入后按手册走才发现。
        raise FileNotFoundError(f"打包清单里不存在：{', '.join(missing)}（根目录 {root}）")

    for item in INCLUDE:
        src = root / item
        if not src.is_dir():
            yield src
            continue
        for path in src.rglob("*"):
            if not path.is_file():
                continue
            parts = path.relative_to(root).parts
            if any(p in EXCLUDE_DIRS for p in parts):
                continue
            if any(p.endswith(EXCLUDE_DIR_SUFFIXES) for p in parts):
                continue
            if path.suffix in EXCLUDE_FILE_SUFFIXES:
                continue
            yield path


def build_zip(dest: Path, root: Path = ROOT) -> list[str]:
    """打包到 dest，返回写入的 arcname 列表（已排序，便于比对与测试）。

    条目不套一层目录（等价于 .ps1 的 Compress-Archive `staging/*`），
    解压后 SKILL.md 就在根上 —— 技能导入要求 SKILL.md 位于包根。
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    # 先收集再排序，保证 zip 条目顺序稳定（rglob 的枚举顺序依赖文件系统）
    entries = sorted((p.relative_to(root).as_posix(), p) for p in iter_packaged(root))

    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, path in entries:
            zf.write(path, arcname)
    return [arcname for arcname, _ in entries]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="打包 web-api-extractor 技能导入包")
    parser.add_argument("-o", "--output", default="web-api-extractor-agent.zip",
                        help="输出 zip 路径；相对路径按仓库根解析（默认在仓库根建 %(default)s）")
    args = parser.parse_args(argv)

    dest = Path(args.output)
    if not dest.is_absolute():
        dest = ROOT / dest
    if dest.exists():
        # Compress-Archive 也覆盖旧包；留旧 zip 会让人以为打成功了
        dest.unlink()

    names = build_zip(dest)
    print(f"Created {dest}")
    print(f"  {len(names)} 个文件，{dest.stat().st_size} 字节")
    print(f"  zip 内有 SKILL.md: {'SKILL.md' in names}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
