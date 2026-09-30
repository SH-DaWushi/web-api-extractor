# -*- coding: utf-8 -*-
"""纯 Python 版技能打包（E-1：不依赖 PowerShell，受限环境可用）。

用法：
    python package-agent.py [-o scry-mcp-gen-agent.zip]
    python package-agent.py --store [-o scry-mcp-gen-store.zip]

产出的是**技能导入包**：解压后必须自足。runbook/00 让 Agent 跑 bootstrap 与
start_server.py / mcp_call.py，SKILL.md 的硬规则也要求用 start_server.py。
这些文件此前漏在清单外，打出来的 zip 导入后按手册走会直接找不到脚本，
所以清单里少一项是**错误**，不能静默跳过。

两个版本（开源版 / 商店版）的清单口径不同：
- 默认 = 开源版，逐项与 package-agent.ps1 的 $include 一致；
- `--store` = 商店版，在默认清单上做机械变换（见 STORE_INCLUDE），逐项与 .ps1 的
  $storeInclude 一致。商店版把 LICENSE-STORE 落成包内的 LICENSE —— 商店包只能带
  一份授权文件，且必须是商店版那份，不能是仓库里的非商业 LICENSE。

INCLUDE / STORE_INCLUDE 必须与 package-agent.ps1 的 $include / $storeInclude 一致
（两者都对使用者分发，tests/test_package_agent.py 会逐项比对，防止只改一边）。
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
    "requirements-dev.txt",
    "README.md",
    "README.en.md",
    "SKILL.md",
    "docs",
    "runbook",
    "LICENSE",
    "DISCLAIMER.md",
    "bootstrap.py",
    "bootstrap.ps1",
    "bootstrap.sh",
    "install-agent.ps1",
    "start_server.py",
    "run_http.py",
    "mcp_call.py",
    ".vscode",
    "scry_mcp_gen",
    "tests",
)

# 商店版在默认清单上做的变换，三份数据都必须与 package-agent.ps1 对应数组一致。
# STORE_EXCLUDE 是「开发用 / 平台不支持」的项，外加 LICENSE：
#   LICENSE 不是被丢掉，而是由 LICENSE-STORE 顶替（见 STORE_RENAME / STORE_ADD），
#   否则商店包会同时带两份授权文件、且其中一份是仓库的非商业 LICENSE。
# 注意 DISCLAIMER.md 两个版本都带，故只在 INCLUDE 里出现一次；**绝不能**再放进
#   STORE_ADD —— STORE_INCLUDE = INCLUDE−STORE_EXCLUDE + STORE_ADD 是简单拼接，
#   同一项出现两次会让商店 zip 里出现同名重复成员（各实现解包行为不一）。
STORE_EXCLUDE = frozenset({
    "bootstrap.sh",        # POSIX 脚本；本平台决定只支持 Windows
    "tests",
    ".vscode",
    "package-agent.py",
    "package-agent.ps1",
    "install-agent.ps1",
    ".gitattributes",
    "requirements-dev.txt",
    "pyproject.toml",
    "LICENSE",
})
STORE_ADD = ("LICENSE-STORE",)
# 商店版包内改名：LICENSE-STORE → LICENSE（商店包只能有一份授权文件）
STORE_RENAME = {"LICENSE-STORE": "LICENSE"}

# 开源版清单减去商店排除项，再接上商店附加项（保持顺序，便于与 .ps1 逐项比对）
STORE_INCLUDE = tuple([item for item in INCLUDE if item not in STORE_EXCLUDE] + list(STORE_ADD))

# 与 .ps1 里那段 `Where-Object { $_.FullName -match "(__pycache__|...)" }` 等价
EXCLUDE_DIRS = frozenset({"__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache",
                          ".venv", ".git"})
EXCLUDE_DIR_SUFFIXES = (".egg-info",)
EXCLUDE_FILE_SUFFIXES = (".pyc", ".pyo")


def iter_packaged(root: Path = ROOT, manifest=None):
    """按 manifest（默认 INCLUDE）展开出待打包文件（相对 root 的 Path），已剔除运行产物。

    manifest 在调用时才解析成模块级的 INCLUDE，这样测试 monkeypatch INCLUDE 后
    不传 manifest 也生效（历史行为）。
    """
    manifest = INCLUDE if manifest is None else manifest
    missing = [item for item in manifest if not (root / item).exists()]
    if missing:
        # 绝不静默跳过：缺文件要在打包时炸掉，而不是等导入后按手册走才发现。
        raise FileNotFoundError(f"打包清单里不存在：{', '.join(missing)}（根目录 {root}）")

    for item in manifest:
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


def build_zip(dest: Path, root: Path = ROOT, manifest=None, rename=None) -> list[str]:
    """打包到 dest，返回写入的 arcname 列表（已排序，便于比对与测试）。

    条目不套一层目录（等价于 .ps1 的 Compress-Archive `staging/*`），
    解压后 SKILL.md 就在根上 —— 技能导入要求 SKILL.md 位于包根。

    manifest 为清单（默认 INCLUDE）；rename 为清单顶层项的包内改名
    （商店版用它把 LICENSE-STORE 落成 LICENSE，两份脚本必须同样处理）。
    """
    manifest = INCLUDE if manifest is None else manifest
    rename = {} if rename is None else rename
    dest.parent.mkdir(parents=True, exist_ok=True)
    # 先收集再排序，保证 zip 条目顺序稳定（rglob 的枚举顺序依赖文件系统）
    entries: list[tuple[str, Path]] = []
    for path in iter_packaged(root, manifest):
        rel = path.relative_to(root).as_posix()
        top, sep, rest = rel.partition("/")
        arcname = rename.get(top, top) + (sep + rest if sep else "")
        entries.append((arcname, path))
    entries.sort(key=lambda entry: entry[0])

    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, path in entries:
            zf.write(path, arcname)
    return [arcname for arcname, _ in entries]


DEFAULT_OUTPUT = "scry-mcp-gen-agent.zip"
STORE_OUTPUT = "scry-mcp-gen-store.zip"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="打包 scry-mcp-gen 技能导入包")
    parser.add_argument("--store", action="store_true",
                        help="打商店版（去掉开发/不支持项，LICENSE 换成商店版那份；"
                             "DISCLAIMER.md 两版都带）")
    parser.add_argument("-o", "--output", default=None,
                        help="输出 zip 路径；相对路径按仓库根解析"
                             "（默认开源版 %s / 商店版 %s，建在仓库根）" % (DEFAULT_OUTPUT, STORE_OUTPUT))
    args = parser.parse_args(argv)

    default_name = STORE_OUTPUT if args.store else DEFAULT_OUTPUT
    dest = Path(args.output) if args.output else ROOT / default_name
    if not dest.is_absolute():
        dest = ROOT / dest
    if dest.exists():
        # Compress-Archive 也覆盖旧包；留旧 zip 会让人以为打成功了
        dest.unlink()

    manifest = STORE_INCLUDE if args.store else INCLUDE
    rename = STORE_RENAME if args.store else None
    names = build_zip(dest, manifest=manifest, rename=rename)
    print(f"Created {dest}" + ("（商店版）" if args.store else ""))
    print(f"  {len(names)} 个文件，{dest.stat().st_size} 字节")
    print(f"  zip 内有 SKILL.md: {'SKILL.md' in names}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
