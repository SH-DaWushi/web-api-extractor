#!/usr/bin/env bash
# scry-mcp-gen 引导脚本 —— POSIX / macOS / Linux 未经验证、不受支持。
# 本项目只支持 Windows：受支持的引导路径是 bootstrap.py / bootstrap.ps1。
# 本文件仅出于礼节保留在仓库中，仅供参考、不作完整验证，也不随商店构建分发。
# 作用：调用 bootstrap.py 建立独立 venv、安装依赖 + Playwright Chromium，最后跑 doctor 自检。
# 用法： bash ./bootstrap.sh [--with-tests]
#
# venv 位置（数据目录下 / 复用旧的技能目录 .venv）由 bootstrap.py 决定：
# .py / .ps1 / .sh 三份脚本各写一套逻辑就会漂移，venv 位置正是这样走过样。
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$root"

PY="${WAE_PYTHON:-python3}"
echo ">> 使用 Python: $PY"

exec "$PY" "$root/bootstrap.py" "$@"
