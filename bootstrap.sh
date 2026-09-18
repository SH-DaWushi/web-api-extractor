#!/usr/bin/env bash
# web-api-extractor 一键引导脚本 (macOS / Linux)
# 作用：创建独立 .venv，安装依赖 + Playwright Chromium，最后跑 doctor 自检。
# 用法： bash ./bootstrap.sh
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$root"

PY="${WAE_PYTHON:-python3}"
echo ">> 使用 Python: $PY"

venv="$root/.venv"
if [ ! -x "$venv/bin/python" ]; then
  echo ">> 创建虚拟环境 .venv"
  "$PY" -m venv "$venv"
fi
venvPy="$venv/bin/python"

echo ">> 安装依赖 (requirements.txt)"
"$venvPy" -m pip install --disable-pip-version-check --upgrade pip >/dev/null
"$venvPy" -m pip install --disable-pip-version-check -r requirements.txt

echo ">> 安装 Playwright Chromium 内核（较大，请稍候）"
"$venvPy" -m playwright install chromium

echo ">> 运行环境自检 doctor"
"$venvPy" -m webapi_extractor doctor

cat <<EOF

引导完成。后续用法：
  启动服务:  $venvPy run_http.py
  调用工具:  $venvPy mcp_call.py <tool_name> '<json-args>'
EOF
