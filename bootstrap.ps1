# web-api-extractor 一键引导脚本 (Windows PowerShell)
# 作用：在本技能目录创建独立 .venv（隔离可能损坏的全局 user site-packages），
#       安装依赖 + Playwright Chromium 内核，最后跑 doctor 自检。
# 用法：在本目录执行   powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# 找一个可用的 Python (>=3.10)
$py = $env:WAE_PYTHON
if (-not $py) {
  $cmd = Get-Command python -ErrorAction SilentlyContinue
  if ($cmd) { $py = $cmd.Source } else { $py = "python" }
}
Write-Host ">> 使用 Python: $py"

$venv = Join-Path $root ".venv"
$venvPy = Join-Path $venv "Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
  Write-Host ">> 创建虚拟环境 .venv （隔离全局 site-packages）"
  & $py -m venv $venv
}

Write-Host ">> 安装依赖 (requirements.txt)"
& $venvPy -m pip install --disable-pip-version-check --upgrade pip | Out-Null
& $venvPy -m pip install --disable-pip-version-check -r requirements.txt

Write-Host ">> 安装 Playwright Chromium 内核（较大，请稍候）"
& $venvPy -m playwright install chromium

Write-Host ">> 运行环境自检 doctor"
& $venvPy -m webapi_extractor doctor

Write-Host ""
Write-Host "引导完成。后续用法："
Write-Host "  启动服务:  & '$venvPy' run_http.py"
Write-Host "  调用工具:  & '$venvPy' mcp_call.py <tool_name> '<json-args>'"
