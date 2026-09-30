# web-api-extractor 一键引导脚本 (Windows PowerShell)
# 作用：调用 bootstrap.py 建立独立 venv（隔离可能损坏的全局 user site-packages）、
#       装依赖 + Playwright Chromium 内核，最后跑 doctor 自检。
# 用法：在本目录执行   powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1
#       需要跑测试时追加   -WithTests   （额外装 requirements-dev.txt）
#
# venv 位置（数据目录下 / 复用旧的技能目录 .venv）由 bootstrap.py 决定：
# .py / .ps1 / .sh 三份脚本各写一套逻辑就会漂移，venv 位置正是这样走过样。
param(
    [switch]$WithTests
)
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

$bootstrapArgs = @((Join-Path $root "bootstrap.py"))
if ($WithTests) { $bootstrapArgs += "--with-tests" }

& $py @bootstrapArgs
