param(
    [string]$Python = "python",
    [switch]$WithTests
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

# 统一走 bootstrap.py：它建独立 venv（数据目录下）、装运行依赖 + Playwright Chromium、
# 最后跑 doctor 自检。这里**不再**用全局解释器 pip install —— 那会污染使用者的全局
# site-packages，并让同一个技能出现「一处隔离、一处不隔离」两条安装路径。
$bootstrap = Join-Path $root "bootstrap.py"
$bootstrapArgs = @($bootstrap)
if ($WithTests) {
    # 显式要跑测试时才装 requirements-dev.txt（pytest / pytest-asyncio）。
    $bootstrapArgs += "--with-tests"
}

& $Python @bootstrapArgs
if ($LASTEXITCODE -ne 0) {
    throw "scry-mcp-gen environment bootstrap failed."
}

Write-Host "scry-mcp-gen is ready for Agent import."
Write-Host "Open this folder in VS Code; .vscode/mcp.json registers the stdio MCP server."
