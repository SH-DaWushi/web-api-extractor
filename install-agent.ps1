param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"

& $Python -m pip install -r "$PSScriptRoot\requirements.txt"
if ($LASTEXITCODE -ne 0) {
    throw "Python dependency installation failed."
}

& $Python -m playwright install chromium
if ($LASTEXITCODE -ne 0) {
    throw "Playwright Chromium installation failed."
}

Write-Host "Web API Extractor is ready for Agent import."
Write-Host "Open this folder in VS Code; .vscode/mcp.json registers the stdio MCP server."