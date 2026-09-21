param(
    [string]$Output = "web-api-extractor-agent.zip"
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
# 绝对路径直接用；Join-Path 会把 "D:\repo" + "C:\out\x.zip" 拼成一个坏路径。
$outputPath = if ([System.IO.Path]::IsPathRooted($Output)) { $Output } else { Join-Path $root $Output }
$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("web-api-extractor-package-" + [guid]::NewGuid().ToString("N"))

try {
    New-Item -ItemType Directory -Path $staging | Out-Null
    # 这是**技能导入包**：必须是自足的——runbook/00 让 Agent 跑 bootstrap 与
    # start_server.py / mcp_call.py，SKILL.md 的硬规则也要求用 start_server.py。
    # 这些文件此前漏在列表外，打出来的 zip 导入后按手册走会直接找不到脚本。
    $include = @(
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
        "tests"
    )
    foreach ($item in $include) {
        Copy-Item -Path (Join-Path $root $item) -Destination $staging -Recurse -Force
    }
    Get-ChildItem -Path $staging -Recurse -Force |
        Where-Object { $_.FullName -match "(__pycache__|\.pytest_cache|\.egg-info|\.pyc$)" } |
        Remove-Item -Recurse -Force
    if (Test-Path $outputPath) {
        Remove-Item $outputPath -Force
    }
    Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $outputPath -CompressionLevel Optimal
    Write-Host "Created $outputPath"
}
finally {
    if (Test-Path $staging) {
        Remove-Item $staging -Recurse -Force
    }
}