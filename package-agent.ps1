param(
    [string]$Output = "web-api-extractor-agent.zip"
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$outputPath = Join-Path $root $Output
$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("web-api-extractor-package-" + [guid]::NewGuid().ToString("N"))

try {
    New-Item -ItemType Directory -Path $staging | Out-Null
    $include = @(
        "pyproject.toml",
        "requirements.txt",
        "README.md",
        "SKILL.md",
        "runbook",
        "install-agent.ps1",
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