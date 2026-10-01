param(
    [string]$Output = "",
    [switch]$Store
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

# 开源版（默认）与商店版（-Store）两个清单口径不同：商店版在 $include 上做机械变换，
# 见 $storeInclude。$include 与 $storeInclude 必须分别与 package-agent.py 的
# INCLUDE / STORE_INCLUDE 逐项一致（tests/test_package_agent.py 会比对，防止只改一边）。
$include = @(
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
    "tests"
)

# 商店版去掉开发用 / 平台不支持的项，再附上商店版自己那三份文件。
# LICENSE / README.md / README.en.md 都**不在**商店清单里：它们由 -STORE 那三份顶替
#   （见 $rename）—— 商店包只能带一份授权，而 README 里写着公开仓库地址与
#   「另有开源版」的说明，那些不能发给商店用户。
# docs/ 两版都带：docs/reference.md 被 SKILL.md、runbook/ 与**代码文档字符串**引用，
#   必须随包分发，也因此不得含仓库线索（打包清单与目录树在 PACKAGING.md，它不在 $include 里）。
# DISCLAIMER.md 两个版本都带，来自 $include（不在 $storeInclude 里重复列一次）。
# bootstrap.ps1 则**保留** —— 本平台只支持 Windows，runbook 的 Windows 路径要引用它。
$storeInclude = @(
    "requirements.txt",
    "SKILL.md",
    "docs",
    "runbook",
    "DISCLAIMER.md",
    "bootstrap.py",
    "bootstrap.ps1",
    "start_server.py",
    "run_http.py",
    "mcp_call.py",
    "scry_mcp_gen",
    "LICENSE-STORE",
    "README-STORE.md",
    "README-STORE.en.md"
)

# 商店版包内改名：这三份在包里各自就叫正式名字（不带 -STORE 后缀）
$rename = @{
    "LICENSE-STORE" = "LICENSE"
    "README-STORE.md" = "README.md"
    "README-STORE.en.md" = "README.en.md"
}

# 绝对路径直接用；Join-Path 会把 "D:\repo" + "C:\out\x.zip" 拼成一个坏路径。
if ([string]::IsNullOrEmpty($Output)) {
    $Output = if ($Store) { "scry-mcp-gen-store.zip" } else { "scry-mcp-gen-agent.zip" }
}
$outputPath = if ([System.IO.Path]::IsPathRooted($Output)) { $Output } else { Join-Path $root $Output }
$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("scry-mcp-gen-package-" + [guid]::NewGuid().ToString("N"))

$effective = if ($Store) { $storeInclude } else { $include }

try {
    New-Item -ItemType Directory -Path $staging | Out-Null
    # 这是**技能导入包**：必须是自足的——runbook/00 让 Agent 跑 bootstrap 与
    # start_server.py / mcp_call.py，SKILL.md 的硬规则也要求用 start_server.py。
    # 这些文件此前漏在列表外，打出来的 zip 导入后按手册走会直接找不到脚本。
    foreach ($item in $effective) {
        $src = Join-Path $root $item
        if ($Store -and $rename.ContainsKey($item)) {
            # 改名项是单文件，直接落到目标名（LICENSE-STORE → LICENSE）
            Copy-Item -Path $src -Destination (Join-Path $staging $rename[$item]) -Force
        }
        else {
            Copy-Item -Path $src -Destination $staging -Recurse -Force
        }
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
