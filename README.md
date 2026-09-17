# Web API Extractor

本项目按 `设计文档_v2.md` 实施，已完成认证、浏览器/CDP 捕获、分析、加密初检和 Python/FastMCP 生成主链路。

## 快速开始

```powershell
python -m pip install -e .
playwright install chromium
web-api-extractor
```

## 导入 Agent

项目内置 `.vscode/mcp.json`，在 VS Code 中打开本目录后，Agent 会发现名为
`web-api-extractor` 的 stdio MCP Server。首次使用先执行：

```powershell
.\install-agent.ps1
```

也可以生成可分发压缩包：

```powershell
.\package-agent.ps1
```

解压后在目标机器打开该目录，执行 `install-agent.ps1`，再让 Agent 导入该工作区。
压缩包不包含 `.egg-info`、Python 缓存、测试缓存或会话凭证；真实认证数据仍保存在
`%USERPROFILE%\.webapiextractor`。

默认数据目录为 `%USERPROFILE%\.webapiextractor`，可通过环境变量覆盖：

```powershell
$env:WEB_API_EXTRACTOR_DATA = "D:\web-api-extractor-data"
$env:WEB_API_EXTRACTOR_RESPONSE_LIMIT = "262144"
$env:WEB_API_EXTRACTOR_IDLE_TIMEOUT = "300"
```

## 当前状态

- M1-M5：配置、认证、审计、原子会话元数据、孤儿会话回收、登录探测、浏览器/CDP 捕获、分析和生成器已完成。
- 脱敏：密码、Authorization、Cookie 和 JSON token 字段在进入共享语料前会被替换。
- 分析基础：已实现 `/orders/123`、`/orders/456` 与 `/orders/latest` 的保守归一化规则。
- 已知限制：L1 加密目前提供指纹检测结果，标准库密钥重实现和 L2/L3 运行时透传仍需针对具体站点补全。

运行 M1 测试：

```powershell
python -m pytest tests/test_m1.py -q
```