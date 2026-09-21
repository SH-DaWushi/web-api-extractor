---
name: web-api-extractor
description: Extract web API traffic through browser authentication and CDP capture, analyze endpoints, and generate a Python FastMCP server.
install_method: upload
---

# Web API Extractor — 操作手册 (Runbook)

让 Agent 在真实站点上完成「登录 → 操作 → 抓包 → 分析 → 生成 MCP」的闭环。

本文件是**主索引**：只保留核心流程与硬性规则；各步骤的详细操作拆在 `runbook/` 下，
**按需加载**（顺利时不加载排错等无关章节，避免无关内容全量进上下文）。原理与背景见 `README.md`。

## 核心流程

按顺序执行；每步的「怎么做」见对应模块（`runbook/xx.md`，相对本目录）。

1. **环境准备 + 传输引导**（新部署一次）：`bootstrap` → `doctor`；工具无法直接调用时用 `start_server.py` + `mcp_call.py`。→ `runbook/00-environment.md`
2. **探测登录方式 → 登录**：`probe_login`；`open_browser_login`（或 `http_login`）；
   **用户确认登录完成后**调 `confirm_login` 拿 `auth_state`。→ `runbook/01-authentication.md`
3. **抓包**：`start_capture`（带 `auth_state_path`），用户操作目标功能，`stop_capture`。→ `runbook/02-capture.md`
4. **分析**：`analyze_traffic`。→ `runbook/03-analyze.md`
5. **加密与凭据核实**（强制，禁止跳过）：看 `crypto_found`，必要时 `extract_crypto_logic`。→ `runbook/04-crypto.md`
6. **生成**：`generate_mcp_server(session_id, output_dir)`。→ `runbook/05-generate.md`
7. **持续迭代**：`diff_capture` → `merge_capture` → `regenerate_server` → `export_project`。→ `runbook/06-iterate.md`

## 关键限制（硬规则）

- **步骤 5 不可跳过**：抓包里的凭据值必然被脱敏为 `***`，明文/密文不可区分，禁止假设，必须核实。
- **登录完成必须由用户确认**：`open_browser_login` 后先问用户是否已登录完成，得到答复再调
  `confirm_login`；抓包未带 `auth_state_path` 时，问用户后再调 `confirm_login_ready`。
  工具返回的 `auth_evidence` 只是旁证，**不得据此自行判定并往下走**——用户确认前不要开始抓包或分析。
- **启动服务务必用 `start_server.py`**，不要直接在宿主 shell 后台跑 `run_http.py`（否则浏览器「打开后立刻消失」）。

## 模块索引

| 模块 | 内容 | 何时加载 |
|---|---|---|
| `runbook/00-environment.md` | 环境准备、传输引导 | 新部署 / 工具无法调用时 |
| `runbook/01-authentication.md` | 探测登录、登录（用户确认登录完成、SSO 交互式授权生命周期） | 登录环节 |
| `runbook/02-capture.md` | 抓包 | 抓包环节 |
| `runbook/03-analyze.md` | 分析能力（噪音/参数化/登录接口/站点档案） | 分析环节 |
| `runbook/04-crypto.md` | 加密与凭据核实 | `crypto_found=true` 时必读 |
| `runbook/05-generate.md` | 生成项目、生成器能力、Basic 口令验证 | 生成环节 |
| `runbook/06-iterate.md` | 增量合并、锁定、用户态隔离 | IT 管理态迭代 |
| `runbook/90-reference.md` | 数据目录、环境变量 | 查配置/路径时 |
| `runbook/99-troubleshooting.md` | 排错速查 | 出问题时 |
