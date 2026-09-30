---
name: scry-mcp-gen
description: Extract web API traffic through browser authentication and CDP capture, analyze endpoints, and generate a Python FastMCP server.
install_method: upload
---

# Web API Extractor — 操作手册 (Runbook)

让 Agent 在真实站点上完成「登录 → 操作 → 抓包 → 分析 → 生成 MCP」的闭环。

本文件是**主索引**：只保留核心流程与硬性规则；各步骤的详细操作拆在 `runbook/` 下，
**按需加载**（顺利时不加载排错等无关章节，避免无关内容全量进上下文）。
需要环境变量、工具清单、项目结构等技术细节时查 `docs/reference.md`。

## 核心流程

按顺序执行；每步的「怎么做」见对应模块（`runbook/xx.md`，相对本目录）。

1. **环境准备 + 传输引导**（新部署一次）：`bootstrap` → `doctor`；工具无法直接调用时用 `start_server.py` + `mcp_call.py`。→ `runbook/00-environment.md`
2. **探测登录方式 → 登录**：`probe_login`；再**实测一次 `http_login`**（它真的 POST 一次，
   失败会换个形态再试，并把结论**落盘** —— 生成期据此决定生成物里是账号密码登录还是**自带的
   交互式登录**，所以**别跳过它**）；实测过不去才用 `open_browser_login`，
   **用户确认登录完成后**调 `confirm_login` 拿 `auth_state`。→ `runbook/01-authentication.md`
3. **抓包**：`start_capture`（带 `auth_state_path`），用户操作目标功能，`stop_capture`。→ `runbook/02-capture.md`
4. **分析**：`analyze_traffic`。→ `runbook/03-analyze.md`
5. **加密与凭据核实**（强制，禁止跳过）：先做必做核对（本轮抓包是否真的覆盖了凭据交换）；
   `crypto_found=true` 时再读全文并调 `extract_crypto_logic`。→ `runbook/04-crypto.md`
6. **生成**：`generate_mcp_server(session_id, output_dir)`。→ `runbook/05-generate.md`
7. **持续迭代**：`diff_capture` → `merge_capture` → `regenerate_server` → `export_project`。→ `runbook/06-iterate.md`

## 关键限制（硬规则）

- **步骤 5 不可跳过**：抓包中 JSON / 表单编码请求体里的凭据值被脱敏为 `***`，明文/密文不可区分，
  禁止假设，必须核实。（URL 与响应体**不**脱敏，别据此认定抓到的是明文。）
  「不可跳过」= 每个 session 都要先做「本轮抓包是否真的覆盖了凭据交换」这条必做核对；
  `crypto_found=true` 时再做四层密文核实。`crypto_found=false` **不等于**「明文传输」——
  它只说明本轮没有可核实的密文（判据与例外见 `runbook/04-crypto.md`）。
- **登录完成必须由用户确认**：`open_browser_login` 后先问用户是否已登录完成，得到答复再调
  `confirm_login`；抓包未带 `auth_state_path` 时，问用户后再调 `confirm_login_ready`。
  不便在对话里问时，改用 `request_login_confirm_dialog` / `request_capture_confirm_dialog`
  弹系统对话框让用户点选（点「否」不丢弃，可再次弹出）。
  工具返回的 `auth_evidence` 只是旁证，**不得据此自行判定并往下走**——用户确认前不要开始抓包或分析。
- **启动服务务必用 `start_server.py`**，不要直接在宿主 shell 后台跑 `run_http.py`（否则浏览器「打开后立刻消失」）。

## 模块索引

**命名约定**：文件名前缀是**模块序号**（从 `00` 起），流程**步骤号**从 `1` 起 —— 两者恒差 1。
每个模块的标题同时标出「模块 `xx-name` · 步骤 N」，**交叉引用一律用文件名**，不要只说「步骤 N」。
（文件名不可改：本索引、打包清单与一致性测试都按文件名引用。）

| 模块 | 步骤 | 内容 | 何时加载 |
|---|---|---|---|
| `runbook/00-environment.md` | 1 | 环境准备、传输引导 | 新部署 / 工具无法调用时 |
| `runbook/01-authentication.md` | 2 | 探测登录、登录（用户确认登录完成、SSO 交互式授权生命周期） | 登录环节 |
| `runbook/02-capture.md` | 3 | 抓包 | 抓包环节 |
| `runbook/03-analyze.md` | 4 | 分析能力（噪音/参数化/登录接口/站点档案） | 分析环节 |
| `runbook/04-crypto.md` | 5 | 加密与凭据核实 | **必读**（步骤 5 强制）；其中四层密文核实仅 `crypto_found=true` 时做 |
| `runbook/05-generate.md` | 6 | 生成项目、生成器能力、Basic 口令验证 | 生成环节 |
| `runbook/06-iterate.md` | 7 | 增量合并、锁定、用户态隔离 | IT 管理态迭代 |
| `runbook/90-reference.md` | — | 数据目录、环境变量 | 查配置/路径时 |
| `runbook/99-troubleshooting.md` | — | 排错速查 | 出问题时 |

> 能力边界（做不到什么）、平台限制、安全语义与工具参数速查见 `docs/reference.md`。
