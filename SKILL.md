---
name: web-api-extractor
description: Extract web API traffic through browser authentication and CDP capture, analyze endpoints, and generate a Python FastMCP server.
install_method: upload
---

# Web API Extractor — 操作手册 (Runbook)

让 Agent 在真实站点上完成「登录 → 操作 → 抓包 → 分析 → 生成 MCP」的闭环。
本文件是**可执行流程**，按顺序照做即可；原理与背景见 `README.md`。

---

## 步骤 0 · 环境准备（新部署必做，只需一次）

工具依赖 `fastmcp / httpx / jinja2 / playwright` + Playwright Chromium 内核。

```powershell
# Windows：一键引导（创建独立 .venv，装依赖+Chromium，跑自检）
powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1
```
```bash
# macOS / Linux
bash ./bootstrap.sh
```

已装过环境时，只做自检：

```bash
python -m webapi_extractor doctor            # 检查
python -m webapi_extractor doctor --install  # 检查并自动补装缺失项
```

doctor 全绿（端口 WARN 可忽略）后再继续。

> **重要（Windows）**：若全局 Python 的 user site-packages 损坏（pip 报 `WinError 1392` / 扫描 dist-info 崩溃），务必用 bootstrap 创建的独立 `.venv`，它默认禁用 user site，可绕开损坏。

---

## 步骤 0.5 · 如何真正调用这些工具（传输引导）

`probe_login` 等是**本技能自带的 MCP 工具**。若宿主环境没把它们注册成可直接调用的工具，用自带的 HTTP 传输 + 驱动脚本来调：

```bash
# 1) 启动本地 HTTP MCP 服务（脱离宿主进程，全程保持运行）
python start_server.py          # 监听 127.0.0.1:8422/mcp
#   附加开关：
#   python start_server.py --status    # 查看状态（端口/PID/日志）
#   python start_server.py --stop      # 停止
#   python start_server.py --port 8423 # 换端口

# 2) 另开命令，用驱动脚本调用任意工具
python mcp_call.py <tool_name> '<json_arguments>'
#   例： python mcp_call.py list_sessions '{}'
#   例： python mcp_call.py probe_login '{"url":"https://example.com/"}'
#   含 Windows 路径等复杂参数时，用文件或 stdin 传，避开 shell 引号问题：
#   例： python mcp_call.py start_capture @args.json
#   例： echo '{...}' | python mcp_call.py start_capture -
```

> ⚠️ **务必用 `start_server.py` 启动，不要直接在宿主 shell 的后台任务里跑 `run_http.py`。**
> 直接后台运行时，服务进程仍留在宿主 shell 的 **job object** 内；宿主回收 shell 时，
> Windows 会连带终止 job 内所有进程——包括服务本身，以及它通过 Playwright 拉起的
> Chromium 子进程。症状是浏览器窗口**一闪即消失**、端口失去监听，而服务日志末尾完全
> 正常（属被外部终止，非自身崩溃），极易误判成"目标网站有问题"。
> `start_server.py` 用 `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP |
> CREATE_BREAKAWAY_FROM_JOB` 让服务彻底独立，并把日志与 PID 落盘。

`mcp_call.py` 会把会话 id 缓存到 `.mcp_session`，多次调用复用同一服务进程（会话状态在内存里，**服务不能中途重启**）。

> **Windows 传参**：JSON 里路径用正斜杠 `C:/dir/file.json`（反斜杠破坏 JSON 转义）；复杂参数一律走 `@file` / stdin。

数据目录默认 `~/.webapiextractor`，可用环境变量覆盖（见文末）。

---

## 步骤 1 · 探测登录方式

调用 `probe_login(url)`（SPA 友好：domcontentloaded + 登录入口探测，超时可用 `WEB_API_EXTRACTOR_PROBE_TIMEOUT` 调）。
- `confidence >= 0.8` 且 `auth_mode == "form"` → 可尝试 `http_login`。
- 否则（含 SPA/弹窗登录/超时）→ 走交互式登录（步骤 2）。

## 步骤 2 · 登录（拿到 auth_state）

优先 `open_browser_login(url)` → 轮询 `get_login_status(login_session_id)`。

登录完成判定为**三层信号**（页内按钮不作主机制：CSP/iframe/SSO 弹窗会使其失效）：
1. **主（自动）**：目标域出现 token/session Cookie 且稳定 5 秒 → 自动 `completed`；
2. **备（页外）**：extractor 弹出**系统原生对话框**，用户点「是」；
3. **兜底（带外）**：60 秒无凭据证据 → 状态转 `waiting_user_confirm`，Agent 询问用户后调 `confirm_login(login_session_id)`。

`http_login` 返回 `fallback=interactive` 时，改用 `open_browser_login`。

**兜底做法（推荐，抓包登录合一）**：直接给 `start_capture` 传**种子 auth_state**：

```bash
echo '{"cookies": [], "origins": []}' > "<数据目录>/auth_states/seed.json"
python mcp_call.py start_capture '{"url":"https://example.com/","auth_state_path":"C:/.../auth_states/seed.json"}'
```

## 步骤 3 · 抓包

- 带 `auth_state_path` 的 `start_capture` 会**直接进入 `capturing`**；不带的先 `authenticating`，登录后自动转（同三层证据标准），或用户点页内「登录完成」，或 Agent 调 `confirm_login_ready(session_id)`。
- 告诉用户：**在弹出的浏览器里正常操作目标功能**，操作完回来告知。
- `get_capture_status` 看进度，`stop_capture` 结束；空闲超时自动 `paused` 可 `resume_capture`。

## 步骤 4 · 分析

`analyze_traffic(session_id)` → 返回**精简摘要**（host 分布 + 接口清单 + 各 host 鉴权 scheme + crypto 标记 + `full_result_path`）。分析器已内置：
- **噪音标记**（`noise: true`，不删除，生成时默认跳过）：埋点/心跳/面包屑/菜单配置/第三方统计域名；
- **命名参数化**：单样本数字段也参数化（`/user/127733/info` → `/user/{user_id}/info`），同构自动合并；
- **登录接口识别**：识别「账号+密码换 token」接口 → `auth_login`（含密码加密策略与 PEM 公钥提取），生成阶段转为 `login()`/`auth_status()` 专用工具；
- **站点档案**：example 等已知站点自动应用语义化命名与中文描述（`site_profiles/`）。

用 `update_endpoint(session_id, endpoint_id, description=...)` 补充/修正描述。

## 步骤 5 · 加密与凭据核实（强制，禁止跳过）

> **硬规则：抓包中的凭据字段值必然被脱敏为 `***`，明文与密文在此不可区分。禁止假设，必须核实。**

核实手段（按可靠性排序）：
1. **URL 查询参数** — `encrypt=2` / `version=2` / `sign` 之类（最可靠信号）；
2. **形态元数据**（脱敏边车）— 保留了 `len`/`shape`：如 RSA-2048 密文恒为 344 字符 base64；
3. **前端 JS** — `crypto.subtle` / `JSEncrypt` / `CryptoJS` / `sm2` 调用与 PEM 公钥块；
4. **故意发一次明文请求看错误码** — 500（解密失败）vs 业务错误码（参数错）。

`analyze_traffic` 的 `crypto_found` 为 true 时调用 `extract_crypto_logic(session_id)` 查看明细。

> ⚠️ **不要假设「CDP 拿到的一定是明文」**。CDP 捕获的是网络层实际发出的字节，可能已被 JS 加密；加密后的值同样会被抓到（且按字段名脱敏后更难察觉）。按明文实现会撞 500。

## 步骤 6 · 生成（registry 项目）

`generate_mcp_server(session_id, output_dir, endpoint_ids=[...])` → 生成**项目**：

```
<output_dir>/
├─ project.json / registry.json   # registry 为唯一事实源
├─ server.py                       # 多域名路由 + 类型化参数 + 按实测 scheme 鉴权
├─ requirements.txt / .env.example / README.md / smoke_test.py
└─ captures/                       # 各轮合并的 provenance
```

生成器能力：
- **多域名路由** + **类型化签名**（query/path 样本 → `page: int = 1`）；
- **默认值门槛**：仅多轮采样稳定、短、纯 ASCII、无逗号且非身份/时间类的参数才有默认值（防隐私泄漏与过期默认值）；
- **鉴权按实测**：Basic/Bearer/Cookie 分别生成；
- **写操作护栏**：非 GET 工具需 `confirm=true`，写 audit.log；
- **登录工具**（识别到 auth_login 时）：`login()` / `auth_status()`——凭据与 token **DPAPI 加密持久化**（`cred_cache.bin`/`token_cache.bin`，仅同一 Windows 用户可解密，已列 .gitignore），重启自动恢复，**401 自动重登录并重试一次**；密码按前端实测策略加密传输；
- **用户态诊断**：`tool_catalog`（含 registry_version）/ `error_log_tail`。

### Basic 口令验证（必做）

抓包发现 `Authorization: Basic` 时，前端 JS 里的固定口令**可能是装饰性的，服务端并不校验**。生成前做对照实验：带该头发一次、不带头再发一次——两次都成功则口令留空即可，不要把「缺 Authorization 头」当成错误第一嫌疑（曾误导一轮排障）。

## 步骤 7 · 持续迭代（IT 管理态专属）

初次抓包漏掉的 API，补一轮抓包后**增量合并**，而非推倒重建：

```
再抓一轮遗漏功能 → analyze_traffic
→ diff_capture(project_dir, session_id)                     # 只读差异报告
→ 与用户确认报告
→ merge_capture(project_dir, session_id, endpoint_keys?)    # version+1
→ regenerate_server(project_dir)                            # 从 registry 重出代码，旧文件留 .bak
→ export_project(project_dir, out_dir)                      # 导出用户态分发包
```

安全语义：
- **用户态物理隔离**：分发包的 server.py 不含也不 import 任何 registry 写入代码——Agent 无法通过子 MCP 修改工具集，只能调用与只读诊断；
- **locked**：`project.json` 置 `locked:true` 后 merge/regenerate 均拒绝，解锁须人工改文件；
- 端点一轮没抓到只标 `unseen_since`，**永不自动删除**；合并只增不改默认值（向后兼容）；鉴权 scheme 变化必须 `allow_auth_change=true` 显式确认。

---

## 数据目录与环境变量

```
~/.webapiextractor/
├─ sessions/<id>/{capture.jsonl, analysis.json, session.json, scripts/}
├─ auth_states/<site>.json      # 登录态，含敏感数据，勿提交/截图
└─ audit.log                    # 工具调用审计
```

| 变量 | 默认 | 说明 |
|---|---|---|
| `WEB_API_EXTRACTOR_DATA` | `~/.webapiextractor` | 数据根目录 |
| `WEB_API_EXTRACTOR_RESPONSE_LIMIT` | `262144` | 响应体截断上限(字节) |
| `WEB_API_EXTRACTOR_IDLE_TIMEOUT` | `300` | 空闲自动暂停(秒) |
| `WEB_API_EXTRACTOR_MAX_SESSIONS` | `3` | 并发抓包会话上限 |

---

## 排错速查

| 现象 | 原因 | 处理 |
|---|---|---|
| 工具无法调用 / 找不到 `probe_login` | 宿主未注册本技能工具 | 用步骤 0.5：`start_server.py` + `mcp_call.py` |
| 浏览器「打开后立刻消失」、端口无监听 | 服务被宿主 shell 的 job 回收 | 用 `start_server.py` 启动（见步骤 0.5），勿直接后台跑 `run_http.py` |
| `mcp_call.py` 报 `Invalid \escape` | Windows 路径反斜杠 | 路径改用正斜杠，或用 `@file` / stdin 传参 |
| `open_browser_login` 秒完成、没等我登录 | 旧版检测缺陷 | 已修（三层信号）；仍异常时用种子 auth_state 兜底 |
| `start_capture` 一直 `authenticating`、抓不到 | 未登录置位 | 传 `auth_state_path`；或 `confirm_login_ready`；或点页内「登录完成」 |
| doctor 报缺 Chromium | 内核未装 | `python -m playwright install chromium` 或 `doctor --install` |
| pip 报 `WinError 1392` / dist-info 损坏 | 全局 user site 损坏 | 用 bootstrap 的独立 `.venv` |
| `analyze_traffic` 摘要不够看 | 完整 Schema 更大 | 读返回里的 `full_result_path`（analysis.json） |
| 端口 8422 被占 | 服务已在跑或冲突 | 复用已运行服务，或改 `run_http.py` 端口 |
| 生成的工具 401 | Basic 口令没填 | scheme 已按实测生成；在 `.env` 填 `<前缀>_BASIC_PASSWORD_<HOST>`（抓包 scripts/ 搜 `btoa(` 找固定串）与 token |
| merge/regenerate 被拒 `project_locked` | 项目被锁定 | 人工编辑 project.json 的 locked 字段解锁 |
| 生成的工具 401 后未自动重登录 | 无登录配置或无凭据 | 确认 auth_login 已识别；调用一次 login() 或在 .env 配凭据（之后走加密缓存） |
| 想清除已保存的凭据/token | — | 删除项目目录下 cred_cache.bin / token_cache.bin（均为加密文件） |
| PowerShell 下 bootstrap 段错误 | 受限环境 | 用纯 Python 引导：`python bootstrap.py` |
