# WebAPIExtractor

**让 Agent 陪你打开真实浏览器、完成真实登录与操作，把「你点过的每一个功能」变成可调用的 API，并一键生成对接该站点的 MCP 工具服务器。**

它给你的不是一份静态 API 列表，而是一条完整链路：

```
浏览器真实交互 ──► CDP 全量抓包 ──► 接口归一化/鉴权识别 ──► 人工确认 ──► 生成可运行的 Python + FastMCP 服务
```

---

## 为什么需要它

| 传统做法 | WebAPIExtractor |
|---|---|
| 对着 F12 手工翻请求，复制 curl | 打开浏览器正常使用网站，后台自动记录全部请求/响应 |
| 接口文档靠猜，参数靠试 | 从真实流量归纳参数结构、请求/响应 Schema，路径自动归一化（`/orders/123` + `/orders/456` → `/orders/{id}`） |
| 登录态、token、签名逻辑难复刻 | 识别认证流程（表单/HTTP/交互式），保存可复用的登录态，识别鉴权字段与 token 来源 |
| 拿到接口还要手写胶水代码 | 直接生成 FastMCP 服务器 + 冒烟测试 + 配置模板，写操作自动标记 `[MUTATING]` |
| 抓包数据含敏感信息 | 记录即时脱敏（密码/token/cookie），认证数据存独立安全目录 |

**典型场景**：想给内网 OA、公司系统、无公开 API 的网站做一个 AI Agent 可调用的工具——只要你能用浏览器操作它，WebAPIExtractor 就能把它变成 MCP 工具。

---

## 它能做什么

- 识别目标站点是否需要登录（`probe_login`）
- 支持三种登录方式：表单 / HTTP / 交互式浏览器登录（`http_login` / `open_browser_login`）
- 通过 Playwright + CDP 监听真实请求与响应，记录请求体、响应体、请求头
- 自动过滤静态资源、埋点、跟踪器等噪音流量
- 路径归一化合并同构接口，识别鉴权字段、Cookie、Token 与认证头
- 从流量推断请求/响应 JSON Schema
- 生成适配目标站点的 Python + FastMCP 工具代码（含 requirements / .env 模板 / 冒烟测试 / README）

---

## 快速开始

### 1. 环境准备（新机器只需一次）

```powershell
# Windows：一键引导（创建独立 .venv，安装依赖 + Chromium，跑自检）
powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1
```

```bash
# macOS / Linux
bash ./bootstrap.sh
```

已装过环境，只做检查：

```bash
python -m webapi_extractor doctor             # 自检：依赖 / Chromium / 数据目录 / 端口
python -m webapi_extractor doctor --install   # 自检并自动补装缺失项
```

依赖：Python ≥ 3.10，`fastmcp / httpx / jinja2 / playwright` + Playwright Chromium 内核。

### 2. 启动服务

```bash
python run_http.py        # HTTP 传输，监听 http://127.0.0.1:8422/mcp
# 或 stdio 方式（供 MCP 客户端直接拉起）：
python -m webapi_extractor
```

### 3. 调用工具

如果你的 Agent 环境已注册本技能的 MCP 工具，直接调用即可；否则用自带驱动脚本：

```bash
python mcp_call.py probe_login '{"url":"https://example.com/"}'
```

完整流程（探测登录 → 登录 → 抓包 → 分析 → 生成）见 **SKILL.md**——它是按步骤可照做的操作手册。

---

## 工具一览

| 阶段 | 工具 | 作用 |
|---|---|---|
| 探测 | `probe_login` | 判断站点登录方式（SPA 友好，含登录入口探测） |
| 登录 | `http_login` / `open_browser_login` / `get_login_status` / `confirm_login` | 表单登录 / 交互式登录（三层完成判定）/ 查进度 / 带外确认 |
| 抓包 | `start_capture` / `get_capture_status` / `stop_capture` / `resume_capture` / `confirm_login_ready` | 开始 / 查看 / 结束 / 恢复抓包会话 / 手动置登录完成 |
| 会话 | `list_sessions` | 列出历史会话 |
| 分析 | `analyze_traffic` / `update_endpoint` | 精简摘要+鉴权 scheme / 补充接口描述 |
| 加密 | `extract_crypto_logic` | 检测加密载荷并给出处理策略 |
| 生成 | `generate_mcp_server` | 生成 registry 项目（多域名/类型化参数/实测鉴权） |
| 迭代 | `diff_capture` / `merge_capture` / `regenerate_server` / `export_project` | 只读差异 / 确认合并（version+1）/ 从 registry 重生成 / 导出用户态分发包 |

---

## 典型工作流

```
1. probe_login(url)                        判断登录需求
2. open_browser_login(url)                 弹浏览器，用户完成登录（三层完成判定）
3. start_capture(url, auth_state_path)     带登录态开始抓包
4. 用户在浏览器里正常操作目标功能            （想变成工具的功能都要真实点一遍）
5. stop_capture(session_id)                结束收集
6. analyze_traffic(session_id)             精简摘要 + 各 host 鉴权 scheme
7. update_endpoint(...)                    剔除噪音、补充描述
8. generate_mcp_server(session_id, dir, endpoint_ids)   生成 registry 项目
```

**持续迭代（漏了 API 不用推倒重来）**：

```
再抓一轮遗漏功能 → analyze_traffic
→ diff_capture(project_dir, session_id)                  # 只读差异报告
→ merge_capture(project_dir, session_id, endpoint_keys?) # 合并入 registry，version+1
→ regenerate_server(project_dir)                         # 从 registry 重出代码
→ export_project(project_dir, out_dir)                   # 导出用户态分发包
```

角色分离：**IT 管理态**（装本工具）可 diff/merge/regenerate；**用户态**（只拿分发包）的 server.py 物理上不含任何写入能力，AI Agent 只能调用与只读诊断（`tool_catalog` / `error_log_tail`），无法修改工具集。

> 提示：抓包记录的是**真实用户操作**——你操作了什么，才会发现什么接口。目标功能没点到，接口就不会出现。

---

## 数据目录与环境变量

```
~/.webapiextractor/
├─ sessions/<id>/          # 每次抓包：capture.jsonl / analysis.json / scripts/
├─ auth_states/            # 登录态（含敏感数据，禁止提交/同步/截图）
└─ audit.log               # 工具调用审计日志
```

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `WEB_API_EXTRACTOR_DATA` | `~/.webapiextractor` | 数据根目录 |
| `WEB_API_EXTRACTOR_RESPONSE_LIMIT` | `262144` | 响应体截断上限（字节） |
| `WEB_API_EXTRACTOR_IDLE_TIMEOUT` | `300` | 无操作自动暂停（秒） |
| `WEB_API_EXTRACTOR_MAX_SESSIONS` | `3` | 并发抓包会话上限 |

---

## 许可说明

本项目的使用边界与授权约束以 [LICENSE](LICENSE) 为准：

- 允许个人学习、测试和非商业自用
- 修改后再分发须保留原始来源说明
- 基于本项目开发的衍生工作应当开源
- 不允许直接商用

## 免责声明（适用范围）

本项目仅用于合法合规的开发、测试、接口分析、文档生成、集成验证与合规评估场景，目的在于帮助使用者研究、理解和管理**自己拥有授权的系统**接口行为。

使用者必须遵守中华人民共和国法律法规及当地适用法律，并自行确认其使用行为的合法性。下列用途均不被视为本项目的合法用途：

- 用于未经授权的系统探测、攻击、绕过认证、破坏服务可用性或违反网站/平台使用条款的行为
- 用于窃取、泄露、篡改、篡用他人数据或敏感信息
- 用于非法访问、非法抓取、非法分析或非法加工受保护的接口与数据
- 用于造成目标系统宕机、服务中断、拒绝服务或其他损害他人合法权益的行为
- 用于任何违反适用法律、合同、行业规范和安全要求的目的

本项目不对使用者的任何行为承担责任。将本项目用于外部系统时，使用者必须事先确认具备相应授权、合法依据，并自行承担安全与合规责任。

---

## 常见问题

| 问题 | 处理 |
|---|---|
| 浏览器弹出后秒关 / 登录没完成 | 检查 `get_login_status`；仍异常时给 `start_capture` 传种子 auth_state（`{"cookies":[],"origins":[]}`）直进抓包模式，在抓包浏览器里登录 |
| 抓包一直 `authenticating` 不记录 | 同上：传 `auth_state_path`，或确认登录已置位 |
| doctor 报缺 Chromium | `python -m playwright install chromium` |
| pip 报 `WinError 1392`（dist-info 损坏） | 用 bootstrap 的独立 `.venv`（默认禁用 user site） |
| `mcp_call.py` 报 `Invalid \escape` | JSON 参数里的 Windows 路径改用正斜杠 |
| `analyze_traffic` 返回过大/为空 | 直接读 `sessions/<id>/analysis.json` |
| 生成的工具 401 | 目标站鉴权与生成的 Bearer 不符（如 Basic 站），需按抓包实际 scheme 修正 |
| 端口 8422 被占 | 复用已运行服务，或修改 `run_http.py` 端口 |

---

## 项目结构

```
WebAPIExtractor/
├─ SKILL.md                  # Agent 操作手册（按步骤照做）
├─ README.md                 # 本文件
├─ bootstrap.ps1 / .sh       # 一键环境引导
├─ run_http.py               # HTTP 传输启动器 (127.0.0.1:8422/mcp)
├─ mcp_call.py               # MCP 工具驱动脚本
├─ requirements.txt
└─ webapi_extractor/
   ├─ server.py              # MCP Server 与工具注册
   ├─ auth.py                # 登录流程
   ├─ capture.py             # Playwright/CDP 抓包
   ├─ analyzer.py            # 路径归一化与 Schema 识别
   ├─ generator.py           # FastMCP 代码生成
   ├─ doctor.py              # 环境自检
   ├─ crypto_analyzer.py     # 加密检测
   ├─ login_detector.py      # 登录成功检测
   ├─ redaction.py           # 脱敏
   └─ storage.py / audit.py / config.py / control_bar.py / probe.py
```

---

## 这是 Skill，还是 MCP？

两者都是：**底层是 MCP Server**（暴露 `probe_login`、`start_capture`、`generate_mcp_server` 等工具），**上层是 Agent 可唤起的 Skill**（`SKILL.md` 定义了完整调度流程）。推荐作为 Skill 使用——由 Agent 发起、用户操作站点、它负责观察与生成。
