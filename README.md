# Web API Extractor

这是一个“由 Agent 唤起、由浏览器真实交互驱动、并生成目标站点 MCP 工具”的 Skill 包。

它不是一个普通的独立脚本程序；它的定位是：
- 作为 Skill 被 Agent 调用和唤起
- 通过浏览器自动化监测用户与目标网站的真实操作
- 监听并整理真实网络请求/响应
- 识别认证流程、接口路径与参数结构
- 最终生成可以对接目标站点的 Python + FastMCP 工具代码

一句话概括：

“它不直接给你一个静态 API 列表，而是让 Agent 在真实站点上完成登录、操作、抓包、分析和生成，最终产出一个可用于对接该网站的 MCP 工具。”

---

## 这个项目能做什么

- 让 Agent 识别目标站点是否需要登录
- 监控用户在真实网站中的操作过程
- 支持普通表单登录、HTTP 登录与交互式浏览器登录
- 通过 CDP / Playwright 监听真实请求和响应
- 过滤静态资源、JS 跟踪、无用请求和噪音流量
- 把接口归一化，例如 `/orders/123` 和 `/orders/456` 合并为 `/orders/{id}`
- 识别鉴权字段、Cookie、Token、认证头及数据结构
- 生成符合目标站点的 Python + FastMCP MCP 工具代码
- 让 Agent 自动化完成“页面行为 → API 抽取 → 工具生成”的闭环

---

## 适合谁

- 需要从真实网站中提取并整理 API 的开发者
- 需要让 Agent 自动生成站点适配 MCP 工具的使用者
- 希望把“浏览器交互 → 接口归并 → 代码生成”整条链路交给 AI 自动化的人
- 需要把这个能力作为 Skill 导入到 Agent 环境中并由 Agent 主动调用的人

它不是一个“纯 API 接口库”，也不是一个单独的通用脚本工具。它更像是一个用于“站点行为观测与 API 发现”的 Agent Skill：
- Agent 负责唤起它
- 用户在目标站点中执行真实操作
- 这个 Skill 负责记录实际请求与响应
- 最终生成对接该站点的 MCP 工具代码

如果你想把它当作复用能力包使用，最正确的方式不是单独运行 Python 脚本，而是把整个项目压缩包导入 Agent 的 Skill / 工具目录，随后由 Agent 负责唤起和执行。`SKILL.md` 就是这个入口文件。

---

## 使用前须知

### 许可说明

本项目的使用边界与授权约束已单独写入 [LICENSE](LICENSE)。

- 允许个人学习、测试和非商业自用
- 修改后再分发须保留原始来源说明
- 基于本项目开发的衍生工作应当开源
- 不允许直接商用

如需正式法律依据，请以 [LICENSE](LICENSE) 为准。

### 免责声明（适用范围）

本项目仅用于合法合规的开发、测试、接口分析、文档生成、集成验证与合规评估场景，目的在于帮助用户研究、理解和管理自己拥有授权的系统接口行为。

使用者必须遵守中华人民共和国法律法规以及使用者当地适用法律，并自行确认其使用行为的合法性。

下列用途均不被视为本项目的合法用途：

- 用于未经授权的系统探测、攻击、绕过认证、破坏服务可用性或违反网站/平台使用条款的行为
- 用于窃取、泄露、篡改、篡用他人数据或敏感信息
- 用于非法访问、非法抓取、非法分析或非法加工受保护的接口与数据
- 用于造成目标系统宕机、服务中断、拒绝服务或其他对他人合法权益造成损害的行为
- 用于任何违反适用法律、合同、行业规范和安全要求的目的

本项目不提供、也不应被用于任何违法、违规或有潜在损害性的场景。

本项目仅对“合法、授权、审慎、可控”的使用方式提供技术支持；对使用者基于本项目进行的任何行为，开发者均不承担责任。若使用者将本项目用于外部系统接口分析、调试、演示、测试或生产环境，必须事先确认其具备相应授权、合法依据和安全责任。

在任何情况下，使用者都应自行负责遵守当地法律、行业规范、目标系统许可协议、隐私保护要求和网络安全要求。

---

## 目录结构

```text
WebAPIExtractor/
├─ README.md                 # 项目说明
├─ SKILL.md                  # Skill 使用说明
├─ pyproject.toml            # Python 包配置
├─ requirements.txt          # 依赖
├─ webapi_extractor/          # 主代码目录
│  ├─ __init__.py
│  ├─ __main__.py
│  ├─ analyzer.py             # 请求分析、路径归一化、Schema 识别
│  ├─ audit.py               # 审计日志
│  ├─ auth.py                # 登录流程
│  ├─ capture.py             # 浏览器/CDP 抓包
│  ├─ config.py              # 配置和环境变量
│  ├─ control_bar.py         # 页面控制条
│  ├─ crypto_analyzer.py     # 加密/密文检测
│  ├─ generator.py           # 生成 FastMCP 服务
│  ├─ login_detector.py      # 登录成功检测
│  ├─ probe.py               # 登录探测
│  ├─ redaction.py           # 脱敏
│  ├─ server.py              # MCP Server 与工具注册
│  └─ storage.py             # 会话存储与恢复
└─ .vscode/                  # 通用 Agent 配置
```

---

## 快速开始

这里的“快速开始”指的是本地环境准备和底层运行方式；但它的主使用方式并不是把它当作普通独立程序来运行，而是把它作为 Agent Skill 导入并由 Agent 主动唤起。

### 1）安装依赖

```powershell
cd D:\MCP\WebAPIExtractor
python -m pip install -r requirements.txt
```

### 2）安装浏览器依赖

```powershell
python -m playwright install chromium
```

### 3）本地启动底层 MCP 服务（仅供调试/工具链运行）

```powershell
python -m webapi_extractor
```

如果你正在一个支持 MCP 工具调用的环境中使用它，那么真正的流程不是“直接运行程序”，而是：

1. 把整个项目导入 Agent 的 Skill / 工具目录
2. 由 Agent 识别 `SKILL.md`
3. Agent 让用户在目标站点中完成真实操作
4. Skill 监听真实请求并生成目标站点的 MCP 工具代码

---

## 典型使用流程

### 方式 1：Agent 作为主调度器（正确主路径）

1. 把项目压缩包导入 Agent 支持的 Skill/工具目录
2. Agent 识别 `SKILL.md` 并理解它是一个站点交互分析 + API 提取 + MCP 生成 Skill
3. Agent 调用 `probe_login(url)` 判断站点是否需要登录
4. 若需要登录，则调用 `http_login(...)` 或 `open_browser_login(...)`
5. 用户在目标站点中执行真实业务操作
6. Agent / Skill 通过 `start_capture(...)` 监听浏览器网络请求
7. 调用 `analyze_traffic(session_id)` 识别与整理 API
8. 通过 `update_endpoint(...)` 修正描述与备注
9. 调用 `generate_mcp_server(...)` 生成目标站点适配的 MCP 工具

这是这个项目的真实主流程：Agent 发起、用户操作、Skill 观察与生成。

### 方式 2：已登录站点

1. 先准备已有的 auth state 文件
2. 调用 `start_capture(url, auth_state_path=...)`
3. 直接在浏览器里继续操作
4. 结束后调用 `stop_capture(session_id)`
5. 执行分析和生成

### 方式 3：底层 MCP 工具链调用（仅作为执行接口）

1. `probe_login(url)`
2. `http_login(...)` 或 `open_browser_login(...)`
3. `start_capture(...)`
4. `stop_capture(session_id)`
5. `analyze_traffic(session_id)`
6. `generate_mcp_server(session_id, output_dir, endpoint_ids)`

这个路径是底层工具接口，不是它的核心设计。

---

## 关键模块说明

### server.py
这个文件最重要，它负责把能力暴露成 MCP 工具。

它主要提供这些能力：
- `probe_login()`
- `http_login()`
- `open_browser_login()`
- `get_login_status()`
- `start_capture()`
- `get_capture_status()`
- `stop_capture()`
- `resume_capture()`
- `list_sessions()`
- `analyze_traffic()`
- `update_endpoint()`
- `generate_mcp_server()`
- `extract_crypto_logic()`

### capture.py
负责抓包。它用 Playwright + CDP 监听网络事件，收集请求、响应和响应体，并写入 `capture.jsonl`。

### analyzer.py
负责整理抓到的请求，并做路径归一化。

例如：
- `/orders/123`
- `/orders/456`
- `/orders/latest`

会被归一化成：
- `/orders/{id}`
- `/orders/latest`

### generator.py
负责把分析结果转成一份可运行的 Python/FastMCP 服务代码。

输出包括：
- `server.py`
- `requirements.txt`
- `.env.example`
- `README.md`
- `smoke_test.py`

### auth.py / login_detector.py
负责认证逻辑。它不仅支持直接登录，还支持“登录检测成功后继续收集”，而不是简单地登录完就关掉浏览器。

这也是这个项目和传统单纯 MCP 的关键区别：
- 它是“登录 → 操作 → 抓包 → 分析 → 生成”一条链路
- 不是只提供几个接口调用工具

---

## 数据目录说明

默认数据目录：

```text
~/.webapiextractor/
├─ sessions/
│  └─ {session_id}/
│     ├─ capture.jsonl
│     ├─ session.json
│     ├─ analysis.json
│     └─ ...
├─ auth_states/
│  └─ {site}.json
├─ audit.log
└─ ...
```

说明：
- `sessions/`：保存每次抓包会话
- `auth_states/`：保存登录后的认证状态，里面是敏感数据，不能随意提交
- `audit.log`：审计日志，用于记录工具调用

如果需要自定义目录，可以用环境变量：

```powershell
$env:WEB_API_EXTRACTOR_DATA = "D:\web-api-extractor-data"
$env:WEB_API_EXTRACTOR_RESPONSE_LIMIT = "262144"
$env:WEB_API_EXTRACTOR_IDLE_TIMEOUT = "300"
```

---

## 这是 Skill，还是 MCP？

结论：它同时包含两层能力，但最核心的定位是 Skill。

### 1）底层是 MCP Server
它暴露了一组工具，供 Agent / MCP Client 调用，例如：
- `probe_login()`
- `http_login()`
- `open_browser_login()`
- `start_capture()`
- `analyze_traffic()`
- `generate_mcp_server()`

这些是它运行时的工具层接口。

### 2）上层是 Agent 可唤起的 Skill
真正的使用方式不是“直接拿一个 Python 程序当脚本跑”，而是：
- Agent 识别这个 Skill
- Agent 调用它来检测站点是否需要登录
- Agent 让用户在真实页面中执行操作
- Skill 监测浏览器交互，抓取真实请求
- Skill 分析接口、补全描述、识别认证和参数结构
- 最终生成目标站点的 MCP 工具代码

所以它不是“一个普通程序 + 一组 MCP 方法”，而是“一个围绕真实站点交互展开的 Agent Skill，并在内部附带 MCP 执行接口”。

---

## 适合的使用姿势

最核心的使用形式是：Agent 唤起 Skill，而不是用户直接以普通程序方式使用。

### 方式 1：作为 Agent Skill 运行（推荐）

1. 把整个项目压缩包解压后导入到支持 Skill 的 Agent 环境
2. Agent 识别 `SKILL.md` 和该项目的能力描述
3. Agent 根据用户目标决定是否调用 `probe_login()`
4. 如果站点需要登录，调用 `http_login()` 或 `open_browser_login()`
5. 用户在目标站点里完成真实操作
6. 用 `start_capture()` 监听实际网络请求
7. `analyze_traffic()` 抽取接口并整理结构
8. `update_endpoint()` 修正描述和补充注释
9. `generate_mcp_server()` 生成对接该站点的 MCP 工具

这是真正的主路径：Agent 负责组织、用户负责操作站点，Skill 负责观察和生成。

### 方式 2：作为 MCP 工具链调用

如果你已经在一个能调用 MCP 工具的环境中运行它，也可以按底层工具顺序调用：

1. `probe_login(url)`
2. `http_login(...)` 或 `open_browser_login(...)`
3. `start_capture(...)`
4. `stop_capture(session_id)`
5. `analyze_traffic(session_id)`
6. `generate_mcp_server(session_id, output_dir, endpoint_ids)`

这个路径是底层执行接口，不是它的主设计定位。

### 方式 3：作为辅助的命令行入口

`python -m webapi_extractor` 这种形式主要是为了让 MCP 服务本身能启动；它不是这个项目的核心使用方式。

---

## 关键设计判断

这个项目的核心价值，不在于把它当成一个“单独运行的软件”，而在于：

- 它依赖真实用户操作和浏览器行为
- 它通过观察真实请求来发现接口
- 它把“网页行为”转成“可调用 API 结构”
- 它最终生成一个能够对接目标站点的 MCP 工具

这就是它作为 Skill 的意义，而不是普通脚本的意义。

---

## 注意事项

- 它会抓真实网络请求，所以请在测试站点或授权站点中使用
- 对敏感字段做了脱敏，但仍建议不要把认证数据放进仓库
- 生成的接口工具可能具有真实副作用，写接口默认要特别小心
- `generate_mcp_server()` 的默认策略是“只生成已确认的接口”，不要一次性全量生成

---

## 结论

这个仓库的核心价值不是“单纯转一个 URL 到接口列表”，而是：

“从真实浏览器行为中，自动发现 API、提炼认证方式、生成可运行的 MCP 工具。”

这也正是它作为 Skill 的意义：它不只是能调用接口，而是能帮助 Agent 真正完成从页面操作到接口生成的整条链路。

---

## 性能考量
- 响应体限制：通过 WEB_API_EXTRACTOR_RESPONSE_LIMIT 控制响应体大小，避免大响应拖慢写入与分析。
- 空闲超时：WEB_API_EXTRACTOR_IDLE_TIMEOUT 控制无操作自动暂停，减少资源占用。
- 并发上限：WEB_API_EXTRACTOR_MAX_SESSIONS 限制同时捕获会话数量，防止浏览器与 CPU 过载。
- 批量写入：事件队列批处理 flush，降低 I/O 频率。
- 脚本保存：仅保存脚本片段以节省磁盘空间。

[本节为通用性能指导，不直接分析具体文件]

## 故障排查指南
- 会话未找到：检查 session_id 是否正确，确认 analyze_traffic 前先完成捕获。
- 会话不存在或已结束：stop_capture 后状态为 stopped，无法 resume。
- 登录失败：http_login 返回 fallback=interactive 时，改用 open_browser_login 完成交互登录。
- 页面加载超时：probe 或登录阶段可能因网络或站点渲染缓慢导致超时，适当增加超时时间。
- 加密载荷：若 detect_crypto 返回 found=true，需补充密钥或运行时透传逻辑后再调用生成。
- 审计日志：所有工具调用均被审计记录，便于回溯问题。

## 附录：快速开始与使用要点
- 安装与初始化
  - 安装依赖并安装 Chromium 浏览器。
  - 首次使用可执行安装脚本或在 VS Code 中导入 Agent。
- 环境变量
  - 数据目录、响应体限制、空闲超时、最大会话数均可通过环境变量覆盖。
- 基本工作流
  - 认证：优先尝试 http_login，必要时使用 open_browser_login。
  - 捕获：start_capture 后操作网站，完成后 stop_capture。
  - 分析：analyze_traffic 生成 endpoints 与 schema。
  - 生成：generate_mcp_server 输出 FastMCP 客户端与服务端代码。
- 注意事项
  - 敏感数据保存在安全目录，勿提交至版本库。
  - 对于加密站点，先进行加密检测与策略补充。
