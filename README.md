# Web API Extractor

这是一个“浏览器抓取 + 登录识别 + 接口分析 + 代码生成”的工具项目。

## 简介
WebAPIExtractor 是一个基于 FastMCP 协议的自动化 Web API 发现与提取工具。它通过 Playwright 驱动浏览器、利用 CDP（Chrome DevTools Protocol）捕获网络流量，结合智能分析引擎对请求/响应进行归一化与模式识别，最终生成可运行的 Python/FastMCP 客户端代码，实现“从真实浏览器行为到可用接口”的端到端自动化。使用方法见[快速开始](https://github.com/shdawushi-dotcom/WebAPIExtractor/blob/main/Docs/content/%E5%BF%AB%E9%80%9F%E5%BC%80%E5%A7%8B.md)。

它不是单纯的一个 MCP 服务，而是一个可被 Agent / Skill 调用的能力包：
- 下面有一个 FastMCP 的 MCP Server
- 上层也可以被当作 Skill 使用
- 真正的能力来自浏览器自动化、CDP 抓包、登录检测和接口分析

如果你只是想快速知道它是干什么的，可以记住一句话：

“它会在真实网站里登录并操作，然后自动抓取网络请求，识别 API，最后生成一个可运行的 Python + FastMCP 服务。”

---

## 这个项目能做什么

- 自动打开浏览器并访问目标网站
- 检测是否需要登录
- 支持普通表单登录、HTTP 登录和交互式浏览器登录
- 监听页面请求和响应，抓取真实 API 流量
- 过滤静态资源、跟踪脚本和无用请求
- 归一化接口路径，比如 `/orders/123` 和 `/orders/456` 合并成 `/orders/{id}`
- 识别鉴权字段、Cookie、token、认证头
- 生成 Python + FastMCP 的接口封装代码

---

## 适合谁

- 需要从真实网站中抽取 API 的开发者
- 需要快速生成 MCP 工具的 Agent/Skill 使用者
- 想做浏览器行为到接口调用的自动化链路的人

不适合把它当做一个单独的“纯 API 接口库”；它更像是一个真实浏览器行为采集器 + 分析器 + 代码生成器。

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

### 1）安装依赖

```powershell
cd D:\MCP\WebAPIExtractor
python -m pip install -r requirements.txt
```

### 2）安装浏览器依赖

```powershell
python -m playwright install chromium
```

### 3）运行项目

```powershell
python -m webapi_extractor
```

或者安装为命令行工具：

```powershell
python -m pip install -e .
web-api-extractor
```

---

## 典型使用流程

### 方式 1：普通认证站点

1. 调用 `probe_login(url)` 先看这个站点像不像需要登录
2. 如果是简单表单，调用 `http_login(...)`
3. 如果失败，调用 `open_browser_login(...)`
4. 调用 `start_capture(...)` 启动抓包
5. 用户在浏览器里正常操作
6. 调用 `analyze_traffic(session_id)` 分析接口
7. 让用户确认要生成的接口
8. 调用 `generate_mcp_server(...)` 输出代码

### 方式 2：已登录站点

1. 先准备已有的 auth state 文件
2. 调用 `start_capture(url, auth_state_path=...)`
3. 直接在浏览器里继续操作
4. 结束后调用 `stop_capture(session_id)`
5. 执行分析和生成

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

## 这是 Skill 还是 MCP？

结论：它同时具备两层含义。

### 1）它是一个 MCP Server
底层暴露了一组工具，供 Agent / MCP Client 调用。

### 2）它也是一个 Skill 包
它的工作流更像一个 Skill：
- 先判断站点是否需要登录
- 再让用户在浏览器里正常操作
- 抓取实际请求
- 识别接口
- 生成可用代码

所以你不能把它简单理解成“一个只有几个接口的 MCP 小工具”。它更接近“一个 Agent/Skill 能直接拿来用的 Web API 抽取工作流”。

---

## 适合的使用姿势

对于新手，建议按这个顺序理解：

1. 先看 `probe_login()`
2. 再用 `http_login()` 或 `open_browser_login()`
3. 然后 `start_capture()`
4. 用户在页面中操作业务流程
5. `analyze_traffic()` 生成接口列表
6. `update_endpoint()` 修正描述
7. `generate_mcp_server()` 输出代码

这样最符合这个项目的真实使用方式。

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
