# 技术参考

> 面向开发与运维。想快速上手请看 [README.md](../README.md)；Agent 的操作流程见 [SKILL.md](../SKILL.md)。

---

## 传统开发 vs 用本技能

对接一个「只有网页界面、没有 API」的系统，两条路的差别在这里：

```mermaid
flowchart TB
    subgraph T["传统做法 —— 输入是文档与推测"]
        direction TB
        T1["找接口文档<br/>（往往不存在）"] --> T2["开 F12 逐条翻请求<br/>猜参数含义"]
        T2 --> T3["自己写鉴权<br/>Cookie / Basic / 密码加密"]
        T3 --> T4["手写胶水代码 → 联调 → 上线"]
        T4 -.->|系统改版| T5["几乎全部重做"]
        T4 -.->|登录过期| T6["再实现一遍"]
    end
    subgraph S["用本技能 —— 输入是你真实的操作"]
        direction TB
        S1["在浏览器里正常用一遍目标功能"] --> S2["自动记录全部流量<br/>CDP 全量抓包"]
        S2 --> S3["自动归纳<br/>参数化 / Schema / 噪音标记<br/>凭据脱敏 / 加密识别"]
        S3 --> S4["生成可运行项目<br/>多域名路由 + 实测鉴权<br/>写操作护栏 + 冒烟测试"]
        S4 --> S5["上线"]
        S5 -.->|系统改版| S6["再操作一遍 → diff → merge<br/>只补差异"]
        S5 -.->|登录过期| S7["重新授权一次<br/>覆盖同一份登录态"]
    end
```

### 具体省在哪

| 传统做法 | 用本技能 |
|---|---|
| 对着 F12 手工翻请求、复制 curl | 打开浏览器正常使用网站，后台自动记录全部请求/响应 |
| 接口文档靠猜，参数靠试 | 从真实流量归纳参数结构、请求/响应 Schema；同构接口自动合并（`/user/123` + `/user/456` → `/user/{user_id}`） |
| 登录态、token、密码加密逻辑难复刻 | 识别账号密码登录接口（含密码加密策略与公钥提取），生成的 MCP 自带 `login()`，凭据加密持久化、401 自动重登录（**仅识别到登录接口时**；纯 Cookie / SSO 站点走交互式授权，见「续期语义」） |
| 拿到接口还要手写胶水代码 | 直接生成 registry 项目：多域名路由 + 类型化参数 + 实测鉴权 + 写操作护栏 + 冒烟测试 |
| 抓包数据含敏感信息，得人工清洗 | 记录即时脱敏（值抹掉但保留长度/形态元数据，明密文仍可区分）；凭据/Token 走系统级加密存储 |
| 初次漏抓的 API 要推倒重来 | registry 增量迭代：再抓一轮 → diff → merge → regenerate |

### 本质差别

传统路径的输入是**文档与推测**，本技能的输入是**你真实的操作**。这决定了三件事：

- **不需要文档** —— 没有 API 文档的系统一样能做，包括带验证码、短信验证、SSO 的内部系统
  （这类站点走交互式授权，**没有自动重登录**）；
- **不需要猜参数** —— 参数结构来自真实流量，而不是从 JS 里反推；
- **改版成本低** —— 端点只标 `unseen_since`、**永不自动删除**，所以增量合并即可，不必推倒重建。

---

## 安装形态

**A. 作为技能导入（推荐，使用者走这条）** —— 把技能文件夹（或 `web-api-extractor-agent.zip`
导入包）拖进 AI 助手的「技能 / Skill」设置页；或直接拖进对话，让 Agent 自己装。
**使用者不需要装库、也不需要跑任何命令**，首次使用的运行环境（含浏览器内核）由 Agent
引导完成（见下「环境准备」）。

技能文件夹里的 `SKILL.md`、`runbook/`、`bootstrap.*`、`start_server.py`、`mcp_call.py`
都是**给 Agent 消费**的文件，`docs/reference.md`（本文件）是给人看的技术文档。
`web-api-extractor-agent.zip` 由 `package-agent.py`（跨平台）或 `package-agent.ps1`（Windows）
打包 —— 两份脚本的清单与产物一致，用哪份都行；内容与技能文件夹相同。

**B. 从源码用（自己动手 / 二次开发）** —— 本节以下内容都是给这类使用者的。
**本项目未发布到 PyPI，必须先从源码取用。**

```bash
git clone https://github.com/SH-DaWushi/web-api-extractor.git
cd web-api-extractor
```

作为 Python 库可编辑安装：

```bash
pip install -e .
python -m playwright install chromium
```

此时入口为 `web-api-extractor`（stdio，见 `pyproject.toml` 的 `[project.scripts]`）与
`python -m webapi_extractor serve-http`；仓库内的驱动脚本（`mcp_call.py`、`start_server.py`
等）不在发行包里。注意 `pip install -e .` **不会**装测试运行器，跑测试需另装
`pytest` / `pytest-asyncio`，否则 `asyncio_mode=auto` 会被静默忽略（详见「测试」）。

### 环境准备

```bash
# 推荐：纯 Python 引导（受限环境免疫，不依赖 PowerShell/bash）
python bootstrap.py

# 或平台脚本引导（创建独立 .venv，装依赖 + Chromium，跑自检）
powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1   # Windows
bash ./bootstrap.sh                                        # macOS / Linux
```

> `bootstrap.sh` 与 macOS / Linux 命令属"尽力而为"，未做完整验证；完整支持平台见「平台矩阵」。

已装过环境，只做检查：

```bash
python -m webapi_extractor doctor             # 自检：依赖 / Chromium / 数据目录 / 端口
python -m webapi_extractor doctor --install   # 自检并自动补装缺失项
```

依赖：Python ≥ 3.10，`fastmcp / httpx / playwright` + Playwright Chromium 内核。

---

## 启动服务

```bash
# HTTP 传输（推荐）：务必用 start_server.py
python start_server.py              # 监听 http://127.0.0.1:8422/mcp
python start_server.py --status     # 查看状态（端口 / PID / 日志）
python start_server.py --stop       # 停止
python start_server.py --port 8423  # 换端口

# 或 stdio 方式（供 MCP 客户端直接拉起）：
python -m webapi_extractor
```

> ⚠️ **不要用宿主 shell 的「后台任务」方式直接跑 `run_http.py`** —— 该脚本自己的
> docstring 也是这么写的。那样进程仍留在宿主 shell 的 job object 内，宿主回收
> shell 时，服务连同它拉起的 Chromium 会被一起杀掉：症状是浏览器窗口**一闪即消失**、
> 端口失去监听，而日志末尾完全正常，极易误判成「目标网站有问题」。
> `start_server.py` 用 `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP |
> CREATE_BREAKAWAY_FROM_JOB` 让服务彻底独立，并把日志与 PID 落盘。

### 调用工具

宿主环境已注册本技能的 MCP 工具时直接调用；否则用自带驱动脚本：

```bash
python mcp_call.py probe_login '{"url":"https://example.com/"}'
# 复杂参数（含 Windows 路径）用文件或 stdin 传，避开 shell 引号问题：
python mcp_call.py start_capture @args.json
echo '{...}' | python mcp_call.py start_capture -
```

`mcp_call.py` 把会话 id 缓存到 `.mcp_session`，多次调用复用同一服务进程
（会话状态在内存里）。**服务中途重启会让已缓存的会话失效**，但驱动脚本检测到后会
自动重新初始化会话并重试一次（`.mcp_session` 自愈，见 `mcp_call.py` 的 `_is_stale`）。

> **Windows 传参**：JSON 里路径用正斜杠 `C:/dir/file.json`（反斜杠破坏 JSON 转义）。

---

## 工具清单（21 个）

| 阶段 | 工具 | 作用 |
|---|---|---|
| 探测 | `probe_login` | 判断站点登录方式（SPA 友好，含登录入口探测） |
| 登录 | `http_login` / `open_browser_login` / `get_login_status` / `confirm_login` / `request_login_confirm_dialog` | 表单登录 / 交互式登录 / 查进度 / **用户确认登录完成** / 系统对话框兜底确认 |
| 抓包 | `start_capture` / `get_capture_status` / `stop_capture` / `resume_capture` / `confirm_login_ready` / `request_capture_confirm_dialog` | 开始 / 查看 / 结束 / 恢复抓包 / 确认已登录、开始记录 / 同上，改用系统对话框让用户点选 |
| 会话 | `list_sessions` | 列出历史会话 |
| 分析 | `analyze_traffic` / `update_endpoint` | 精简摘要 + 鉴权 scheme / 补充接口描述 |
| 加密 | `extract_crypto_logic` | 加密检测：URL 参数信号 + 密文形态 + JS 公钥 |
| 生成 | `generate_mcp_server` | 生成 registry 项目 |
| 迭代 | `diff_capture` / `merge_capture` / `regenerate_server` / `export_project` | 只读差异 / 确认合并（version+1）/ 从 registry 重生成 / 导出用户态分发包 |

### 工具参数速查（衔接键与容易漏的参数）

- `analyze_traffic` 返回的 `endpoints[].endpoint_id` 是**衔接键**：`update_endpoint` 与
  `generate_mcp_server(endpoint_ids=[...])` 都用它；不传 `endpoint_ids` 则生成全部端点。
- `update_endpoint(session_id, endpoint_id, description=None, notes=None)`：`notes` 是自由文本备注，
  与 `description`（工具描述，会进生成物的工具清单）分开。
- `generate_mcp_server(..., endpoint_ids=None, language="python", framework="fastmcp")`：
  目前仅支持 python + fastmcp，其它取值直接报错。
- `merge_capture(..., endpoint_keys=None, allow_auth_change=False)`：`endpoint_keys` 形如
  `["GET|api.example.com|/pets"]`；**鉴权 scheme 变化必须显式传 `allow_auth_change=true`**。
- `http_login(url, username, password, login_endpoint=None)`：给了 `login_endpoint` 才按 JSON POST
  登录，否则取首页第一个表单提交。
- `start_capture(url, auth_state_path=None, session_id=None)`：`session_id` 可由调用方自定。
- 噪音端点的保留开关 `include_noise` 是 `project.py` 内部函数参数，**MCP 工具层不暴露**。

---

## 典型工作流

编号与 [`SKILL.md`](../SKILL.md) 的 7 步流程一一对应。

```
1. bootstrap → doctor                            环境准备（新机器只需一次）
2. probe_login(url)                              判断登录需求
   open_browser_login(url)                       弹浏览器 → 用户完成登录
   → 问用户 → confirm_login(login_session_id)     登录完成只由用户确认，不自动判定
3. start_capture(url, auth_state_path)           带登录态开始抓包
   ↳ 用户在浏览器里正常操作目标功能                 （想变成工具的功能都要真实点一遍）
   ↳ stop_capture(session_id)                     操作完结束收集
4. analyze_traffic(session_id)                   精简摘要：噪音标记 / 命名参数化 / 登录接口识别
5. 凭据与加密核实（强制，禁止跳过）                抓包中凭据必然是 ***，禁止假设明文，四层手段核实
6. generate_mcp_server(session_id, dir, endpoint_ids)   生成 registry 项目
7. diff_capture → merge_capture → regenerate_server → export_project   持续迭代
```

**持续迭代（漏了 API 不用推倒重来）**：命令序列与注意事项见
[`runbook/06-iterate.md`](../runbook/06-iterate.md)，本节只定义语义 —— `registry.json` 由 merge
维护、每次合并 `version+1`、端点一轮没抓到只标 `unseen_since`（**永不自动删除**）。

> 提示：抓包记录的是**真实用户操作**——你操作了什么，才会发现什么接口。

---

## 数据目录与环境变量

```
~/.webapiextractor/
├─ sessions/<id>/          # 每次抓包：capture.jsonl / analysis.json / session.json / scripts/
├─ auth_states/<site_key>.json   # 登录态（**明文**，禁止提交/同步/截图），文件名规则见「安全设计」
└─ audit.log               # 工具调用审计日志
```

环境变量的**完整清单以本表为准**；实现见 `webapi_extractor/config.py`（**例外**：
`WEB_API_EXTRACTOR_PROBE_TIMEOUT` 实现在 `probe.py`，不在 `config.py`）。

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `WEB_API_EXTRACTOR_DATA` | `~/.webapiextractor` | 数据根目录 |
| `WEB_API_EXTRACTOR_RESPONSE_LIMIT` | `262144` | 响应体截断上限（字节） |
| `WEB_API_EXTRACTOR_IDLE_TIMEOUT` | `300` | 无操作自动暂停（秒） |
| `WEB_API_EXTRACTOR_MAX_SESSIONS` | `3` | 并发抓包会话上限 |
| `WEB_API_EXTRACTOR_PROBE_TIMEOUT` | `15000` | 登录探测超时（毫秒） |
| `WEB_API_EXTRACTOR_NOISE_RESPONSE_BYTES` | `1048576` | 单端点累计响应体超此值 → 标记待复核 |
| `WEB_API_EXTRACTOR_NOISE_SAMPLE_COUNT` | `50` | 单端点采样次数超此值 → 标记待复核 |

### 数据目录体积与响应上限语义

- **响应上限不是「截断」，是整条丢弃**：`WEB_API_EXTRACTOR_RESPONSE_LIMIT`（默认 256 KB）按
  **解码后字节数**判定；超限的响应体整条不记录，只留 `size` / `body_truncated` / `body_dropped`
  元数据。**后果**：该端点拿不到 `response_schema`，生成的工具也就没有结构化响应。
  需要时调高该变量并重抓一轮。
- **`capture.jsonl` 只追加，无轮转、无保留期**：静态资源（图片 / JS / CSS）的响应体也照写，
  长会话会持续增长，需人工清理。脚本类响应另存 `sessions/<id>/scripts/`（每个最多取前 2 MB，
  加密检测从中提取 PEM 公钥）。
- **分析是整文件读入内存**：`analyze_traffic` 会把整个 `capture.jsonl` 读进来，超大文件会显著吃内存。

---

## 安全设计

- **脱敏保留形态**：凭据值抹为 `***`，但保留长度/形态元数据（`len` / `shape` =
  `base64` / `hex` / `plain`）——下游可判明密文而不见值。密文的判定门槛是
  `shape ∈ {base64, hex}` 且 `len >= 128`，**不依赖任何固定长度常量**（不同算法与密钥
  长度会给出不同长度）；
- **脱敏的覆盖范围（别想当然）**：只有**请求**侧的 JSON 体与表单编码体会被清洗
  （另外 `authorization` 头保留 scheme、`cookie` 头保留 Cookie 名）。以下**不脱敏**：
  - **URL 原样记录**——query 里的 token 会留在 `capture.jsonl` 与 `analysis.json` 里；
  - **响应体完全不脱敏**（原样写入，只做大小判断）；
  - **非 JSON、非表单编码的请求体不脱敏**（`multipart/form-data`、XML、部分纯文本原样保留）；
- **生成的子项目不落明文凭据**：`.env` 留空即可；`login()` 成功后凭据与 token 以
  **DPAPI 加密**持久化（`cred_cache.bin` / `token_cache.bin`，仅同一 Windows 用户可解密；
  **非 Windows 上退化为仅内存**，重启不恢复），401 自动重登录（仅识别到登录接口时）；
- **本工具自身的登录态是明文的**：`auth_states/<site_key>.json` 里，`open_browser_login`
  存下的 Cookie 是明文，`http_login` 默认还会把**账号与密码**一并写入该文件的
  `secrets` 字段。文件名由目标站点推导：取 netloc 并把 `.` 与 `:` 换成 `_`
  （`https://oa.example.com/` → `oa_example_com.json`）。它只应留在本机数据目录
  （`config.py` 会在该目录写入 `*` 规则的 `.gitignore`），**禁止提交、同步、截图或分享**。
  复用它给子项目时，真正被需要的是其中的 Cookie，不是密码；
- **审计规范**：日志只记脱敏账号与加密策略，永不记密码；
- **强制核实规则**（步骤 5）：抓包中凭据字段明密文不可区分，禁止假设，必须按四层
  手段核实后再实现。

---

## 分析器内置能力

- **噪音标记**（`noise: true`，不删除）：埋点/心跳/面包屑/菜单配置/第三方统计域名，
  生成时默认跳过；
- **命名参数化**：单样本数字段也参数化（`/user/127733/info` → `/user/{user_id}/info`），
  同构自动合并；
- **登录接口识别**：识别「账号+密码换 token」接口（含密码加密策略与 PEM 公钥提取）；
- **站点档案**：可选的 `webapi_extractor/site_profiles/` 支持为已知站点应用语义化工具
  命名与中文描述；仓库不内置任何档案，其它站点走通用推导。

## 生成的子 MCP 自带的能力

- **多域名路由 + 类型化签名**（query/path 样本 → `page: int = 1`）。默认值的门槛共 **6 个**，
  全部满足才写入：采样 ≥ 2 次、样本值唯一、长度 ≤ 24、纯 ASCII、不含逗号、参数名不属于
  身份/时间类（user / account / time / date / token / session 等）——目的是杜绝把抓包时的
  真实用户 ID / 时间戳烘进代码；
- **鉴权按实测 scheme 生成**（Basic / Bearer / Cookie 分别处理）；纯 Cookie 站点不会被
  误写成「公开接口」（有回归测试守护）；
- **登录工具**（**仅当识别到账号密码登录接口时**）：`login()` / `auth_status()`——凭据与
  token 以 **DPAPI 加密**持久化（**仅 Windows**，其它平台退化为仅内存），重启自动恢复，
  **401 自动重登录并重试一次**；密码按前端实测策略加密传输（如 RSA-OAEP + 前端 JS 公钥）；
- **写操作护栏**：非 GET 工具需显式 `confirm=true`，执行写 audit.log；
- **只读诊断**：`tool_catalog`（工具清单 + registry_version）/ `error_log_tail`。

### 续期语义（什么时候才有自动重登录）

`login()` 与 401 自动重登录**只在识别到账号密码登录接口（registry 里的 `auth_login`）时才生成**。
所以：

- **表单 / JSON 登录的站点** —— 有 `login()`，token 过期可自动恢复；
- **纯 Cookie / SSO / 验证码站点** —— **没有自动重登录**。登录态过期后只能重跑一次
  `open_browser_login` 覆盖同一份 auth_state（端点与工具集不受影响，不必重建项目）。

**角色分离**：**IT 管理态**（装本工具）可 diff/merge/regenerate；**用户态**（只拿分发包）
的 server.py **不含任何修改工具集的能力**（没有 registry 写入与再生成代码），AI Agent 只能
调用其中的业务工具与只读诊断。注意：业务写操作工具**仍在**分发包里（带 `confirm=true` 护栏），
被剥离的是「改工具集」的能力，不是「写业务数据」的能力。

---

## 能力边界（做不到什么）

按「最容易被误以为支持」排序。这些不是缺陷清单，而是设计边界——遇到时应改用别的手段。

| 做不到 | 说明 | 代码依据 |
|---|---|---|
| **文件上传** | `multipart/form-data` 的上传体既**不解析为参数**、也**不脱敏**；附件内容不分析 | `analyzer.py`、`bodies.py`（只处理 JSON 与 urlencoded）、`redaction.py` |
| **实时推送** | WebSocket 只记录「建立连接」，**帧内容不采集**；SSE / 流式响应无专门处理 | `capture.py`（仅订阅 `Network.webSocketCreated`） |
| **文件下载** | 无 `Content-Disposition` / 附件专门处理，下载与普通响应同样对待 | 无相关实现 |
| **GraphQL 语义** | 当普通 POST 端点处理，不展开 query / mutation | 无相关实现 |
| **protobuf / 二进制响应** | 不解码（base64 只用于算长度），拿不到结构化字段 | `capture.py`、`analyzer.py` |
| **大响应拿 Schema** | 超响应上限的响应体**整条丢弃**，该端点没有 `response_schema`（见「数据目录体积与响应上限语义」） | `capture.py` |
| **纯 Cookie / SSO 站点自动续期** | 没有自动重登录，过期须重新授权（见「续期语义」） | `generator.py`（`if auth_login:`） |
| **无桌面环境** | 抓包与交互式登录必须弹出真实浏览器窗口，只有登录探测是无头的 | `capture.py`、`auth.py`、`probe.py` |
| **非 Windows 的加密持久化** | DPAPI 不可用 → 凭据/token 只在内存，重启不恢复（静默降级） | `generator.py` |

另外两点如实说明：

- **只有你操作过的功能才会被发现**——没点过的接口不会被猜到；
- **不提供验证码 / 登录加密的逆向或绕过**，遇到就走交互式授权（见 `runbook/01-authentication.md`）。

---

## 平台矩阵

抓包与交互式登录必须**有桌面环境**（`headful`），只有 `probe_login` 是无头的。
凭据加密持久化依赖 Windows DPAPI。

| 能力 | Windows | macOS | Linux |
|---|---|---|---|
| 抓包（headful） | ✅ | ✅ 需桌面 | ✅ 需桌面 |
| 交互式登录（headful） | ✅ | ✅ 需桌面 | ✅ 需桌面 |
| 登录探测（headless） | ✅ | ✅ | ✅ |
| 凭据 / token 加密持久化 | ✅ DPAPI | ❌ 仅内存，重启不恢复 | ❌ 仅内存，重启不恢复 |
| 401 自动重登录 | ✅ | 仅当前进程内 | 仅当前进程内 |
| `bootstrap.ps1` / `start_server.py` 的进程脱离 | ✅ | 尽力而为 | 尽力而为 |
| **支持级别** | **完整** | 实验 | 实验 |

`pyproject.toml` 的平台 classifier 与 README 徽章都只声明 Windows，与上表一致；
`bootstrap.sh` 与文档里的 macOS / Linux 命令属"尽力而为"，未做完整验证。

---

## 项目结构

```
WebAPIExtractor/
├─ SKILL.md                     # Agent 操作手册主索引（按步骤照做）
├─ README.md                    # 人类入口：这是什么、怎么用起来
├─ docs/reference.md            # 本文件（技术参考）
├─ runbook/                     # SKILL 的分步模块，按需加载
│                               #   00 环境 / 01 登录 / 02 抓包 / 03 分析 / 04 加密
│                               #   05 生成 / 06 迭代 / 90 参考 / 99 排错
├─ bootstrap.py / .ps1 / .sh    # 环境引导（纯 Python 版免疫受限环境）
├─ start_server.py              # 启动 HTTP 服务的推荐方式（脱离 shell job object）
├─ run_http.py                  # 等价的 HTTP 启动器（勿用后台任务方式直接跑）
├─ mcp_call.py                  # MCP 工具驱动（@file / stdin 传参，404 自愈）
├─ install-agent.ps1            # 装依赖 + Chromium（供 Agent 导入）
├─ package-agent.py / .ps1      # 打包成可分发的 zip（清单一致，产物相同）
├─ pyproject.toml               # 打包元数据（含 license / readme / classifiers）
├─ requirements.txt             # 运行 + 测试依赖
├─ LICENSE                      # 自拟使用条款（非 SPDX / OSI）
├─ .gitignore / .gitattributes  # 忽略运行产物；锁定行尾（*.sh 必须为 LF）
├─ .vscode/mcp.json             # 把本服务注册为 stdio MCP（无本机绝对路径）
├─ tests/                       # pytest 套件（22 个文件）
└─ webapi_extractor/
   ├─ __main__.py               # CLI：doctor | serve-http |（默认）stdio
   ├─ server.py                 # MCP Server 与工具注册
   ├─ auth.py                   # 登录流程（用户确认完成，不自动判定）
   ├─ capture.py                # Playwright/CDP 抓包
   ├─ analyzer.py               # 参数化 / 噪音标记 / 登录识别
   ├─ crypto_analyzer.py        # 加密检测 + PEM 公钥提取
   ├─ generator.py              # registry 驱动的项目生成
   ├─ project.py                # registry 唯一事实源（diff / merge / export）
   ├─ redaction.py / bodies.py  # 脱敏（保留形态元数据）/ 请求体解析
   ├─ dialog.py                 # 系统原生确认对话框（登录与抓包共用一份实现）
   ├─ doctor.py                 # 环境自检
   ├─ domain.py / probe.py / proxy_env.py
   ├─ audit.py / storage.py / config.py
   └─ site_profiles/            # 站点档案（可选加载，仓库不内置）
```

---

## 测试

```bash
# pytest 配置在 pyproject.toml（testpaths + asyncio_mode=auto）
uv run --with pytest --with pytest-asyncio --with httpx --with playwright \
       --with fastmcp python -m pytest tests -q

# 装了环境的话直接：
python -m pytest tests -q
```

注意三点：

- `requirements.txt` 里带了 `pytest` / `pytest-asyncio`（bootstrap 会装上），所以
  走 bootstrap 的环境可以直接跑；而 `pip install -e .` **不会**装测试运行器 ——
  此时需自行安装，否则 `asyncio_mode=auto` 会被静默忽略、异步用例全部失败。
- 套件是单元级的，**不会启动浏览器**。
- **测试没覆盖什么**（如实说明，别把「没测到」当成「没问题」）：
  - `tests/` 从不 import `server.py` —— **21 个 MCP 工具层本身无测试**；
  - `doctor.py`、`generator.generate` / `regenerate`、`project.merge_registry` / `diff_hosts` /
    `export_user_package` 均无测试 ⇒ 迭代链路（`runbook/06-iterate.md`）、用户态隔离、
    locked 拒绝都**只有实现、没有验证**；
  - `test_proxy_env.py` 有一条 POSIX-only 用例，在 Windows 上会被 skip（属预期）。
