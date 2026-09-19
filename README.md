# WebAPIExtractor

**让 Agent 陪你打开真实浏览器、完成真实登录与操作，把「你点过的每一个功能」变成可调用的 API，并一键生成对接该站点的 MCP 工具服务器。**

它给你的不是一份静态 API 列表，而是一条完整链路：

```
浏览器真实交互 ──► CDP 全量抓包 ──► 归一化/参数化/噪音标记 ──► 凭据与加密核实 ──► 生成可运行项目(含登录能力)
```

---

## 为什么需要它

| 传统做法 | WebAPIExtractor |
|---|---|
| 对着 F12 手工翻请求，复制 curl | 打开浏览器正常使用网站，后台自动记录全部请求/响应 |
| 接口文档靠猜，参数靠试 | 从真实流量归纳参数结构、请求/响应 Schema；同构接口自动合并（`/user/123` + `/user/456` → `/user/{user_id}`） |
| 登录态、token、密码加密逻辑难复刻 | 识别账号密码登录接口（含密码加密策略与公钥提取），生成的 MCP 自带 `login()`，凭据加密持久化、401 自动重登录 |
| 拿到接口还要手写胶水代码 | 直接生成 registry 项目：多域名路由 + 类型化参数 + 实测鉴权 + 写操作护栏 + 冒烟测试 |
| 抓包数据含敏感信息 | 记录即时脱敏（值抹掉但保留长度/形态元数据，明密文仍可区分）；凭据/Token 走系统级加密存储 |
| 初次漏抓的 API 要推倒重来 | registry 增量迭代：再抓一轮 → diff → merge → regenerate |

**典型场景**：想给内网 OA、公司系统、无公开 API 的网站做一个 AI Agent 可调用的工具——只要你能用浏览器操作它，WebAPIExtractor 就能把它变成 MCP 工具。

---

## 快速开始

### 1. 环境准备（新机器只需一次）

```bash
# 推荐：纯 Python 引导（受限环境免疫，不依赖 PowerShell/bash）
python bootstrap.py

# 或平台脚本引导（创建独立 .venv，装依赖 + Chromium，跑自检）
powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1   # Windows
bash ./bootstrap.sh                                        # macOS / Linux
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

宿主环境已注册本技能的 MCP 工具时直接调用；否则用自带驱动脚本：

```bash
python mcp_call.py probe_login '{"url":"https://example.com/"}'
# 复杂参数（含 Windows 路径）用文件或 stdin 传，避开 shell 引号问题：
python mcp_call.py start_capture @args.json
echo '{...}' | python mcp_call.py start_capture -
```

完整流程见 **SKILL.md**（按步骤可照做的操作手册）。服务重启后驱动脚本会自动重新初始化会话并重试。

---

## 工具一览

| 阶段 | 工具 | 作用 |
|---|---|---|
| 探测 | `probe_login` | 判断站点登录方式（SPA 友好，含登录入口探测） |
| 登录 | `http_login` / `open_browser_login` / `get_login_status` / `confirm_login` | 表单登录 / 交互式登录（三层完成判定）/ 查进度 / 带外确认 |
| 抓包 | `start_capture` / `get_capture_status` / `stop_capture` / `resume_capture` / `confirm_login_ready` | 开始 / 查看 / 结束 / 恢复抓包 / 手动置登录完成 |
| 会话 | `list_sessions` | 列出历史会话 |
| 分析 | `analyze_traffic` / `update_endpoint` | 精简摘要+鉴权 scheme / 补充接口描述 |
| 加密 | `extract_crypto_logic` | 加密检测：URL 参数信号 + 密文形态 + JS 公钥 |
| 生成 | `generate_mcp_server` | 生成 registry 项目 |
| 迭代 | `diff_capture` / `merge_capture` / `regenerate_server` / `export_project` | 只读差异 / 确认合并（version+1）/ 从 registry 重生成 / 导出用户态分发包 |

---

## 典型工作流

```
1. probe_login(url)                        判断登录需求
2. open_browser_login(url)                 弹浏览器，用户完成登录（三层完成判定）
3. start_capture(url, auth_state_path)     带登录态开始抓包
4. 用户在浏览器里正常操作目标功能            （想变成工具的功能都要真实点一遍）
5. stop_capture(session_id)                结束收集
6. analyze_traffic(session_id)             精简摘要：噪音标记 / 命名参数化 / 登录接口识别
7. 凭据与加密核实（强制）                    抓包中凭据必然是 ***，禁止假设明文，四层手段核实
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

> 提示：抓包记录的是**真实用户操作**——你操作了什么，才会发现什么接口。

---

## 分析器内置能力

- **噪音标记**（`noise: true`，不删除）：埋点/心跳/面包屑/菜单配置/第三方统计域名，生成时默认跳过；
- **命名参数化**：单样本数字段也参数化（`/user/127733/info` → `/user/{user_id}/info`），同构自动合并；
- **登录接口识别**：识别「账号+密码换 token」接口（含密码加密策略与 PEM 公钥提取）；
- **站点档案**：example 等已知站点自动应用语义化工具命名与中文描述（`webapi_extractor/site_profiles/`），其它站点走通用推导。

## 生成的子 MCP 自带的能力

- **多域名路由 + 类型化签名**（query/path 样本 → `page: int = 1`；默认值有四重门槛，杜绝把抓包时的真实用户 ID / 时间戳烘进代码）；
- **鉴权按实测 scheme 生成**（Basic / Bearer / Cookie 分别处理）；
- **登录工具**（识别到登录接口时）：`login()` / `auth_status()`——凭据与 token 以 **DPAPI 加密**持久化（仅同一 Windows 用户可解密，已列 .gitignore），重启自动恢复，**401 自动重登录并重试一次**；密码按前端实测策略加密传输（如 RSA-OAEP + 前端 JS 公钥）；
- **写操作护栏**：非 GET 工具需显式 `confirm=true`，执行写 audit.log；
- **只读诊断**：`tool_catalog`（工具清单 + registry_version）/ `error_log_tail`。

**角色分离**：**IT 管理态**（装本工具）可 diff/merge/regenerate；**用户态**（只拿分发包）的 server.py 物理上不含任何写入能力，AI Agent 只能调用与只读诊断，无法修改工具集。

---

## 安全设计

- **脱敏保留形态**：凭据值抹为 `***`，但保留长度/形态元数据（如 RSA-2048 密文恒为 344 字符 base64）——下游可判明密文而不见值；
- **凭据不落明文**：`.env` 留空即可；`login()` 成功后凭据与 token 走系统级加密存储；
- **审计规范**：日志只记脱敏账号与加密策略，永不记密码；
- **强制核实规则**（SKILL 步骤 5）：抓包中凭据字段明密文不可区分，禁止假设，必须按四层手段核实后再实现。

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
| `WEB_API_EXTRACTOR_PROBE_TIMEOUT` | `15000` | 探测超时（毫秒） |

---

## 常见问题

| 问题 | 处理 |
|---|---|
| 浏览器弹出后秒关 / 登录没完成 | 三层完成判定已内置；仍异常时给 `start_capture` 传种子 auth_state（`{"cookies":[],"origins":[]}`）直进抓包模式 |
| 抓包一直 `authenticating` 不记录 | 传 `auth_state_path`；或 `confirm_login_ready`；或点页内「登录完成」 |
| doctor 报缺 Chromium | `python -m playwright install chromium` 或 `doctor --install` |
| pip 报 `WinError 1392`（dist-info 损坏） | 用 bootstrap 的独立 `.venv`（默认禁用 user site） |
| `mcp_call.py` 报 `Invalid \escape` | 路径改用正斜杠，或用 `@file` / stdin 传参 |
| PowerShell 下 bootstrap 段错误 | 用 `python bootstrap.py`（纯 Python 引导） |
| 生成的工具 401 | 自动重登录已内置；确认调用过一次 `login()` 或已配置凭据 |
| 想清除已保存的凭据/token | 删除项目目录下 `cred_cache.bin` / `token_cache.bin`（均为加密文件） |
| 生成的工具含真实用户 ID / 过期时间戳默认值 | 已修：默认值四重门槛（多轮稳定+短+纯 ASCII+非身份/时间类） |
| merge/regenerate 被拒 `project_locked` | 人工编辑 project.json 的 locked 字段解锁 |

---

## 项目结构

```
WebAPIExtractor/
├─ SKILL.md                  # Agent 操作手册（按步骤照做）
├─ README.md                 # 本文件（唯一事实源，随功能提交演进）
├─ bootstrap.py / .ps1 / .sh # 环境引导（纯 Python 版免疫受限环境）
├─ run_http.py               # HTTP 传输启动器 (127.0.0.1:8422/mcp)
├─ mcp_call.py               # MCP 工具驱动（@file/stdin 传参，404 自愈）
├─ requirements.txt
└─ webapi_extractor/
   ├─ server.py              # MCP Server 与工具注册
   ├─ auth.py                # 登录流程（三层完成信号）
   ├─ capture.py             # Playwright/CDP 抓包
   ├─ analyzer.py            # 参数化/噪音标记/登录识别
   ├─ crypto_analyzer.py     # 加密检测 + PEM 公钥提取
   ├─ redaction.py           # 脱敏（保留形态元数据）
   ├─ generator.py           # registry 驱动的项目生成
   ├─ project.py             # registry 唯一事实源（diff/merge/export）
   ├─ site_profiles/         # 站点档案（example 等，可选加载）
   ├─ doctor.py              # 环境自检
   └─ ...
```

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

## 这是 Skill，还是 MCP？

两者都是：**底层是 MCP Server**（暴露 `probe_login`、`start_capture`、`generate_mcp_server` 等工具），**上层是 Agent 可唤起的 Skill**（`SKILL.md` 定义了完整调度流程）。推荐作为 Skill 使用——由 Agent 发起、用户操作站点、它负责观察与生成。
