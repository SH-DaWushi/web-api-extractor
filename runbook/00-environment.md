# 模块 00-environment · 步骤 1 · 环境准备 + 传输引导

> 主索引见 `SKILL.md`。本模块在新部署、或工具无法直接调用时才需要。
> **命名约定**：标题里的「模块」= 文件名前缀（从 00 起），「步骤」= `SKILL.md` 的流程
> 步骤号（从 1 起）—— 两者恒差 1，因为文件名不可改（`SKILL.md` 模块索引、打包清单与
> 一致性测试都按文件名引用），故标题同时标出两个号，交叉引用一律用**文件名**。

## 环境准备（新部署必做，只需一次）

运行时依赖只有 `fastmcp / httpx / playwright` + Playwright Chromium 内核（测试用的
`pytest` / `pytest-asyncio` 已拆到 `requirements-dev.txt`，默认不装）。

```powershell
# Windows（唯一受支持的平台）：一键引导（建独立 venv，装运行依赖+Chromium，跑自检）
powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1
# 需要跑 tests/ 时：加 -WithTests（额外装 requirements-dev.txt）
```
```bash
# 或不依赖 PowerShell 的纯 Python 引导（受支持路径，受限环境免疫）
python bootstrap.py
python bootstrap.py --with-tests
```
```bash
# 非支持平台（仅供参考、未经验证）：bootstrap.sh 是 bootstrap.py 的 POSIX 薄封装。
# 本项目只支持 Windows，不为 macOS / Linux 提供支持（见 reference「平台矩阵」）。
bash ./bootstrap.sh [--with-tests]
```

venv 建在**数据目录**下（`<数据目录>/venv`，默认 `~/.scry/venv`），**不在技能文件夹里**——
技能目录会被宿主应用重新同步/替换，放进去的 venv 可能被连带删除。若技能目录里还留着历史的
`.venv`，引导会**直接复用它**。`start_server.py` 取解释器的顺序同样是
**数据目录 venv → 技能目录旧 `.venv` → 当前解释器**。

已装过环境时，只做自检：

```bash
python -m scry_mcp_gen doctor            # 检查
python -m scry_mcp_gen doctor --install  # 检查并自动补装缺失项
```

doctor 全绿（端口 WARN 可忽略）后再继续。

> **重要（Windows）**：若全局 Python 的 user site-packages 损坏（pip 报 `WinError 1392` / 扫描 dist-info 崩溃），务必用 bootstrap 创建的独立 venv（数据目录下那个，或历史遗留的 `.venv`），它默认禁用 user site，可绕开损坏。

## 如何真正调用这些工具（传输引导）

`probe_login` 等是**本技能自带的 MCP 工具**。若宿主环境没把它们注册成可直接调用的工具，用自带的 HTTP 传输 + 驱动脚本来调：

```bash
# 1) 启动本地 HTTP MCP 服务（脱离宿主进程，全程保持运行）
python start_server.py          # 监听 127.0.0.1:8422/mcp
#   附加开关：
#   python start_server.py --status    # 查看状态（端口/PID/日志）
#   python start_server.py --stop      # 停止（按进程树；先校验 PID 归属）
#   python start_server.py --port 8423 # 换端口
#   python start_server.py --stop --force  # 跳过 PID 归属校验（确认过再用）

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

`mcp_call.py` 会把会话 id 缓存到 `.mcp_session`，多次调用复用同一服务进程（会话状态在内存里）。
**服务中途重启会让已缓存的会话失效**，但驱动脚本检测到后会重新初始化会话并自动重试一次。

> **Windows 传参**：JSON 里路径用正斜杠 `C:/dir/file.json`（反斜杠破坏 JSON 转义）；复杂参数一律走 `@file` / stdin。

数据目录默认 `~/.scry`，可用环境变量覆盖（见 `runbook/90-reference.md`）。
