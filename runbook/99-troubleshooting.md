# 排错速查

> 主索引见 `SKILL.md`。**只在出问题时加载。**

| 现象 | 原因 | 处理 |
|---|---|---|
| 工具无法调用 / 找不到 `probe_login` | 宿主未注册本技能工具 | 用 `runbook/00-environment.md`：`start_server.py` + `mcp_call.py` |
| 浏览器「打开后立刻消失」、端口无监听 | 服务被宿主 shell 的 job 回收 | 用 `start_server.py` 启动，勿直接后台跑 `run_http.py` |
| `mcp_call.py` 报 `Invalid \escape` | Windows 路径反斜杠 | 路径改用正斜杠，或用 `@file` / stdin 传参 |
| `open_browser_login` 秒完成、浏览器随即消失、没等我登录 | 登录页**自设**的 `JSESSIONID` / `PHPSESSID` 等被误判为登录证据（#20 修了基线比对） | 自动判定已整体移除：登录完成只由用户确认，理论上不会再发生。若仍出现，检查是否有代码把 `_login_evidence()` 当判定用——它只是旁证 |
| 确认对话框点了「否」，之后不知怎么再确认 | 旧实现点「否」即丢弃、且永不重弹 | 已修：再调 `request_login_confirm_dialog` 即可重弹；或直接在对话里问用户后调 `confirm_login` |
| `start_capture` 一直 `authenticating`、抓不到 | 用户尚未确认登录完成 | 问用户确认后调 `confirm_login_ready(session_id)`；或直接传 `auth_state_path` 跳过登录环节 |
| doctor 报缺 Chromium | 内核未装 | `python -m playwright install chromium` 或 `doctor --install` |
| pip 报 `WinError 1392` / dist-info 损坏 | 全局 user site 损坏 | 用 bootstrap 的独立 `.venv` |
| `analyze_traffic` 摘要不够看 | 完整 Schema 更大 | 读返回里的 `full_result_path`（analysis.json） |
| 端口 8422 被占 | 服务已在跑或冲突 | 复用已运行服务；换端口用 `python start_server.py --port 8423` |
| `--stop` 打印「已停止服务」，端口却仍被占（下次 `start` 报「已有服务在监听」） | 旧实现只 `taskkill /F` 记录的 PID，那是**启动器**，真正的监听者是它的子进程 | 已修：`--stop` 按**进程树**结束、以**端口真的空出来**为唯一成功判据、强杀前先校验该 PID 确在跑本项目 `run_http.py`；未释放时会报出真正占用端口的 PID。若提示「无法确认 PID 身份」（取不到命令行），确认它确为本项目服务后加 `--force`：`python start_server.py --stop --force` |
| 生成的工具没有参数 / 没有响应 Schema | 响应体超过体积上限（默认 256 KB，可用 `start_capture(response_limit_bytes=…)` 调大，最多 64 MB），超限**整条丢弃**（不是截断） | 重新抓一轮并在 `start_capture` 里传 `response_limit_bytes`（如 `4194304` = 4 MB；提示语里会给建议值，照抄即可）。**别让使用者去设环境变量** —— 那是他做不到的事（reference「数据目录体积与响应上限语义」） |
| 抓包记录目录越来越大 | `capture.jsonl` 只追加、无轮转，静态资源也写 | 人工清理不需要的 `sessions/<id>/`（同上节） |
| 非 Windows 上重启后 token 丢了 | 本项目不支持 macOS / Linux（DPAPI 是 Windows 专有） | 平台本身不受支持，请改用 Windows；逐项说明见 reference「平台矩阵」 |
| 上传文件的接口做不出来 | `multipart/form-data` 的上传体不解析为参数、也不脱敏 | 不支持，见 reference「能力边界」 |
| 生成的工具 401 / 跳回登录页 | Cookie 已过期 | 重新触发一次 `open_browser_login` 完成交互式登录，覆盖同一 `auth_states/<site_key>.json`；无需重建项目 |
| 生成的工具 401，且项目 README 写着「登录需要你本人完成一次」（提示语指向 `login_interactive()`） | 这是**验证码 / 二次验证站点**的产物：它**没有** 401 自动重登录 | 让 Agent 调 `login_interactive()`（弹出真实浏览器窗口，用户本人登录），用户确认后调 `confirm_login()`。**别去改 `.env` 的账号密码** —— 这个产物里没有那两项，构造请求登录本来就过不去 |
| 生成的工具 401，报错里的变量在 `.env.example` 里找不到 | 修复前 401 报错硬写 `<前缀>_TOKEN`，而纯 Cookie 站点的 `.env.example` 只给 `<前缀>_COOKIE_<HOST>` | 已修：401 报错点名的变量与 `.env.example` **同源**（纯 Cookie 站点指 Cookie 项，混用站点同时给 token 项）。若仍对不上，按 `.env.example` 里实际有的那几行配 |
| 生成的工具 401 | Basic 口令没填 | scheme 已按实测生成；在 `.env` 填 `<前缀>_BASIC_PASSWORD_<HOST>`（抓包 scripts/ 搜 `btoa(` 找固定串）与 token |
| merge/regenerate 被拒 `project_locked` | 项目被锁定 | 人工编辑 project.json 的 locked 字段解锁 |
| 生成的工具 401 后未自动重登录 | 无登录配置或无凭据 | 确认 auth_login 已识别；调用一次 login()（无参数会弹窗问用户一次；弹不出就在对话里问，再带参调用） |
| **换了电脑 / 换了 Windows 用户后，登录失败或工具一直 401** | 加密凭据（`cred_cache.bin`）与本机用户绑定，换用户后**解不开** | **删掉项目里的 `cred_cache.bin`，再 `login()` 一次**。`auth_status()` 会给出 `credentials_cache_state: unreadable` 与同一句建议；`login()` / 401 报错里也带这句话 |
| 生成的服务分享给同事后，对方一登录就失败 | 加密凭据不随包走（只在本机同一 Windows 用户下可解） | 正常语义：让对方在自己机器上 `login()` 一次即可；不要把 `cred_cache.bin` / `token_cache.bin` 随包发出去 |
| 想清除已保存的凭据/token | — | 删除项目目录下 cred_cache.bin / token_cache.bin（均为加密文件） |
| PowerShell 下 bootstrap 段错误 | 受限环境 | 用纯 Python 引导：`python bootstrap.py` |
