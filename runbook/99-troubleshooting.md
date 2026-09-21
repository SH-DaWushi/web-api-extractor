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
| 端口 8422 被占 | 服务已在跑或冲突 | 复用已运行服务，或改 `run_http.py` 端口 |
| 生成的工具 401 / 跳回登录页 | Cookie 已过期 | 重新触发一次 `open_browser_login` 完成交互式登录，覆盖同一 `auth_states/<site>.json`；无需重建项目 |
| 生成的工具 401 | Basic 口令没填 | scheme 已按实测生成；在 `.env` 填 `<前缀>_BASIC_PASSWORD_<HOST>`（抓包 scripts/ 搜 `btoa(` 找固定串）与 token |
| merge/regenerate 被拒 `project_locked` | 项目被锁定 | 人工编辑 project.json 的 locked 字段解锁 |
| 生成的工具 401 后未自动重登录 | 无登录配置或无凭据 | 确认 auth_login 已识别；调用一次 login() 或在 .env 配凭据（之后走加密缓存） |
| 想清除已保存的凭据/token | — | 删除项目目录下 cred_cache.bin / token_cache.bin（均为加密文件） |
| PowerShell 下 bootstrap 段错误 | 受限环境 | 用纯 Python 引导：`python bootstrap.py` |
