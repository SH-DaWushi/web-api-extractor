# 步骤 3 · 抓包

> 主索引见 `SKILL.md`。

- 带 `auth_state_path` 的 `start_capture` 会**直接进入 `capturing`**；不带的先 `authenticating`，登录后自动转（同三层证据标准，见 `runbook/01-authentication.md`），或用户点页内「登录完成」，或 Agent 调 `confirm_login_ready(session_id)`。
- 告诉用户：**在弹出的浏览器里正常操作目标功能**，操作完回来告知。
- `get_capture_status` 看进度，`stop_capture` 结束；空闲超时自动 `paused` 可 `resume_capture`。
