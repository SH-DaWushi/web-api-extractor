# 步骤 3 · 抓包

> 主索引见 `SKILL.md`。

- 带 `auth_state_path` 的 `start_capture` 会**直接进入 `capturing`**；不带的先 `authenticating`，
  **在用户确认登录完成前不记录任何流量**。
- 放行方式只有一种：问用户「登录好了吗」，得到肯定答复后调 `confirm_login_ready(session_id)`，
  会话才从 `authenticating` 翻到 `capturing`。`get_capture_status` 返回的 `auth_evidence`
  只是旁证，**不会自动放行**（登录页自设会话 Cookie 曾导致约 6 秒后自动开抓）。
- 告诉用户：**在弹出的浏览器里正常操作目标功能**，操作完回来告知。
- `get_capture_status` 看进度，`stop_capture` 结束；空闲超时自动 `paused` 可 `resume_capture`。
