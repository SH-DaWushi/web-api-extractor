# 步骤 3 · 抓包

> 主索引见 `SKILL.md`。

- 带 `auth_state_path` 时：该文件**真实存在**才**直接进入 `capturing`**；未传、或路径指向的
  文件不存在时，先进入 `authenticating` 并起登录监视。**在用户确认登录完成前不记录任何流量。**
- 放行方式有两种，都会让会话从 `authenticating` 翻到 `capturing`：
  1. **对话确认（主）**：问用户「登录好了吗」，得到肯定答复后调 `confirm_login_ready(session_id)`；
  2. **系统对话框（兜底）**：不便在对话里询问时调 `request_capture_confirm_dialog(session_id)`——
     弹出系统对话框让用户点选，会阻塞到用户作答；点「否」不丢弃，会话保持等待且可再次调用。
  `get_capture_status` 返回的 `auth_evidence` 只是旁证，**不会自动放行**
  （登录页自设会话 Cookie 曾导致约 6 秒后自动开抓）。
- 告诉用户：**在弹出的浏览器里正常操作目标功能**，操作完回来告知。
- `get_capture_status` 看进度，`stop_capture` 结束；空闲超时自动 `paused` 可 `resume_capture`。
- **用户中途直接关掉浏览器也会自动收尾**，不必手动 `stop_capture`：会话转为 `stopped`、
  `stop_reason=browser_closed`，已抓到的记录仍在磁盘上。数据够用就继续 `analyze_traffic`，
  不够就重新 `start_capture`。
- 超过响应上限（默认 256 KB）的响应**整条丢弃 body**（不是截断保留前 N 字节），该端点因此
  拿不到响应 Schema。要抓这类接口就调高 `WEB_API_EXTRACTOR_RESPONSE_LIMIT` 后重抓一轮
  （详见 `docs/reference.md` 的「数据目录体积与响应上限语义」）。
