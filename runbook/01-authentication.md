# 步骤 1–2 · 探测登录方式 → 登录

> 主索引见 `SKILL.md`。登录是必经环节，本模块每次都会用到。

## 探测登录方式

调用 `probe_login(url)`（SPA 友好：domcontentloaded + 登录入口探测，超时可用 `WEB_API_EXTRACTOR_PROBE_TIMEOUT` 调）。
- `confidence >= 0.8` 且 `auth_mode == "form"` → 可尝试 `http_login`。
- 否则（含 SPA/弹窗登录/超时）→ 走交互式登录（见下）。

## 登录（拿到 auth_state）

优先 `open_browser_login(url)` → 轮询 `get_login_status(login_session_id)`。

登录完成判定为**三层信号**（页内按钮不作主机制：CSP/iframe/SSO 弹窗会使其失效）：
1. **主（自动）**：目标域出现 token/session Cookie 且稳定 5 秒 → 自动 `completed`；
2. **备（页外）**：extractor 弹出**系统原生对话框**，用户点「是」；
3. **兜底（带外）**：60 秒无凭据证据 → 状态转 `waiting_user_confirm`，Agent 询问用户后调 `confirm_login(login_session_id)`。

`http_login` 返回 `fallback=interactive` 时，改用 `open_browser_login`。

## 无法用构造请求登录的站点（验证码 / 凭据加密 / MFA / SSO）

相当一部分站点**无法**靠 Agent 构造 POST 登录：登录需要**验证码**、**前端加密的账号密码**、
二次验证或 SSO 跳转。`http_login` 对这类站点必然失败。

> 实测：传统 OA 系统（`/api/auth/login/login`）的 `username` 与 `user_password`
> 均为 RSA 密文（351 字符），且必须带 `captcha` 验证码——
> 构造请求登录**不可行**。

**这类站点一律走 CDP 交互式登录**，并按「一次性授权 + Cookie 复用 + 过期重授权」使用：

1. **初次授权** —— `open_browser_login(url)`，让用户在**真实浏览器**里完成登录
   （验证码、二次验证、SSO 都由人完成）；`get_login_status` 判到完成后，
   登录态落盘为 `<数据目录>/auth_states/<site>.json`。
2. **留存复用** —— 该 auth_state 就是**长期凭据**。后续 `start_capture` 传
   `auth_state_path` 复用它；生成的 MCP 若为 Cookie 鉴权，同样复用它，
   **无需再次登录**。
3. **过期重授权** —— Cookie 失效后（工具 401 或跳回登录页），**重新触发一次
   `open_browser_login` 覆盖同一个 auth_state 文件**即可。不必重建项目、
   不必重抓全部接口——端点只标 `unseen_since`，**永不自动删除**（见 `runbook/06-iterate.md`）。

> ⚠️ 不要为这类站点**逆向其登录加密或验证码**：既不必要，也极不稳定。
> 交互式授权一次、复用 Cookie，才是这类系统唯一可靠的路子。
> 相应地，生成的 MCP 不必带 `login()` 工具——**Cookie 即凭据**。

**兜底做法（推荐，抓包登录合一）**：直接给 `start_capture` 传**种子 auth_state**：

```bash
echo '{"cookies": [], "origins": []}' > "<数据目录>/auth_states/seed.json"
python mcp_call.py start_capture '{"url":"https://example.com/","auth_state_path":"C:/.../auth_states/seed.json"}'
```
