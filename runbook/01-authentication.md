# 步骤 1–2 · 探测登录方式 → 登录

> 主索引见 `SKILL.md`。本模块在**需要登录时**加载；若已有可用的 auth_state（种子文件或上一轮留存），
> 可跳过本节，直接按 `runbook/02-capture.md` 传 `auth_state_path` 抓包。

## 探测登录方式

调用 `probe_login(url)`（SPA 友好：domcontentloaded + 登录入口探测，超时可用 `WEB_API_EXTRACTOR_PROBE_TIMEOUT` 调）。

- 返回的 `auth_mode` **只有两种取值**：`none`（未发现登录入口）与 `interactive`（需要交互式登录）。
  **没有 `form` 这种取值**，不要按它分支。
- `confidence` 最高 **0.75**（发现登录入口且命中验证码 / MFA / SSO 等指标时；无指标为 0.6）。
  它**不足以**判定「能否用 `http_login`」——`http_login` 的可行性由实测决定：试一次，
  失败会返回 `fallback=interactive`，此时改用 `open_browser_login`。
- `probe_login` 是**无头**探测，给不出「这个登录表单能不能构造请求」的结论：SPA、弹窗登录、
  前端加密密码、验证码都会让它落到 `interactive`。

## 登录（拿到 auth_state）

优先 `open_browser_login(url)` → **由用户确认登录完成后**调 `confirm_login(login_session_id)` 保存登录态。

**登录完成绝不自动判定。** 以前这里按「目标域出现 token/session Cookie 且稳定 5 秒」
自动置 `completed` 并关掉浏览器——而登录页**自己就会设** `JSESSIONID` / `PHPSESSID`，
于是用户还在输密码、Agent 已经拿着 completed 往下跑了。判定权现在只在用户手里：

| 通道 | 用法 | 说明 |
|---|---|---|
| **主：对话确认** | 问用户「登录好了吗」，得到肯定答复后调 `confirm_login(login_session_id)` | 推荐；与 Agent 工作方式一致 |
| 备用：系统对话框 | `request_login_confirm_dialog(login_session_id)` | 不便用对话询问时用；**会阻塞到用户点选为止**。点「否」返回 `confirmed=false`，会话保持等待，**可再次调用**（对话框可重复弹出） |

`get_login_status` 返回的 `auth_evidence` 只是**旁证**——目标域上相对登录前基线
新增 / 值变化的凭据类 Cookie。它用于在用户确认前提示「看起来已经登录成功了，请确认」，
**不会自动放行，也不驱动状态**。若 `confirm_login` 返回 `warning=no_credential_evidence`，
说明没观察到凭据 Cookie，存下的登录态可能是未认证状态，需向用户核实。

**用户确认后**（`confirm_login` 或确认对话框）状态才变 `completed`，登录态才落盘为
`<数据目录>/auth_states/<site_key>.json`——文件名取 netloc 并把 `.` / `:` 换成 `_`，
如 `https://oa.example.com/` → `oa_example_com.json`。

> ⚠️ 该文件**是明文的**：Cookie 原样保存，`http_login` 默认还会把账号与密码写进 `secrets` 字段。
> 禁止提交、同步、截图或分享。字段说明与脱敏范围见 `docs/reference.md` 的「安全设计」。

`http_login` 返回 `fallback=interactive` 时，改用 `open_browser_login`。

## 无法用构造请求登录的站点（验证码 / 凭据加密 / MFA / SSO）

相当一部分站点**无法**靠 Agent 构造 POST 登录：登录需要**验证码**、**前端加密的账号密码**、
二次验证或 SSO 跳转。`http_login` 对这类站点必然失败。

> 实测：这类系统的登录接口常把账号与口令整体 RSA 加密（base64 形态的密文），
> 且必须带验证码——构造请求登录**不可行**。

**这类站点一律走 CDP 交互式登录**，并按「一次性授权 + Cookie 复用 + 过期重授权」使用：

1. **初次授权** —— `open_browser_login(url)`，让用户在**真实浏览器**里完成登录
   （验证码、二次验证、SSO 都由人完成）；**用户确认后**调 `confirm_login`，
   登录态落盘为 `<数据目录>/auth_states/<site_key>.json`。
2. **留存复用** —— 该 auth_state 就是**长期凭据**。后续 `start_capture` 传
   `auth_state_path` 复用它；生成的 MCP 若为 Cookie 鉴权，同样复用它，
   **无需再次登录**。
3. **过期重授权** —— Cookie 失效后（工具 401 或跳回登录页），**重新触发一次
   `open_browser_login` 覆盖同一个 auth_state 文件**即可。不必重建项目、
   不必重抓全部接口——端点只标 `unseen_since`，**永不自动删除**（见 `runbook/06-iterate.md`）。

> ⚠️ 不要为这类站点**逆向其登录加密或验证码**：既不必要，也极不稳定。
> 交互式授权一次、复用 Cookie，才是这类系统唯一可靠的路子。
> 相应地，生成的 MCP 不必带 `login()` 工具——**Cookie 即凭据**。
> 也因此，这类站点**没有 401 自动重登录**：登录态过期只能重新授权一次
> （原因见 `docs/reference.md` 的「续期语义」）。

**兜底做法（推荐，抓包登录合一）**：直接给 `start_capture` 传**种子 auth_state**：

```bash
echo '{"cookies": [], "origins": []}' > "<数据目录>/auth_states/seed.json"
python mcp_call.py start_capture '{"url":"https://example.com/","auth_state_path":"C:/.../auth_states/seed.json"}'
```

> 种子文件必须**已存在**（如上先 `echo` 写一个空壳）；路径不存在时 `start_capture` 会退回
> `authenticating` 等用户确认。
