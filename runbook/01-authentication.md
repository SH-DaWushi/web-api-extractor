# 模块 01-authentication · 步骤 2 · 探测登录方式 → 登录

> 主索引见 `SKILL.md`。本模块在**需要登录时**加载；若已有可用的 auth_state（种子文件或上一轮留存），
> 可跳过本节，直接按 `runbook/02-capture.md` 传 `auth_state_path` 抓包。

## 探测登录方式

调用 `probe_login(url)`（SPA 友好：domcontentloaded + 登录入口探测，超时可用 `SCRY_PROBE_TIMEOUT` 调）。

- 返回的 `auth_mode` **只有两种取值**：`none`（未发现登录入口）与 `interactive`（需要交互式登录）。
  **没有 `form` 这种取值**，不要按它分支。
- `confidence` 最高 **0.75**（发现登录入口且命中验证码 / MFA / SSO 等指标时；无指标为 0.6）。
  它**不足以**判定「能否用 `http_login`」——`http_login` 的可行性由实测决定：**真的 POST 一次**，
  失败会换个形态**再 POST 一次**，仍失败才返回 `fallback=interactive`，此时改用
  `open_browser_login`。**这次实测的结论会落盘**（`auth_states/<site_key>.login_mode.json`），
  生成期据此决定生成物里是「账号密码登录」还是「自带的交互式登录」——所以**每个新站点都值得
  先试一次 `http_login`**，别直接跳过它。
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

> **这条是流程约定，服务端只能提示、无法强制**：`confirm_login` / `confirm_login_ready`
> 只是普通工具调用，服务端没有证据证明「问过用户」。它会记录「收到过确认请求」
> （`open_browser_login` / `start_capture` 以「请用户确认」返回时、或确认对话框真的弹出过时各记一笔），
> 若查无记录，就在**成功响应**里附 `confirmation_evidence="none"` + `confirmation_warning`
> —— 只提示、不拒绝。所以「先问用户、得到答复再调」仍然是你（Agent）必须自己守的规矩。

`get_login_status` 返回的 `auth_evidence` 只是**旁证**——目标域上相对登录前基线
新增 / 值变化的凭据类 Cookie。它用于在用户确认前提示「看起来已经登录成功了，请确认」，
**不会自动放行，也不驱动状态**。若 `confirm_login` 返回 `warning=no_credential_evidence`，
说明没观察到凭据 Cookie，存下的登录态可能是未认证状态，需向用户核实。

**用户确认后**（`confirm_login` 或确认对话框）状态才变 `completed`，登录态才落盘为
`<数据目录>/auth_states/<site_key>.json`——文件名取 netloc 并把 `.` / `:` 换成 `_`，
如 `https://oa.example.com/` → `oa_example_com.json`。

> ⚠️ 该文件里 **Cookie 是明文的**（Playwright `storage_state` 格式，功能上必需），**账号密码则用
> DPAPI 加密**后存进 `secrets_enc`，不再写明文（DPAPI 不可用时不落盘、只留在内存，并回报
> `secrets_persisted: false` + `secrets_not_persisted`）。旧版遗留的明文 `secrets` 字段仍可读、
> 在被读取时迁移（`read_auth_state_secrets()` 是**迁移 / 排查工具**，生产路径刻意不调用它 ——
> 抓包与分析只要 Cookie）。`open_browser_login` 用 `storage_state` 整体重写该文件时，会先把旧的
> `secrets_enc` 取出、写完后合并回去，**不再**丢掉加密凭据（此前会丢，已修）。
> 禁止提交、同步、截图或分享。字段说明与脱敏范围见 `docs/reference.md` 的「安全设计」。

`http_login` 返回 `fallback=interactive` 时，改用 `open_browser_login`（返回体里的
`login_mode_recorded` 会告诉你这次实测结论有没有落盘；落盘了，生成物才会自带交互式登录）。

## 无法用构造请求登录的站点（验证码 / 凭据加密 / MFA / SSO）

相当一部分站点**无法**靠 Agent 构造 POST 登录：登录需要**验证码**、**前端加密的账号密码**、
二次验证或 SSO 跳转。`http_login` 对这类站点必然失败。

> 实测：这类系统的登录接口常把账号与口令整体 RSA 加密（base64 形态的密文），
> 且必须带验证码——构造请求登录**不可行**。

**判据是两层的，以实测为准**（`analyzer.login_post_verdict`）：

1. **第一层（静态，预判）**：只看登录请求**自己**的字段名与取值形态 —— 验证码字段 /
   二次验证字段 / **无法复现**的前端加密口令 → 预判「不能 POST」。签名 / 时间戳 / 随机数
   这类参数单独出现时**不足以判死**（很多站点的登录并不校验它们），只记进 `signals`。
2. **第二层（实测，决定性）**：`http_login` 真的 POST 一次，失败换个形态**再 POST 一次**
   （JSON ⇄ 表单，参数承载方式一并修正），然后把实际结果落盘成
   `<数据目录>/auth_states/<site_key>.login_mode.json`：只有判定事实
   （`verdict` / 尝试次数 / 原因码 / HTTP 状态码 / 时间），**不含**账号、口令、Cookie 或响应正文。

为什么必须落盘：以前 `fallback=interactive` 只回到对话里，**生成期无从得知**，于是生成物照旧
发射一个假装能 401 自动重登录的 `login()` —— 而它必然失败。现在
`analyze_traffic` 把实测结论写进 `analysis.json` / `registry.json` 的
`auth_login["post_login"]`，生成器据此决定发射哪一套登录代码。**实测覆盖静态预判**：
静态说有验证码、实测真能登录 → 按「能登录」处理；反之亦然。

### 这类站点怎么用（技能侧：一次性授权 + Cookie 复用 + 过期重授权）

1. **初次授权** —— `open_browser_login(url)`，让用户在**真实浏览器**里完成登录
   （验证码、二次验证、SSO 都由人完成）；**用户确认后**调 `confirm_login`，
   登录态落盘为 `<数据目录>/auth_states/<site_key>.json`。
2. **留存复用** —— 该 auth_state 就是**长期凭据**。后续 `start_capture` 传
   `auth_state_path` 复用它；生成的 MCP 若为 Cookie 鉴权，同样复用它，
   **无需再次登录**。
3. **过期重授权** —— Cookie 失效后（工具 401 或跳回登录页），**重新触发一次
   `open_browser_login` 覆盖同一个 auth_state 文件**即可。不必重建项目、
   不必重抓全部接口——端点只标 `unseen_since`，**永不自动删除**（见 `runbook/06-iterate.md`）。

### 生成物侧：自带交互式登录（不再假装能自动重登录）

判为「不能 POST」的站点，生成的 MCP **不再发射 `login()` / `_do_login()`**（那套代码在这里
必然失败），改为发射下面三个工具；`playwright` 写进 `requirements.txt` 并**钉死版本**
（`==1.63.0`，与浏览器内核 `chromium-1243` 绑定 —— 技能侧已缓存该内核，因此**零下载**；
写成版本范围会让新装版本带来新修订号、逼用户重下整个浏览器），且在 MCP 初始化时**尽力自动安装**：

| 生成物里的工具 | 作用 |
|---|---|
| `login_interactive()` | 拉起**真实浏览器窗口**，用户本人在里面登录（验证码 / 短信 / SSO）；**立即返回** |
| `get_login_status()` | 只读轮询：状态 + `auth_evidence` 旁证（**不代表**登录已完成） |
| `confirm_login()` | 用户在对话里确认「登录好了」之后调用 —— 保存登录态 |

- **绝不自动判定登录完成**：状态只由 `confirm_login()` 翻转。技能侧 `auth.py` 记过这次事故
  （自动放行会在用户还在输密码时把会话判成完成并关掉浏览器）。
- 登录态落 `auth_state.json`，生成物的工具**自动带上**它，用户不必手工往 `.env` 粘 Cookie。
- 401 的提示直接指向 `login_interactive()`，**不再声称会自动重登录**，也不再让用户去配一个
  `.env` 里不存在的变量。

> ⚠️ 不要为这类站点**逆向其登录加密或验证码**：既不必要，也极不稳定。
> 交互式授权一次、复用 Cookie，才是这类系统唯一可靠的路子 —— 现在这一步在**生成物里**
> 也能完成，用户不必回头找 Agent 重跑技能。
> 也仍然**没有自动续期**：登录态过期只能重新授权一次（原因见 `docs/reference.md` 的「续期语义」）。

**兜底做法（推荐，抓包登录合一）**：直接给 `start_capture` 传**种子 auth_state**：

```bash
echo '{"cookies": [], "origins": []}' > "<数据目录>/auth_states/seed.json"
python mcp_call.py start_capture '{"url":"https://example.com/","auth_state_path":"C:/.../auth_states/seed.json"}'
```

> 种子文件必须**已存在**（如上先 `echo` 写一个空壳）；路径不存在时 `start_capture` 会退回
> `authenticating` 等用户确认。
