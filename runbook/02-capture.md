# 模块 02-capture · 步骤 3 · 抓包

> 主索引见 `SKILL.md`。

- **`start_capture` 返回 ≠ 页面已就绪**：它会在调用内同步等待启动（起 Playwright/Chromium
  驱动、开浏览器、挂 CDP、加载首个页面），但**最多只等 15 秒**（`server.py` 的
  `_START_UP_WAIT_SECONDS = 15.0`）：15 秒内启动完成就提前返回；超时（页面加载慢）也照样返回，
  此时的 `status` 是**预期状态、不是「已就绪」的确认**（首个页面 `page.goto` 自身上限 30 秒）。
  所以**别把它一返回就当「可以立刻操作了」**：先确认浏览器窗口已打开、页面加载完成再让用户操作，
  否则这段窗口内的请求不会被记录。
- **代理是自动的，别让用户去设环境变量**：`WEB_API_EXTRACTOR_PROXY_MODE` 默认 `auto` ——
  抓包浏览器**先直连**（等价 `--no-proxy-server`）；首个页面若以**代理类形态**失败
  （`ERR_EMPTY_RESPONSE` / `ERR_CONNECTION_TIMED_OUT` / `ERR_PROXY_CONNECTION_FAILED` 等），
  服务**自动改用系统代理重试一次**。直连通的站点直连走、必须经代理才通的站点自动退到系统代理，
  **用户什么都不用设**。只有他明确要求「就直连 / 就走代理」时才提示设
  `WEB_API_EXTRACTOR_PROXY_MODE=direct|system` 并**重启服务**（只对新开的会话生效；已开着的窗口不变）。
- **看到 `proxy_fallback` 要如实转述**：响应里出现 `proxy_fallback`（含 `from` / `to`）说明这次是
  **自动回退**才通的，`message` 末尾也写了「已自动改用系统代理重试」。这句话要带给用户 —— 否则
  他只看到「成功了」，下次换个站点失败时连「代理会被自动切换」这件事都不知道。
- **启动失败先看 `proxy_hint`**：首个页面导航失败且错误码像代理问题（`ERR_PROXY_CONNECTION_FAILED`
  / `ERR_TUNNEL_CONNECTION_FAILED` 等几乎可断定；`ERR_EMPTY_RESPONSE` / `ERR_CONNECTION_RESET`
  / `ERR_TIMED_OUT` 等**可能**是）时，`start_capture` 的响应里会带 `proxy_hint`，`message` 末尾
  也会给出可行动提示（当前模式 + 该切成什么）。看到 `ERR_EMPTY_RESPONSE` **不要**只当成
  「目标站挂了」：先按提示在 direct / system 之间切一次再重试。与代理无关的失败不会被扣上代理帽子。
- **两种模式都试过还是失败**：`detail` 里会写清试过哪两种（直连 / 跟随系统代理）、各自怎么失败的、
  以及按什么顺序排查（先用**普通浏览器**打开该地址确认站点可达 → 检查代理软件在运行 / 端口对不对
  → 内网 / 证书 / DNS 问题看 `doctor`）。这种情况**不要**反复调 `start_capture` 重试：自动回退只做
  一次，再重试还是同样的结果，先把上面三条查一遍。
- **真正决定「是否在记录」的是 `status == "capturing"`**（`capture.py` 的 on_request / on_response /
  on_finished 都先判它，未挂 CDP 前的请求也收不到）。不带 `auth_state_path` 时，**在
  `confirm_login_ready` 之前一条都不记** —— 登录流程下「刚发出 `start_capture` 就操作页面」必然漏抓。
  用 `get_capture_status` 轮询到 `status == "capturing"` 后再开始操作。
- 带 `auth_state_path` 时：该文件**真实存在**才**直接进入 `capturing`**；未传、或路径指向的
  文件不存在时，先进入 `authenticating` 并起登录监视。**在用户确认登录完成前不记录任何流量。**
- 放行方式有两种，都会让会话从 `authenticating` 翻到 `capturing`：
  1. **对话确认（主）**：问用户「登录好了吗」，得到肯定答复后调 `confirm_login_ready(session_id)`；
  2. **系统对话框（兜底）**：不便在对话里询问时调 `request_capture_confirm_dialog(session_id)`——
     弹出系统对话框让用户点选，会阻塞到用户作答；点「否」不丢弃，会话保持等待且可再次调用。
  `get_capture_status` 返回的 `auth_evidence` 只是旁证，**不会自动放行**
  （登录页自设会话 Cookie 曾导致约 6 秒后自动开抓）。
  > 与 `confirm_login` 一样：**问用户是流程约定，服务端只能记录并提示** ——
  > `confirm_login_ready` 也是普通工具调用，查无「已请确认」记录时只在响应里附
  > `confirmation_evidence="none"` + `confirmation_warning`，不会拒绝。
- 告诉用户：**在弹出的浏览器里正常操作目标功能**，操作完回来告知。
- `get_capture_status` 看进度，`stop_capture` 结束；空闲超时自动 `paused` 可 `resume_capture`。
  暂停**不丢数据**：已抓到、还没落盘的事件会先写进 `capture.jsonl`，且这次转换会写进元数据
  （`pause_reason` / `status_history` 的 `reason` / `captured_bytes` + 一句可读提示），
  `list_sessions` 与 `get_capture_status` 都看得到 —— 不是静默发生。看到 `paused` 就先决定
  「`resume_capture` 继续」还是「`stop_capture` 后 `analyze_traffic`」，别当成会话已结束。
- **用户中途直接关掉浏览器也会自动收尾**，不必手动 `stop_capture`：会话转为 `stopped`、
  `stop_reason=browser_closed`，已抓到的记录仍在磁盘上。数据够用就继续 `analyze_traffic`，
  不够就重新 `start_capture`。
- **响应体超限是整条丢弃**：超过体积上限（默认 256 KB）的响应**整条不写 body**（不是截断保留
  前 N 字节），该端点因此拿不到响应 Schema。要抓这类接口就**重新抓一轮并调大上限** —— 重调
  `start_capture` 时多传一个参数 `response_limit_bytes=<字节数>`（例如 `4194304` = 4 MB），
  抓完再跑一次 `analyze_traffic`。这个参数**不传就沿用默认上限，行为与以前完全一致**；合法范围
  `1 ~ 67108864`（64 MB，上限是为了别让一条大响应把只追加、不轮转的 `capture.jsonl` 写满），
  非法值会直接被拒并返回 `invalid_response_limit_bytes` + 一句写明合法范围的话（详见
  `docs/reference.md` 的「数据目录体积与响应上限语义」）。
  > **别让使用者去设环境变量**：`WEB_API_EXTRACTOR_RESPONSE_LIMIT` 是运维/技术侧的开关，
  > 提示语里给出的是上面这条工具调用 —— Agent 自己就能替用户完成「调大上限后重抓」。
- **跨进程 iframe（OOPIF）与 WebSocket 帧也会被记录**，事件形状与已知边界见
  `docs/reference.md` 的「capture.jsonl 事件类型与会话维度」。三条最要紧的：
  - **WebSocket 帧内容**（`websocket_frame`）会落盘，走与请求体**同一套脱敏**、**同一套
    超限语义**（超上限则整条不写体，只留 `payload_size` / `payload_dropped`）；帧收发失败
    另有 `websocket_frame_error`。帧**不会**被分析成端点或生成工具。
  - **子会话事件**多带 `cdp_session`（`sub1` / `sub2` …）与 `source_target`；**主会话不带**。
    `requestId` **主会话无前缀、子会话统一 `sub<n>:` 前缀** —— 这是为了让既有配对、重定向
    hop 与脚本文件名不受影响，别去「统一」它们。
  - **已知漏抓窗口**：iframe 生命周期最前约 50–60 ms 的请求仍可能漏（真机最早 +62 ms 量级
    才能挂上子会话，只有有界重试）；iframe 自己的文档/导航请求走**父会话**；**Worker /
    Service Worker 内部请求完全未覆盖**（没有公开 API 可对 worker target 挂 CDP 会话）。
    因此「页面上明明发生了却抓不到」不一定是你操作错了 —— 先看是不是这几种情况。
