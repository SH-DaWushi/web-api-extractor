# 模块 05-generate · 步骤 6 · 生成（registry 项目）

> 主索引见 `SKILL.md`。

`generate_mcp_server(session_id, output_dir, endpoint_ids=[...])` → 生成**项目**：

前置：**先对本会话调过 `analyze_traffic`**。本工具只读 `<会话>/analysis.json`（由
`analyze_traffic` 从 `capture.jsonl` 写出），自己**不会**再分析一次；缺这份文件时返回
`analysis_not_found` 并让你去调 `analyze_traffic`（不再是看不懂的 `FileNotFoundError`）。

```
<output_dir>/
├─ project.json / registry.json   # registry 由 merge 维护，版本号随每次合并 +1
├─ server.py                       # 多域名路由 + 类型化参数 + **按每个接口实测的方式**鉴权
├─ requirements.txt / .env.example / README.md / smoke_test.py
└─ captures/                       # 各轮合并的 provenance
```

两个 id 列表（可同时传，取**并集**）：

- `endpoint_ids`：圈定要做成工具的端点（摘要里的 `endpoint_id`；不传 = 全部保留端点）。
  对**会被跳过**的键报 `Unknown endpoint_ids`，不静默别名。
- `include_endpoint_ids`：**显式点名包含**。复核完 `not_generated` 决定「这条我就是要」时
  把衔接键填在这里 —— 绕过全部跳过规则（噪音 / 不可独立调用 / 非 JSON 响应）照常生成。
  被点名的端点在 registry 条目上留 `forced_include: true`，生成的 README 单列一节
  「显式点名包含的端点」说明它们为什么在；返回值 `forced_include` 列出实际生效的键
  （拼错的键不会被静默忽略）。**报给用户时照抄 README 那一节**，别让同事以为抓错了。

**文件 / 流式响应工具**（`[FILE]` 标记）：端点响应是 CSV / PDF / XLSX / ZIP 等时，生成的工具
不假装有 JSON schema，而是原样返回响应体（文本在 `text`、二进制在 `base64`，附
`content_type` / `status` / `content_disposition`），**服务不写磁盘** —— 提醒用户自己把
`text`/`base64` 落盘成文件。这类端点走的是与其它工具同一套鉴权与 401 自动重登录。

> ⚠️ `regenerate_server` **只重渲染代码与文档，不写 `registry.json`**（重新渲染时它会主动移除
> registry.json，因为"registry 归 merge 管"）。所以别指望 regenerate 更新 registry ——
> 端点的增改一律走 `diff_capture` → `merge_capture`（见 `runbook/06-iterate.md`）。

**`output_dir` 里已经有项目时不会拒绝，而是先备份再覆盖**：整个目录会被**整份复制**到旁边的
`<dir>.bak-<时间戳>`，然后按这次抓包重新生成。返回值里的 `backup_path` 与 `message` 说明备份
落在哪 —— **把这句话如实转告使用者**（「原有数据已备份到 X」），否则他会以为数据没了。
一次性生成走 `init_project`，会重建 registry；要继续维护同一个项目，用
`regenerate_server` 或 `diff_capture` → `merge_capture`（只增不减）。

返回值还带 `param_defaults` / `param_defaults_notice`：**哪些参数用了抓包时的取值作默认值**
（只有参数名与端点，没有取值）。分享这个 MCP 给他人之前该检查什么，照这句话说 ——
默认值是抓包那一次会话的值，未必适用于别人。**取值会切换响应形态的参数（`count` / `pagesize` /
`bulkbindings` / `filter` / `page` / `sort` / `format` …，以及取值为 `yes` / `no` / `true` /
`false` / `on` / `off` 的）不在这份名单里**：它们一律不烘，并在工具文档字符串里用非技术话术
说明 —— **实测过会切换形态的（`behaviour_switch is True`）是必填**；**只是名字/取值像开关、
没有实测证据的是可选、无默认值**（不传就不发这个键，服务端用自己的默认值）
（判据与理由见 `docs/reference.md` 的「取值会切换响应形态的参数」一节）——
所以别对使用者说「这些参数用了抓包时的值」。登录 query 参数里「来源确定」的那些不烘快照：
生成的服务会在登录前**自动**去来源接口取值，使用者什么都不用填（对应的线索在
`analyze_traffic` 摘要的 `auth_login_query_leads[].auto_fill`）。其余**取用不了**的登录
query 参数（来源带鉴权头 / 来源接口自身要参数 / 字段定位不到 / 多候选 / 循环）**不标必填**：
调 `login()` 时按 **调用入参 → `.env` → 本机弹窗询问** 取值，弹窗取消才返回
`missing_login_query_params` 并点名缺哪个 —— 那时按 `missing_params` 照实转告使用者。
（这条路径是**登录 query 参数**的取值链，与「交互式浏览器登录」无关：只有 POST 登不进去的
站点 —— 验证码 / MFA / SSO / 前端加密复刻不出来 —— 才在生成时改发射交互式登录，判据与产物
见 `runbook/01-authentication.md` 的「生成物侧」一节。）

生成器的完整能力清单（多域名路由、类型化签名与默认值门槛、**逐端点鉴权**、登录工具与续期语义、
写操作护栏与 README 里的「会改数据的工具」清单、只读诊断）见 `docs/reference.md` 的
「生成的子 MCP 自带的能力」——**那里是唯一权威描述**。
一句话提醒：`login()` 与 401 自动重登录**只在识别到 `auth_login`、且该站点判为「能靠构造请求
登录」时才生成**（判据见 `runbook/01-authentication.md`）。判为不能的那种站点，生成物里是
`login_interactive()` / `get_login_status()` / `confirm_login()` 三个工具，`requirements.txt`
里会有**钉死版本**的 `playwright` —— 转告使用者时按 README 的说法讲「过期时弹出浏览器让你登录一次」。
拿到生成的服务后，**让用户做的最少动作就是「调用一次 `login()`」**：无参数时它会在用户
本机弹窗问一次账号 + 掩码密码（口令不进对话、不写明文），用户敲一次就完成登录；因此不要
再让用户去填 `.env`（那是旧配置的兼容通道）。**弹窗会打断用户，先征得他同意再调**；弹不出
窗口时它会返回 `missing_credentials`，那时在对话里问一次、再带参调用。
换电脑 / 换 Windows 用户后凭据解不开，出路是「删掉项目里的 `cred_cache.bin` 再 `login()` 一次」，
`auth_status()` 与 401 报错里都会带上这句话。

## Basic 口令验证（必做）

抓包发现 `Authorization: Basic` 时，前端 JS 里的固定口令**可能是装饰性的，服务端并不校验**。生成前做对照实验：带该头发一次、不带头再发一次——两次都成功则口令留空即可，不要把「缺 Authorization 头」当成错误第一嫌疑（曾误导一轮排障）。
