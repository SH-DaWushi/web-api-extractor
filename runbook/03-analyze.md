# 模块 03-analyze · 步骤 4 · 分析

> 主索引见 `SKILL.md`。

`analyze_traffic(session_id)` → 返回**精简摘要**（host 分布 + 接口清单 + 各 host 鉴权 scheme + crypto 标记 + `full_result_path`）。

**它从磁盘读 `<会话>/capture.jsonl`，并把完整结果整份覆写进 `<会话>/analysis.json`**（不读内存里的
实时流量、也不会写第二份结果）。因此：可重复调用（幂等）；但**抓包有新流量后必须重调一次**，
否则 `generate_mcp_server` / `diff_capture` / `merge_capture`（它们都只读这一份 `analysis.json`）
用的还是上一版结论。这几个工具在 `analysis.json` 缺失时统一返回 `analysis_not_found` 并指向本工具。

摘要里每个端点只有 `endpoint_id / method / host / path / auth_required / auth_hint / sample_count / description`
其中 `auth_hint` 是**这条端点自己**实测到的鉴权载体：`["Bearer"]` / `["cookie"]` /
`["Basic"]`，可同时有多种 —— 同一域名下不同接口可以不一样，生成物据此逐端点发凭据；
待复核的端点再多一个 `review_suggested: true` 与一句人话 `review_suggested_hint`；
响应体被整条丢弃的端点带 `response_body_dropped: true`）；
**参数样本、请求/响应 Schema 都不在摘要里**，要读 `full_result_path` 指向的 `analysis.json`。
摘要整体还带 `stats.insufficient_samples`：**不同请求少于 2 个**的端点个数（这类端点的参数
无法比较是否可变；生成时**只对取值唯一**的参数沿用抓包取值作默认值，其余不设默认值）。
每个端点自己的 `distinct_request_count`（去重后的**不同请求**数，重复的同一个请求不算）、
`insufficient_samples`、`evidence_hint` 在 `analysis.json` 里；`evidence_hint` 就是
「**请让用户再用一次该功能**（换筛选条件 / 翻页 / 带与不带某个开关各一次），再重新抓包分析」
这条提示，生成时也会把它写进生成工具的文档字符串 —— 报给用户时照抄即可。
另有 `not_generated`：列出**生成阶段会跳过**的端点及原因（只给
`endpoint_id / method / host / path / reason / reasons / detail`，不带 schema）。

摘要里还有两组**要与使用者交代**的键：

- `auth_login_query_leads`：登录 query 参数的来源判定里**可行动**的那几条。每条带
  `auto_fill` —— 非 `null` 时表示生成的服务会在登录前**自动**去那个接口取值（使用者什么都不用
  填），`null` 表示这次不满足条件、该参数走**运行时取值链**：调用入参 → `.env` →
  本机弹窗询问（名字像密码 / 令牌 / 密钥的掩码输入）→ 都取不到才报错并点名缺哪个
  （`note` 写了原因），**不标必填**（不填也能调用）。调 `login()` 时若弹窗被取消，
  按返回体的 `missing_params` 把缺的参数名**照实**报给使用者，别让他去猜参数该填什么。
- `baked_param_defaults` / `baked_param_notice`：**哪些参数用了抓包时的取值作默认值**
  （只有参数名与端点，没有取值）。`baked_param_notice` 就是一句可以直接转告使用者的话
  （「分享这个 MCP 给他人前请检查：…」）—— 因为默认值是**抓包那一次会话**的值，
  未必适用于别人。注意：**取值会切换响应形态的参数不会出现在这里**（`count` / `pagesize` /
  `bulkbindings` / `filter` / `page` / `sort` / `format` … 以及取值为 `yes` / `no` / `true` /
  `false` / `on` / `off` 的），它们一律**不烘快照值**，并在工具文档字符串里说明原因：
  **实测过会切换形态的（`behaviour_switch is True`）是必填**；**只是名字/取值像开关、
  没有实测证据的是可选、无默认值**（不传就**不发**这个键，服务端用自己的默认值）
  （判据与理由见 `docs/reference.md` 的「取值会切换响应形态的参数」一节）—— 所以
  「分享前请检查」那句也不该提到它们，别把没烘的参数说成烘了。
- `dropped_response_bodies` / `dropped_response_bodies_hint`：有多少个响应体因为**超过体积上限
  被整条丢弃**（这些接口推断不出响应结构），以及一句**直接转告使用者**的补救话 —— 里面写着
  **下一步具体动作**：重新调 `start_capture` 并传 `response_limit_bytes=<提示给的字节数>`，
  抓完再跑一次本工具。**这件事 Agent 自己做得到**（不要再让使用者去设环境变量
  `WEB_API_EXTRACTOR_RESPONSE_LIMIT` —— 非技术使用者做不到，也不需要做）。**别自己去翻日志判断**
  —— 照这句话说。
- `truncated` / `truncated_hint`：摘要对长列表做了**有损**截断。`truncated` 给出每个列表被省略的
  条数；`truncated_hint` 说明完整清单在 `full_result_path` 的 `analysis.json` 里一条不少，
  且**不影响生成**（不传 `endpoint_ids` 时全部**可生成的**端点照旧生成，被标记跳过的仍会跳过）。
  **照这句话安抚使用者**，别让他以为数据丢了。

分析器的内置能力（噪音标记 / 命名参数化 / 登录接口识别 / 站点档案）见
`docs/reference.md` 的「分析器内置能力」——**那里是唯一权威描述**，此处不重复。

- **`endpoint_id` 是衔接键**：`update_endpoint` 与 `generate_mcp_server(endpoint_ids=[...])` 都用它；
  不传 `endpoint_ids` 则生成全部端点。
- 用 `update_endpoint(session_id, endpoint_id, description=..., notes=..., param_provenance=...)`
  补充信息：`description` 会进生成物的工具清单（给调用方看），`notes` 是自由文本备注；
  `param_provenance` 按**参数**记录「取值从哪来（`origin`）/ 影响什么（`impact`）」，形如
  `{"filter": {"origin": ..., "impact": ...}}`（也可给一段说明文字），会写进生成工具的
  文档字符串 —— 调用方 LLM 据此知道每个参数该传什么。
- **跳过是按端点身上的标记走的，不是按路径长相的**：生成阶段只跳过带这三类标记的端点 ——
  `noise`、`non_json_response`（页面 / 控件端点）、`not_independently_callable`（如 OData
  绑定函数）。它们**只标记不删除**（`analysis.json` 里仍在），生成时会出现在摘要的
  `not_generated` 里并附 `reason` —— 报给用户时照抄即可。
  把它们显式写进 `endpoint_ids` 会被拒绝并报 `Unknown endpoint_ids`。
  > 第三类只认**真** OData 绑定函数（命名空间限定名，或 `name(guid)/函数名` 形态）——
  > `/api/report.csv`、`/export/report.pdf` 这类普通导出端点**不再**被误杀，会正常生成。
- **没有任何标记的端点，一个都不会被跳过**。噪音标记是**规则匹配**（遥测/埋点域名 +
  `/system/stat/`、`/tracking/`、`/_static/` 一类路径模式），**不是**按响应体积自动判噪：
  一个体积很大、但路径不在噪音规则里、响应又是 JSON 的静态资源，会**原样保留并生成工具**
  （实测：`/admin_ui/**` 下五个静态 JSON 端点全部被保留）。所以「分析阶段会自动帮我滤掉
  没用的端点」是不成立的 —— 滤没滤到，只以 `not_generated` 为准。
  摘要里带 `review_suggested: true` 的端点**不在此列**：它只是「体积/频次大，建议人工看一眼」，
  **不会被跳过**。
- **业务文件下载端点不在这三类里**：响应是 CSV / PDF / XLSX / ZIP 等（如 `GET /api/report.csv`）
  的端点会带 `file_response: true`，虽然 `non_json_response` 仍为 true，**但不会被跳过**，
  生成的是「原样返回响应体、由调用方自行落盘」的工具（README 清单里带 `[FILE]` 标记）。
  判定很窄 —— `Content-Disposition: attachment`、文档类 `Content-Type`、或文档扩展名路径 + GET，
  所以 HTML 页面与追踪像素照旧被过滤。摘要的端点上带 `file_response: true`、`stats.file_response`
  给计数。
- **用户想保留一个会被跳过的端点**（复核 `not_generated` 后「我就是要它」）：把它的衔接键传给
  `generate_mcp_server(..., include_endpoint_ids=[...])` —— 绕过全部跳过规则照常生成，registry
  条目带 `forced_include: true`，生成的 README 单列一节说明它为什么在。`endpoint_ids` 的语义
  不变（仍然只接受可生成的键）。
- `not_generated[].reason` 取 `noise` / `not_independently_callable` / `non_json_response`
  之一（`reasons` 给出全部命中项）—— 汇报时按这个字段解释「为什么这些没被生成」。
- **`endpoint_id` 一次分配、全程不变**：合并/丢弃端点只会留下空档，**不会**让后面的
  端点继承被丢弃端点的编号 —— 摘要、`update_endpoint`、`generate_mcp_server` 三处
  认的是同一个键。
