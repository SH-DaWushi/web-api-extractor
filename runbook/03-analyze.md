# 步骤 4 · 分析

> 主索引见 `SKILL.md`。

`analyze_traffic(session_id)` → 返回**精简摘要**（host 分布 + 接口清单 + 各 host 鉴权 scheme + crypto 标记 + `full_result_path`）。

摘要里每个端点只有 `endpoint_id / method / host / path / auth_required / sample_count / description`；
**参数样本、请求/响应 Schema、噪音标记都不在摘要里**，要读 `full_result_path` 指向的 `analysis.json`。

分析器的内置能力（噪音标记 / 命名参数化 / 登录接口识别 / 站点档案）见
`docs/reference.md` 的「分析器内置能力」——**那里是唯一权威描述**，此处不重复。

- **`endpoint_id` 是衔接键**：`update_endpoint` 与 `generate_mcp_server(endpoint_ids=[...])` 都用它；
  不传 `endpoint_ids` 则生成全部端点。
- 用 `update_endpoint(session_id, endpoint_id, description=..., notes=...)` 补充信息：
  `description` 会进生成物的工具清单（给调用方看），`notes` 是自由文本备注。
- 生成阶段会自动跳过三类端点：噪音、`non_json_response`（页面 / 控件端点）、
  `not_independently_callable`（如 OData 绑定函数）。它们**只标记不删除**，需要时可用
  `endpoint_ids` 显式指定。
