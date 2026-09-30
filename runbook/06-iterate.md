# 模块 06-iterate · 步骤 7 · 持续迭代（IT 管理态专属）

> 主索引见 `SKILL.md`。仅当要补全/修正已生成项目时加载。

初次抓包漏掉的 API，补一轮抓包后**增量合并**，而非推倒重建：

```
再抓一轮遗漏功能 → analyze_traffic
→ diff_capture(project_dir, session_id)                     # 只读差异报告
→ 与用户确认报告
→ merge_capture(project_dir, session_id, endpoint_keys?)    # version+1
→ regenerate_server(project_dir)                            # 从 registry 重出代码，旧文件留 .bak
→ export_project(project_dir, out_dir)                      # 导出用户态分发包
```

- `diff_capture` 只比对**新增端点**、**query 参数名集合的变化**与**本轮未见端点**；它不报值变化，
  也不看请求体。**要不要合并由用户拍板**——先把报告讲给用户听，再动手合并。（「未见」只统计
  这次抓包里**根本没出现**的端点；一条本轮仍在、只是被判成噪音的端点不会被误报成「未见」。）
- 参数提示：`merge_capture(..., endpoint_keys=[...])` 可只合并选定端点；**鉴权方式发生变化时
  必须显式传 `allow_auth_change=true`**（默认拒绝，防止鉴权方式被静默改写）。「这一轮一条
  Authorization 都没再抓到」也算变化（修复前它被静默放过，合并后 Bearer 站点的工具会全部
  401）；**同一域名混用多种方式不算** —— 那只是 `auth_conflicts_hint` 里的一句告知，合并照样
  成功，也可以顺口告诉用户「你不需要为它做任何配置」。
- **不传 `endpoint_keys` ≠ 把抓到的每一条都并进来**：只并「会被生成的」端点。噪音 / 不可独立
  调用 / 非 JSON 页面端点不会进 registry，但会逐条列在返回值的 `not_merged`（+ `not_merged_hint`
  说明下一步：`generate_mcp_server(include_endpoint_ids=[…])` 可显式点名包含）——**把这份清单也
  讲给用户听**，不要只报一个 added 数字让他以为全并完了。
- 安全语义（用户态隔离 / `locked` / `unseen_since` 永不自动删除）见 `docs/reference.md` 的
  「生成的子 MCP 自带的能力」——**那里是唯一权威描述**。
- 这条链路（merge / regenerate / export / 用户态隔离 / locked）由 `tests/test_iterate_chain.py`
  （库层语义）与 `tests/test_iterate_tools.py`（工具层契约）覆盖 —— 改动生成逻辑后跑这两份。
  仍未覆盖的部分见 reference「测试」。
