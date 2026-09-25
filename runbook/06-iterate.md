# 步骤 7 · 持续迭代（IT 管理态专属）

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
  也不看请求体。**要不要合并由用户拍板**——先把报告讲给用户听，再动手合并。
- 参数提示：`merge_capture(..., endpoint_keys=[...])` 可只合并选定端点；**鉴权 scheme 发生变化时
  必须显式传 `allow_auth_change=true`**（默认拒绝，防止鉴权方式被静默改写）。
- 安全语义（用户态隔离 / `locked` / `unseen_since` 永不自动删除）见 `docs/reference.md` 的
  「生成的子 MCP 自带的能力」——**那里是唯一权威描述**。
- 这条链路（merge / regenerate / export / 用户态隔离 / locked）由 `tests/test_iterate_chain.py`
  （库层语义）与 `tests/test_iterate_tools.py`（工具层契约）覆盖 —— 改动生成逻辑后跑这两份。
  仍未覆盖的部分见 reference「测试」。
