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

安全语义：
- **用户态物理隔离**：分发包的 server.py 不含也不 import 任何 registry 写入代码——Agent 无法通过子 MCP 修改工具集，只能调用与只读诊断；
- **locked**：`project.json` 置 `locked:true` 后 merge/regenerate 均拒绝，解锁须人工改文件；
- 端点一轮没抓到只标 `unseen_since`，**永不自动删除**；合并只增不改默认值（向后兼容）；鉴权 scheme 变化必须 `allow_auth_change=true` 显式确认。
