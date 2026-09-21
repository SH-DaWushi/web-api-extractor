# 步骤 4 · 分析

> 主索引见 `SKILL.md`。

`analyze_traffic(session_id)` → 返回**精简摘要**（host 分布 + 接口清单 + 各 host 鉴权 scheme + crypto 标记 + `full_result_path`）。分析器已内置：
- **噪音标记**（`noise: true`，不删除，生成时默认跳过）：埋点/心跳/面包屑/菜单配置/第三方统计域名；
- **命名参数化**：单样本数字段也参数化（`/user/127733/info` → `/user/{user_id}/info`），同构自动合并；
- **登录接口识别**：识别「账号+密码换 token」接口 → `auth_login`（含密码加密策略与 PEM 公钥提取），生成阶段转为 `login()`/`auth_status()` 专用工具；
- **站点档案**：可选的 `site_profiles/` 让已知站点自动应用语义化命名与中文描述；仓库不内置任何档案，按需自建。

用 `update_endpoint(session_id, endpoint_id, description=...)` 补充/修正描述。
