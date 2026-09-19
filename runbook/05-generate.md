# 步骤 6 · 生成（registry 项目）

> 主索引见 `SKILL.md`。

`generate_mcp_server(session_id, output_dir, endpoint_ids=[...])` → 生成**项目**：

```
<output_dir>/
├─ project.json / registry.json   # registry 为唯一事实源
├─ server.py                       # 多域名路由 + 类型化参数 + 按实测 scheme 鉴权
├─ requirements.txt / .env.example / README.md / smoke_test.py
└─ captures/                       # 各轮合并的 provenance
```

生成器能力：
- **多域名路由** + **类型化签名**（query/path 样本 → `page: int = 1`）；
- **默认值门槛**：仅多轮采样稳定、短、纯 ASCII、无逗号且非身份/时间类的参数才有默认值（防隐私泄漏与过期默认值）；
- **鉴权按实测**：Basic/Bearer/Cookie 分别生成；
- **写操作护栏**：非 GET 工具需 `confirm=true`，写 audit.log；
- **登录工具**（识别到 auth_login 时）：`login()` / `auth_status()`——凭据与 token **DPAPI 加密持久化**（`cred_cache.bin`/`token_cache.bin`，仅同一 Windows 用户可解密，已列 .gitignore），重启自动恢复，**401 自动重登录并重试一次**；密码按前端实测策略加密传输；
- **用户态诊断**：`tool_catalog`（含 registry_version）/ `error_log_tail`。

## Basic 口令验证（必做）

抓包发现 `Authorization: Basic` 时，前端 JS 里的固定口令**可能是装饰性的，服务端并不校验**。生成前做对照实验：带该头发一次、不带头再发一次——两次都成功则口令留空即可，不要把「缺 Authorization 头」当成错误第一嫌疑（曾误导一轮排障）。
