# 步骤 6 · 生成（registry 项目）

> 主索引见 `SKILL.md`。

`generate_mcp_server(session_id, output_dir, endpoint_ids=[...])` → 生成**项目**：

```
<output_dir>/
├─ project.json / registry.json   # registry 由 merge 维护，版本号随每次合并 +1
├─ server.py                       # 多域名路由 + 类型化参数 + 按实测 scheme 鉴权
├─ requirements.txt / .env.example / README.md / smoke_test.py
└─ captures/                       # 各轮合并的 provenance
```

> ⚠️ `regenerate_server` **只重渲染代码与文档，不写 `registry.json`**（重新渲染时它会主动移除
> registry.json，因为"registry 归 merge 管"）。所以别指望 regenerate 更新 registry ——
> 端点的增改一律走 `diff_capture` → `merge_capture`（见 `runbook/06-iterate.md`）。

生成器的完整能力清单（多域名路由、类型化签名与默认值门槛、鉴权 scheme、登录工具与续期语义、
写操作护栏、只读诊断）见 `docs/reference.md` 的「生成的子 MCP 自带的能力」——**那里是唯一权威描述**。
一句话提醒：`login()` 与 401 自动重登录**只在识别到 `auth_login` 时才生成**。

## Basic 口令验证（必做）

抓包发现 `Authorization: Basic` 时，前端 JS 里的固定口令**可能是装饰性的，服务端并不校验**。生成前做对照实验：带该头发一次、不带头再发一次——两次都成功则口令留空即可，不要把「缺 Authorization 头」当成错误第一嫌疑（曾误导一轮排障）。
