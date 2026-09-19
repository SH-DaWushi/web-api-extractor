# 数据目录与环境变量

> 主索引见 `SKILL.md`。查配置/路径时加载。

## 数据目录

```
~/.webapiextractor/
├─ sessions/<id>/{capture.jsonl, analysis.json, session.json, scripts/}
├─ auth_states/<site>.json      # 登录态，含敏感数据，勿提交/截图
└─ audit.log                    # 工具调用审计
```

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `WEB_API_EXTRACTOR_DATA` | `~/.webapiextractor` | 数据根目录 |
| `WEB_API_EXTRACTOR_RESPONSE_LIMIT` | `262144` | 响应体截断上限(字节) |
| `WEB_API_EXTRACTOR_IDLE_TIMEOUT` | `300` | 空闲自动暂停(秒) |
| `WEB_API_EXTRACTOR_MAX_SESSIONS` | `3` | 并发抓包会话上限 |
