# 数据目录与环境变量

> 主索引见 `SKILL.md`。查配置/路径时加载。

## 数据目录

```
~/.webapiextractor/
├─ sessions/<id>/{capture.jsonl, analysis.json, session.json, scripts/}
├─ auth_states/<site_key>.json  # 登录态，**明文**，勿提交/同步/截图
└─ audit.log                    # 工具调用审计
```

> ⚠️ `auth_states/<site_key>.json` 是**明文**文件：Cookie 原样保存，`http_login` 默认还会把
> 账号与密码写进 `secrets` 字段。文件名取 netloc 并把 `.` / `:` 换成 `_`
> （`oa.example.com` → `oa_example_com.json`）。字段说明与脱敏范围见
> `docs/reference.md` 的「安全设计」。

## 环境变量

完整清单见 **`docs/reference.md` 的「数据目录与环境变量」**一节（含 2 个噪音阈值变量）。
这里不再重复维护 —— 两处各存一份表正是上轮出现漂移的原因。实现见 `webapi_extractor/config.py`；
**例外**：`WEB_API_EXTRACTOR_PROBE_TIMEOUT` 实现在 `probe.py`。
