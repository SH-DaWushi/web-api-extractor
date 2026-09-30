# 数据目录与环境变量

> 主索引见 `SKILL.md`。查配置/路径时加载。

## 数据目录

```
~/.webapiextractor/
├─ sessions/<id>/{capture.jsonl, analysis.json, session.json, scripts/, owner.json}
├─ instances/<token>.json       # 运行中实例的身份 + 心跳（pid / 启动时间指纹 / heartbeat_at）
├─ auth_states/<site_key>.json  # 登录态：Cookie 明文、账号密码 DPAPI 加密，勿提交/同步/截图
└─ audit.log                    # 工具调用审计
```

> 同一数据根可以被多个同时运行的实例共享（`WEB_API_EXTRACTOR_DATA`）：启动时的
> `recover_orphans` 只回收 **owner 可证明已消失**的会话（判定顺序见 `docs/reference.md` 的
> 「多个实例共享一个数据根」），不会把另一个实例正在抓的会话判死。空闲超时自动 `paused`
> 会先把已抓到的数据落盘，并把 `pause_reason` 与这次转换写进元数据（不是静默发生）。

> ⚠️ `auth_states/<site_key>.json` 里 **Cookie 是明文的**（Playwright `storage_state` 格式），
> 账号密码则由 `http_login` 用 **DPAPI 加密**后存进 `secrets_enc`，不再写明文（旧版明文
> `secrets` 字段仍可读、在被读取时迁移，`read_auth_state_secrets()` 是迁移/排查工具）。
> `open_browser_login` 用 `storage_state` 整体重写该文件时会先取出旧的 `secrets_enc`
> 再合并回去，凭据不再被丢掉。文件名取 netloc 并把 `.` / `:` 换成 `_`
> （`oa.example.com` → `oa_example_com.json`）。字段说明与脱敏范围见
> `docs/reference.md` 的「安全设计」。

## 环境变量

完整清单见 **`docs/reference.md` 的「数据目录与环境变量」**一节（含 2 个噪音阈值变量）。
这里不再重复维护 —— 两处各存一份表正是上轮出现漂移的原因。实现见 `webapi_extractor/config.py`；
**例外**：`WEB_API_EXTRACTOR_PROBE_TIMEOUT` 实现在 `probe.py`。
