# 步骤 5 · 加密与凭据核实（强制，禁止跳过）

> 主索引见 `SKILL.md`。`analyze_traffic` 的 `crypto_found` 为 true 时必读；否则可快速扫一眼跳过。

> **硬规则：抓包中的凭据字段值必然被脱敏为 `***`，明文与密文在此不可区分。禁止假设，必须核实。**

核实手段（按可靠性排序）：
1. **URL 查询参数** — `encrypt=2` / `version=2` / `sign` 之类（最可靠信号）；
2. **形态元数据**（脱敏边车）— 保留了 `len`/`shape`：如 RSA-2048 密文恒为 344 字符 base64；
3. **前端 JS** — `crypto.subtle` / `JSEncrypt` / `CryptoJS` / `sm2` 调用与 PEM 公钥块；
4. **故意发一次明文请求看错误码** — 500（解密失败）vs 业务错误码（参数错）。

`analyze_traffic` 的 `crypto_found` 为 true 时调用 `extract_crypto_logic(session_id)` 查看明细。

> ⚠️ **不要假设「CDP 拿到的一定是明文」**。CDP 捕获的是网络层实际发出的字节，可能已被 JS 加密；加密后的值同样会被抓到（且按字段名脱敏后更难察觉）。按明文实现会撞 500。
