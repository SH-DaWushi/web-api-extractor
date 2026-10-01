# 免责声明与使用范围 / Disclaimer and Scope of Use

本文件说明 scry-mcp-gen 的使用边界。**简体中文在前，English follows。**

---

## 一、适用范围

本工具用于在**您自己拥有、或已获得明确授权测试 / 自动化**的系统上提取网页接口。

它会记录 HTTP 流量，并驱动一个真实浏览器完成登录与操作。把它用在**您无法控制的系统**上，
可能违反法律，也可能违反目标站点的使用条款。是否使用、用在哪些系统上，由您自行判断并承担后果。

本工具**仅支持 Windows**。

## 二、本工具不做什么

- **不绕过身份验证**。它使用的是您本人在浏览器里完成的登录。
- **不破解验证码（CAPTCHA）**。
- **不替您判定登录是否完成**。交互式登录 —— 技能侧与**生成的服务**里是同一套约定 —— 只拉起
  一个真实浏览器窗口由您本人登录（验证码 / 短信 / 单点验证都由您完成），服务只观察旁证并
  **等您确认**，绝不自动放行（也绝不在您还没登好时把会话判成完成）。
- **不逆向工程登录加密**。遇到需要交互验证、验证码或无法自动处理的登录流程时，它会回落到
  **由您本人手动完成授权**，而不是尝试突破这些机制。

## 三、凭据处理警告

- **本工具自身的登录态文件：Cookie 是明文的，账号密码是加密的**（`auth_states/<site_key>.json`）：
  `http_login` 会用 Windows DPAPI（用户作用域）把**账号与密码**加密后存入 `secrets_enc` 字段，
  **不再写明文**；因此只有**同一台机器上的同一个 Windows 用户**能解出密码，文件被复制到别处则
  密码不可读（Cookie 仍可读——它是 Playwright 的 `storage_state` 格式，功能上必需）。DPAPI 不可用
  或加密失败时**不落盘任何明文**，凭据只留在本次进程内存中。旧版本残留的明文 `secrets` 字段仍可读，
  会在**被读取时**迁移为 `secrets_enc`（未被读取的旧文件在磁盘上仍是明文）。该文件**只能留在您的
  本机**，禁止提交、同步、截图或分享。
- **抓取的 URL 与响应体不做脱敏**：URL 里的 token、响应体的全部内容都会原样写入抓取数据。
- **只有请求侧的 JSON 体与表单编码体会被脱敏**（凭据值抹为 `***`），`Authorization` 与带 token 的
  常见凭据请求头也会遮蔽；`multipart/form-data`、XML 等非 JSON / 非表单的请求体不脱敏。
- 因此，抓取数据与登录态文件都按**敏感数据**对待（登录态文件里的 Cookie 是明文的）。

（生成出来的子项目不落明文凭据：其登录缓存以 DPAPI 加密保存，且仅同一 Windows 用户可解密。）

## 四、无担保

本工具按“现状”提供。**不保证**生成的工具正确、完整或安全，也**不保证**它能一直可用 ——
目标系统随时可能改版，接口、字段与登录方式都可能失效。请在依赖生成结果前自行核实。

## 五、您的责任

使用本工具的法律、合规与安全责任由**使用者本人**承担。作者不对因使用本工具而产生的任何
后果负责。

## 六、非法律意见

本文件不是法律意见，也不能替代针对您具体情况的专业法律咨询。

---

## 商店条目摘要 / Store listing summary

可直接粘贴到商店条目描述：

- **仅支持 Windows**：本技能只在 Windows 上运行。
  **/ Windows-only**: this skill runs on Windows only.
- **数据只留在本机**：抓取数据与登录态文件都保存在您的本机，不上传。
  **/ Local-only data handling**: captured data and login state stay on your machine; nothing is uploaded.
- **需要您自己的授权**：只能在您拥有或获明确授权自动化的系统上使用。
  **/ Requires your own authorisation**: use only on systems you own or are expressly authorised to automate.
- **不绕过登录、不破解验证码**：需要交互验证时，由您本人手动完成授权。
  **/ Does not bypass auth or CAPTCHA**: when interactive verification is required, you authorise it yourself.
- **Cookie 明文、账号密码加密**：本工具自身的登录态文件里 Cookie 是明文的，账号密码则经 DPAPI 加密（仅同一 Windows 用户可解）；无论如何都请勿提交、同步或分享。
  **/ Plaintext cookies, encrypted credentials**: in the tool's own auth-state file the cookies are plaintext while the account/password are DPAPI-encrypted (decryptable only by the same Windows user) — never commit, sync, or share it either way.
- **无担保**：不保证生成的工具正确、完整或持续可用。
  **/ No warranty**: generated tools are not guaranteed to be correct, complete, or durable.

---

# Disclaimer and Scope of Use (English)

This document describes the usage boundary of scry-mcp-gen.

## 1. Scope of intended use

This tool is for extracting web APIs from systems you own, or are expressly authorised to
test or automate.

It records HTTP traffic and drives a real browser for login and interaction. Using it against
systems you do not control may violate the law and may violate the target's terms of service.
Whether to use it, and on which systems, is your own judgement and your own responsibility.

This tool **supports Windows only**.

## 2. What the tool does not do

- It does **not bypass authentication**. It uses the login you complete yourself in the browser.
- It does **not solve CAPTCHAs**.
- It does **not decide for you whether login is complete**. Interactive login — the same convention
  in this skill and in the **generated service** — only opens a real browser window for you to log in
  (CAPTCHA / SMS / single sign-on are all yours to complete); the service observes side evidence and
  **waits for your confirmation**. It never proceeds on its own, and never marks the session complete
  while you are still typing.
- It does **not reverse-engineer login encryption**. When it meets interactive verification, a
  CAPTCHA, or a login flow it cannot handle automatically, it falls back to **interactive
  authorisation by you**, rather than attempting to defeat those mechanisms.

## 3. Credential handling warning

- **The tool's own login-state file: plaintext cookies, encrypted credentials**
  (`auth_states/<site_key>.json`): `http_login` uses Windows DPAPI (user scope) to encrypt the
  **account and password** into a `secrets_enc` field — **no plaintext is written any more**, so only
  the **same Windows user on the same machine** can recover the password; copied elsewhere, the
  password is unreadable (the cookies stay readable — they are the Playwright `storage_state` format
  and are functionally required). If DPAPI is unavailable or encryption fails, **nothing plaintext is
  written**: the credentials stay in the process memory only. A legacy plaintext `secrets` field is
  still readable and is migrated to `secrets_enc` **when it is read** (an untouched legacy file stays
  plaintext on disk). Keep this file on your machine only — never commit, sync, screenshot, or
  share it.
- **Captured URLs and response bodies are not redacted**: tokens in URLs and the full contents
  of response bodies are written as-is into the capture data.
- **Only request-side JSON bodies and form-encoded bodies are redacted** (credential values are
  blanked to `***`), and common credential headers such as `Authorization` / token-bearing headers are
  masked too; `multipart/form-data`, XML, and other non-JSON / non-form request bodies
  are not redacted.
- Treat both the capture data and the login-state file as sensitive (the cookies in the login-state
  file are plaintext).

(Generated sub-projects do not persist plaintext credentials: their login caches are stored
DPAPI-encrypted, decryptable only by the same Windows user.)

## 4. No warranty / no guarantees

The tool is provided "AS IS". There is **no guarantee** that the tools it generates are correct,
complete, or secure, and **no guarantee** that they will keep working — target systems change,
and endpoints, fields, and login flows can break at any time. Verify results yourself before
relying on them.

## 5. Your responsibility

Legal, compliance, and security responsibility rests with the **user**. The authors accept no
liability for any consequence arising from use of this tool.

## 6. Not legal advice

This document is not legal advice, and it is not a substitute for professional legal advice
about your particular situation.
