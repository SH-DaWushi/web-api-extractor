# scry-mcp-gen

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-custom-orange)

**English** | [简体中文](README.md)

**Turn any web-only system into tools your AI can call directly — no code required.**

---

## What this is

Plenty of systems only have a web UI and no API. You want your AI assistant to look things up,
file tickets, or pull reports for you, but it cannot reach that system at all.

scry-mcp-gen takes a direct approach:

> **However you click through the site, it records it — then turns those operations into tools your AI can call.**

You do not read API documentation, you do not write code, and you do not need to understand
any technical terminology.

---

## Who it is for

- You have a system that is **web-only and operated by hand** (OA, ERP, CRM, ticketing,
  reporting, internal admin panels…)
- You want an AI assistant to take over the repetitive work inside it
- There is no API documentation, and no engineering resource to build one

**What you need:**

- A desktop AI assistant client that supports **Skills**
- Your own computer (all data stays local)
- **Windows** (the only supported platform; macOS / Linux are **not supported** and untested —
  credential encryption relies on Windows DPAPI, and capture and interactive login must open a real
  desktop browser window)
- **Proper authorization** for that system — only use this on systems you are permitted to use

---

## Working in two steps

### Step 1 · Get the skill into your AI assistant

Two ways; pick one — **you do not install any library, and you do not run any command**:

- **Install it from the skill store** — find **scry-mcp-gen** in your AI assistant's **Skills**
  store and install it. The exact entry point differs between clients, but every one of them keeps
  it under skill settings.
- **Drop it into the conversation and let the agent install it** — drag the skill folder into the
  conversation and tell the AI "please install this skill for me".

Once installed, **scry-mcp-gen** appears in your skill list. Your AI assistant now has a new
capability: **walking through a login with you in a real browser, recording what you do, and
turning it into tools.**

> The first run installs a small runtime (including a browser engine), and **the AI does all of it** —
> you do not need to care. If you really do want to do it by hand (or set it up for a colleague),
> the environment setup and start commands are in `runbook/00-environment.md` inside the skill.

### Step 2 · Tell it what you want, in plain conversation

Nothing to memorize — just talk to it:

```
You: Build me a set of MCP tools for our OA system
AI:  (opens a browser) Please log in in the window that just opened, then tell me
You: Logged in
AI:  Session saved. Now please perform, in the browser, every function you want
     turned into a tool — e.g. browse a list, open a detail page, submit a request
You: (done) OK
AI:  Got it — 23 endpoints captured. The login endpoint encrypts its password,
     let me verify that before generating
     ……
     Done. These tools are ready:
       · my_todo_items      · ticket_detail
       · submit_ticket      · export_report
     You (or any AI connected to them) can call them directly from now on
```

**All you do throughout is two things: log in in the browser, then click through the features you want.**

---

## What you end up with

A tool set you can **keep using and keep extending**:

| What you get | What it means |
|---|---|
| Your AI can operate that system directly | No more clicking through web pages by hand |
| The session is reusable | Both capture and later calls can carry the session; no repeated logins |
| Automatic renewal (conditional) | When an account/password login endpoint is detected **and the request really can be constructed**, the generated project can re-login automatically on token expiry; CAPTCHA / SMS / SSO sites need **one login by you** after expiry (the generated project opens the browser window itself, so you do not have to go back to the agent) |
| Adding features later = another walkthrough | No rebuild from scratch |
| You can hand the package to colleagues | They can call the tools but cannot modify them |

---

## What it can and cannot do

> This is the overview for judging "can I use this?". The exact rules and the code behind each
> judgement are in `runbook/90-reference.md` inside the skill.

### It can

1. **Turn a web system into a tool set for your AI** — click through it normally in a browser and
   every request and response is recorded in the background.
2. **Organize the endpoints automatically** — structurally identical endpoints merge
   (`/user/123`, `/user/456` → `/user/{id}`), and parameter types are derived from real samples.
   **Values that are safe to reuse become defaults** (whatever the capture carried is what you get),
   so neither you nor the AI has to guess "what should this parameter be". **Parameters whose value
   changes what comes back are the exception** (for example `count=yes` on a device API: that returns
   only a count, not the actual list) — such parameters are never hard-coded. **Where it was actually
   measured to change what comes back** (both values appeared in the capture), the service asks you to
   state it explicitly, so the AI does not mistake incomplete data for the whole picture; **where the
   name merely sounds like a switch** (`page` / `sort` / `format` …), the service neither hard-codes it
   nor insists — leave it out and it is not sent at all, so the server uses its own default; if what
   comes back looks incomplete, call once more with another value. Before
   you share the package, the service lists **which parameters reused captured values** (names only,
   so you can check them) instead of quietly shipping capture data.
3. **Cover both kinds of login** — sites where a request can be constructed use form login; CAPTCHAs,
   SMS codes, and single sign-on use interactive login in a real browser
   (**you confirm whether login is complete** — a workflow convention: the server can only record and
   warn, it never decides that for you). Which kind a site is, is decided by **actually trying** —
   a login request is really sent once and the outcome is recorded, so **the generated project
   carries that ability too**: for a CAPTCHA site it opens a browser window and lets you log in once
   (`login_interactive()`) when the session expires, instead of pretending it can re-login
   automatically (which would only make you think it was configured correctly).
   If logging in needs an extra parameter (a login page asking
   for a one-time token, say) **and it can be fetched from a public endpoint**, the generated server
   fetches it itself before logging in — **you fill in nothing**; if it cannot be fetched, login fails
   loudly and tells you to capture again.
4. **Generate a runnable MCP project** — multi-host routing, typed parameters, and credentials sent
   **per endpoint** using the method actually observed (on one server some endpoints use
   Authorization while others accept only cookies, with nothing for you to configure), `confirm=true`
   required for writes with a dedicated "tools that change data" list in the README, plus a smoke
   test and read-only diagnostics.
5. **Encrypt credentials, restore them after a restart, and re-login automatically on 401** —
   conditional on an account/password login endpoint having been detected, on the request really
   being constructible, and on Windows; CAPTCHA / SSO sites get **one-click re-login instead** (a
   browser window opens and you log in yourself) — the tool never pretends it can renew by itself.
6. **Iterate incrementally** — capture another round → review the diff → merge → regenerate.
   Endpoints missed in a round are only marked "not seen this round" and are
   **never deleted automatically**.
7. **Redact at record time** — on the request side, credential material is erased on the spot:
   a JSON/form field whose *name* looks like a credential (including synonyms such as `pass` / `pin` /
   `otp` / `api_key`, and form bodies with valueless control segments) has its value erased, and
   token-bearing headers are masked too — while length and shape are kept, so you can still tell
   whether something is ciphertext.
8. **Export a "user-mode distribution package"** — the copy you give a colleague can only call
   tools and read diagnostics; it cannot change the tool set.

### It cannot

| Cannot | Why |
|---|---|
| **Upload files** | File-upload request bodies are neither parsed into parameters nor redacted; attachment contents are not analyzed |
| **Real-time push** | Both the WebSocket connection and its frame contents **are recorded in the capture** (credentials are redacted the same way), but they **are not** turned into tools; streaming responses still get no special handling |
| **Download files (automatic / streaming to disk)** | Business file downloads (CSV / PDF / XLSX / ZIP etc.) are recognised and generated as `[FILE]` tools that return the body verbatim (text in `text`, binary in `base64`); writing it to disk is left to the caller — automatic / streaming download to disk is not supported |
| **GraphQL** | Treated as an ordinary endpoint; query semantics are not expanded |
| **Binary interfaces** | Responses such as protobuf are not decoded, so no structured fields can be extracted |
| **Response schemas for large endpoints** | A response over 256 KB is dropped **entirely** (not truncated), so no response structure is available. Not a dead end: the Agent can raise the limit (up to 64 MB) and capture again |
| **Automatic renewal for CAPTCHA / encrypted-password sites** | A constructed request cannot pass the CAPTCHA, so there is **no automatic re-login** — expiry needs one login by you. The generated project brings that itself: `login_interactive()` opens a real browser window for you to log in, and `confirm_login()` saves it once you confirm (**it never decides "you are logged in" on its own**) |
| **Machines without a desktop** | Capture and login must open a real browser window |

### Conditional

- **Only the features you actually operated will show up** — endpoints you never clicked are not guessed.
- **In the session file the cookies are still plaintext, while the account and password are
  DPAPI-encrypted** (decryptable only by the same Windows user on the same machine; if DPAPI is
  unavailable, nothing is written rather than plaintext) — the file belongs on your own computer only.
  Do not commit it, sync it, screenshot it, or share it: copied elsewhere, the cookies stay readable
  but the password does not.
- **In the generated tools the credentials are encrypted as well, and they only recognise you on this
  machine** — move to another computer, or switch to a different Windows user, and the encrypted
  credentials can no longer be decrypted. The way out is simple: **delete `cred_cache.bin` from the
  project and log in once more** (the service first asks you once for the account and password in a
  native window; the status and error messages tell you this same sentence). When you share the
  generated tools with a colleague, **the credentials do not travel with the package** — the other
  person just logs in once themselves.
- **Records are not cleaned up automatically** — the capture log only appends; there is no rotation,
  so long sessions keep growing.
- **No reverse-engineering or bypassing of CAPTCHAs or login encryption is provided** — when you hit
  one, you go through interactive authorization.

---

## How it works

In one sentence: **it opens a real browser alongside you, records every operation you perform,
and turns them into tools.**

You do not need to follow what happens in between — that is the AI's job.

> For the technical implementation (endpoint normalization, the exact scope of redaction,
> encryption detection, generator capabilities, environment variables, the full list of 21 tools,
> the platform matrix, and the known boundaries), see `runbook/90-reference.md` inside the skill.

---

## FAQ

| Question | Answer |
|---|---|
| Do I need to know how to program? | No. It is all conversation plus browser interaction. |
| Are my account and password safe? | **In the session file the cookies are plaintext and the account/password are stored encrypted** (a JSON file under the local `auth_states/` directory; `http_login` encrypts them with Windows DPAPI into a `secrets_enc` field, decryptable only by the same Windows user on the same machine, and if DPAPI is unavailable nothing is written rather than plaintext; a legacy file may stay plaintext until it is read), so it can only stay on your own computer — **do not commit it, sync it, screenshot it, or share it**. During capture, redaction covers the **request side**: a JSON/form field whose name looks like a credential (including synonyms such as `password` / `pass` / `pin` / `otp` / `token` / `api_key`, and form bodies with valueless control segments) has its value replaced with `***`, and `Authorization` / token-bearing headers are masked too; but **URLs and response bodies are not redacted**, and request bodies that are neither JSON nor form-encoded (`multipart`, XML, plain text) are not redacted either. In the generated project credentials are stored encrypted (Windows only). Full details in `DISCLAIMER.md` and `runbook/90-reference.md` inside the skill. |
| Is any data uploaded to the cloud? | No. Everything is recorded in a data directory on your own computer (`~/.scry`). |
| Which systems are supported? | Any system you can log into and operate in a browser — including internal systems behind CAPTCHAs, SMS verification, or single sign-on (those go through interactive authorization; **an expired session needs one login by you**, it will not renew automatically — the generated project opens the browser window for that). |
| How complex a feature can it handle? | It depends on what you clicked through in the browser. File upload, GraphQL, and binary interfaces are out of scope; WebSocket frame contents are recorded in the capture but are not turned into tools — see "It cannot" above. |
| Can I share the generated tools? | Yes. Hand the distribution package to a colleague; they can call the tools but cannot modify the tool set. |
| What if the system changes? | Walk through it again and have the AI merge the differences. No redo. |
| Will the data keep growing? | Yes. The capture log only appends and is never cleaned automatically; long sessions need manual cleanup of the data directory. |
| Can I use it on non-Windows? | **No — not supported.** This skill supports Windows only: credential encryption relies on Windows DPAPI, and capture and interactive login must open a real desktop browser window. macOS / Linux are neither supported nor tested. |
| Is this a Skill or an MCP server? | You do not need to distinguish. Underneath it is an MCP server; on top it is a skill your agent can invoke — import the skill and you are done. |
| An endpoint will not open, or a tool errors out. | See `runbook/99-troubleshooting.md` inside the skill (the troubleshooting quick reference). |

---

## Learn more

| What you want to know | Where to look |
|---|---|
| What the 21 tools are and what arguments each takes | `runbook/90-reference.md` inside the skill |
| How the login, capture, analyze, and generate steps are run | the `runbook/` directory inside the skill (00 environment → 05 generate → 06 iterate) |
| An endpoint will not open, or a tool errors out | `runbook/99-troubleshooting.md` inside the skill |
| Scope of use, credential handling warning, no warranty, limitation of liability | [DISCLAIMER.md](DISCLAIMER.md), in the same folder |

---

## License

**The `LICENSE` inside the package you actually received is the one that applies.** In short:

- **You may**: install the skill you obtained from the store and use it, including for the internal
  business purposes of you or your organisation; keep and run it locally for that use; distribute it
  through the store you obtained it from, on the terms that store requires of its listings.
- **You must**: retain the copyright and attribution notices.
- **You may not**: resell the skill itself, or charge others specifically for it as a standalone
  product; re-upload or redistribute it outside the store you obtained it from without prior written
  permission; sublicense it; or distribute a modified version to others.
- **Modifying it for your own internal use is allowed**; distributing that modified version to others
  is not, unless you have written permission.

> The license is a **self-authored usage-boundary statement and has not been reviewed by a lawyer** —
> obtain legal review before relying on it as the sole legal basis for a specific deployment.
> Please also read [DISCLAIMER.md](DISCLAIMER.md) (scope of use, credential handling warning,
> no warranty, limitation of liability).

## Disclaimer (scope of use)

> The Chinese text in [README.md](README.md) is the original of this disclaimer and prevails;
> the English below is a faithful translation provided for convenience.

This skill is intended solely for lawful and compliant development, testing, interface analysis,
documentation generation, integration verification, and compliance assessment — to help users study,
understand, and manage the interface behavior of **systems they are authorized to access**.

Users must comply with the laws and regulations of the People's Republic of China and any locally
applicable law, and must independently confirm the legality of their use. The following uses are not
considered legitimate uses of this skill:

- Unauthorized system probing, attacks, authentication bypass, disruption of service availability,
  or any action violating a website's or platform's terms of service
- Stealing, leaking, tampering with, or misappropriating the data or sensitive information of others
- Unlawful access to, scraping of, analysis of, or processing of protected interfaces and data
- Causing a target system to go down, interrupting service, denying service, or otherwise harming
  the lawful interests of others
- Any purpose that violates applicable law, contract, industry norms, or security requirements

This skill assumes no responsibility for any action taken by its users. Before using this skill
against external systems, users must first confirm they hold the appropriate authorization and legal
basis, and they bear the security and compliance responsibility themselves.
