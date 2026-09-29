# WebAPIExtractor

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-custom%20(non--commercial)-orange)

**English** | [简体中文](README.md)

**Turn any web-only system into tools your AI can call directly — no code required.**

---

## What this is

Plenty of systems only have a web UI and no API. You want your AI assistant to look things up,
file tickets, or pull reports for you, but it cannot reach that system at all.

WebAPIExtractor takes a direct approach:

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
- **Windows** (full functionality is Windows-only; macOS / Linux can run it, but credential
  encryption is unavailable there — see below)
- **Proper authorization** for that system — only use this on systems you are permitted to use

---

## Working in two steps

### Step 1 · Get the skill into your AI assistant

Two ways; pick one — **you do not install any library, and you do not run any command**:

- **Drop it into the skills settings page** — drag the skill folder (or the
  `web-api-extractor-agent.zip` import package) into your AI assistant's **Skills** settings page.
  The exact entry point differs between clients, but every one of them keeps it under skill settings.
- **Drop it into the conversation and let the agent install it** — drag the skill folder (or the zip)
  into the conversation and tell the AI "please install this skill for me".

> Where does the zip come from? Download `web-api-extractor-agent.zip` from the
> [Releases page](https://github.com/SH-DaWushi/web-api-extractor/releases/latest) — it is the skill
> folder itself, packaged. Identical contents; you just do not have to pull the whole repository.

Once installed, **web-api-extractor** appears in your skill list. Your AI assistant now has a new
capability: **walking through a login with you in a real browser, recording what you do, and
turning it into tools.**

> The first run installs a small runtime (including a browser engine), and **the AI does all of it** —
> you do not need to care. If you really do want to do it by hand (or set it up for a colleague),
> the environment setup and start commands are in the
> [technical documentation's "Installation forms" and "Starting the server"](https://github.com/SH-DaWushi/web-api-extractor/blob/main/docs/reference.en.md).

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
| Automatic renewal (conditional) | When an account/password login endpoint is detected, the generated project can re-login automatically on token expiry; pure-Cookie / SSO sites need one re-authorization after expiry |
| Adding features later = another walkthrough | No rebuild from scratch |
| You can hand the package to colleagues | They can call the tools but cannot modify them |

---

## What it can and cannot do

> This is the overview for judging "can I use this?". The exact rules and the code behind each
> judgement are in the technical documentation's "Capability boundaries (what it cannot do)"
> and "Platform matrix" chapters.

### It can

1. **Turn a web system into a tool set for your AI** — click through it normally in a browser and
   every request and response is recorded in the background.
2. **Organize the endpoints automatically** — structurally identical endpoints merge
   (`/user/123`, `/user/456` → `/user/{id}`), and parameter types are derived from real samples.
3. **Cover both kinds of login** — sites where a request can be constructed use form login; CAPTCHAs,
   SMS codes, and single sign-on use interactive login in a real browser
   (**you confirm whether login is complete**; the tool never decides that itself).
4. **Generate a runnable MCP project** — multi-host routing, typed parameters, the auth scheme
   actually observed, `confirm=true` required for writes, plus a smoke test and read-only diagnostics.
5. **Encrypt credentials, restore them after a restart, and re-login automatically on 401** —
   conditional on an account/password login endpoint having been detected, and on Windows.
6. **Iterate incrementally** — capture another round → review the diff → merge → regenerate.
   Endpoints missed in a round are only marked "not seen this round" and are
   **never deleted automatically**.
7. **Redact at record time** — credential values in JSON and form bodies are erased on the spot,
   while length and shape are kept so you can still tell whether something is ciphertext.
8. **Export a "user-mode distribution package"** — the copy you give a colleague can only call
   tools and read diagnostics; it cannot change the tool set.

### It cannot

| Cannot | Why |
|---|---|
| **Upload files** | File-upload request bodies are neither parsed into parameters nor redacted; attachment contents are not analyzed |
| **Real-time push** | WebSockets are recorded only as "a connection was established"; frame contents are not captured, and streaming responses get no special handling |
| **Download files** | Downloads are treated like any other response — not distinguished, not written to disk |
| **GraphQL** | Treated as an ordinary endpoint; query semantics are not expanded |
| **Binary interfaces** | Responses such as protobuf are not decoded, so no structured fields can be extracted |
| **Response schemas for large endpoints** | A response over 256 KB is dropped **entirely** (not truncated), so no response structure is available |
| **Automatic renewal for pure-Cookie / SSO sites** | No automatic re-login for these; expiry requires re-authorizing once |
| **Machines without a desktop** | Capture and login must open a real browser window |

### Conditional

- **Only the features you actually operated will show up** — endpoints you never clicked are not guessed.
- **When you log in with an account and password, both are written in plaintext into the session
  file** — it belongs on your own computer only. Do not commit it, sync it, screenshot it, or share it.
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
> the platform matrix, and the known boundaries), see **[Learn more](#learn-more)** at the end.

---

## FAQ

| Question | Answer |
|---|---|
| Do I need to know how to program? | No. It is all conversation plus browser interaction. |
| Are my account and password safe? | **The session file is plaintext** (a JSON file under the local `auth_states/` directory; when you log in with an account and password, both are written into it too), so it can only stay on your own computer — **do not commit it, sync it, screenshot it, or share it**. During capture, credential values in JSON and form bodies are replaced with `***`, but **URLs and response bodies are not redacted**; in the generated project credentials are stored encrypted (Windows only). Full details in the technical documentation's "Security design" (see [Learn more](#learn-more) at the end). |
| Is any data uploaded to the cloud? | No. Everything is recorded in a data directory on your own computer (`~/.webapiextractor`). |
| Which systems are supported? | Any system you can log into and operate in a browser — including internal systems behind CAPTCHAs, SMS verification, or single sign-on (those go through interactive authorization; **an expired session needs re-authorizing once**, it will not renew automatically). |
| How complex a feature can it handle? | It depends on what you clicked through in the browser. File upload, WebSocket push, GraphQL, and binary interfaces are out of scope — see "It cannot" above. |
| Can I share the generated tools? | Yes. Hand the distribution package to a colleague; they can call the tools but cannot modify the tool set. |
| What if the system changes? | Walk through it again and have the AI merge the differences. No redo. |
| Will the data keep growing? | Yes. The capture log only appends and is never cleaned automatically; long sessions need manual cleanup of the data directory. |
| Can I use it on non-Windows? | It runs, but credential encryption is unavailable (credentials stay in memory only, so you log in again after a restart), and a desktop environment is required. See the technical documentation's "Platform matrix" for the item-by-item differences. |
| Is this a Skill or an MCP server? | You do not need to distinguish. Underneath it is an MCP server; on top it is a skill your agent can invoke — import the skill and you are done. |

---

## Learn more

The section above covers "what you get". **Technical details, capability boundaries, and security
semantics** all live in the technical documentation:

📄 **[docs/reference.en.md](https://github.com/SH-DaWushi/web-api-extractor/blob/main/docs/reference.en.md)**
— the `docs/reference.en.md` inside the skill folder; the same file.

| What you want to know | Chapter |
|---|---|
| What the 21 tools are and what arguments each takes | "Tool list", "Tool argument quick reference" |
| Which systems / features are out of scope | "Capability boundaries (what it cannot do)" |
| How far Windows, macOS, and Linux are each supported | "Platform matrix" |
| Exactly how credentials and data are stored, and how far redaction goes | "Security design" |
| What to do when a session expires, and when automatic re-login applies | "Renewal semantics" |
| Where data lives and whether it keeps growing | "Data directory and environment variables" |
| An endpoint will not open, or a tool errors out | `runbook/99-troubleshooting.md` (the troubleshooting quick reference inside the skill) |
| Setting up an environment yourself, driving from the command line, changing the code (for technical colleagues) | "Installation forms", "Starting the server", "Tests" |

> Environment setup, starting the server, and command-line driving are **not things a user does** —
> once the skill is installed the AI handles them. They are documented for the technical people who
> want to work on it directly.

---

## License

The scope and restrictions of use for this project are governed by [LICENSE](LICENSE):

- Personal learning, testing, and non-commercial use are permitted
- Redistributing modifications requires retaining the original source attribution
- Derivative work based on this project must be released as open source
- Direct commercial use is not permitted

## Disclaimer (scope of use)

> The Chinese text in [README.md](README.md) is the original of this disclaimer and prevails;
> the English below is a faithful translation provided for convenience.

This project is intended solely for lawful and compliant development, testing, interface analysis,
documentation generation, integration verification, and compliance assessment — to help users study,
understand, and manage the interface behavior of **systems they are authorized to access**.

Users must comply with the laws and regulations of the People's Republic of China and any locally
applicable law, and must independently confirm the legality of their use. The following uses are not
considered legitimate uses of this project:

- Unauthorized system probing, attacks, authentication bypass, disruption of service availability,
  or any action violating a website's or platform's terms of service
- Stealing, leaking, tampering with, or misappropriating the data or sensitive information of others
- Unlawful access to, scraping of, analysis of, or processing of protected interfaces and data
- Causing a target system to go down, interrupting service, denying service, or otherwise harming
  the lawful interests of others
- Any purpose that violates applicable law, contract, industry norms, or security requirements

This project assumes no responsibility for any action taken by its users. Before using this project
against external systems, users must first confirm they hold the appropriate authorization and legal
basis, and they bear the security and compliance responsibility themselves.
