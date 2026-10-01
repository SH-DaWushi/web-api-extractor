# Packaging and project structure

This file is for **maintainers and secondary developers**: how the repository is organized, how it is
packaged, and how the two distribution editions differ.

It **ships with no distribution package** (it is not in `package-agent.py`'s `INCLUDE`) — precisely
because it describes the repository's own organization, and the store edition must be self-contained
in its documentation and must not lead back to the open-source edition. Users read `README.md`;
the technical semantics that ship with a package live in `docs/reference.md`.

---

## 1. Working from source

**This project is not published to PyPI, so you must work from source.**

```bash
git clone https://github.com/SH-DaWushi/web-api-extractor.git
cd web-api-extractor
```

Editable install as a Python library:

```bash
pip install -e .
python -m playwright install chromium
```

The entry points are then `scry-mcp-gen` (stdio, see `[project.scripts]` in `pyproject.toml`)
and `python -m scry_mcp_gen serve-http`; the repository-local driver scripts (`mcp_call.py`,
`start_server.py`, …) are not in the package. The runtime dependencies are only
`fastmcp / httpx / playwright`; the test runner (`pytest` / `pytest-asyncio`) is **optional** —
`pip install -e .` does **not** install it, use `pip install -e ".[test]"` (equivalent to
`pip install -r requirements-dev.txt`), otherwise `asyncio_mode=auto` is silently ignored
(see section 5).

---

## 2. Editions and licensing

This project ships as **two editions with different terms** — **the `LICENSE` inside the package you
actually received is the one that applies**:

| Edition | Where it comes from | Terms |
|---|---|---|
| Open-source | this repository, the GitHub Releases skill package | the repository's root `LICENSE` (custom, **non-commercial**) |
| Store | the package distributed through a skill store | the `LICENSE` inside that package, which is `LICENSE-STORE` (a custom **store-distribution license**) |

The store edition grants store listing and end-user use (including internal business purposes), retains
attribution and disclaimers, forbids resale, redistribution outside that store, sublicensing and
distributing modified versions (private modification is fine).

**The two editions are independent of each other**: the store edition does not describe the
open-source edition and carries no pointer to this repository (its README, license text and technical
reference are its own). `tests/test_store_no_oss_leak.py` enforces this by scanning a real package.

The editions differ in more than the license — **what actually goes into a package differs too**. The
authoritative source is `INCLUDE` (open-source) plus the `--store` trimming logic (`STORE_EXCLUDE` /
`STORE_ADD` / `STORE_RENAME`) in `package-agent.py`, mirrored item-for-item by `package-agent.ps1`
(see `tests/test_package_agent.py`):

- **Open-source** packages the top-level items of `INCLUDE`: `pyproject.toml`, `requirements.txt`,
  `requirements-dev.txt`, `README.md` / `README.en.md`, `SKILL.md`, `docs/`, `runbook/`, `LICENSE`,
  `DISCLAIMER.md`, `bootstrap.py` / `bootstrap.ps1` / `bootstrap.sh`, `install-agent.ps1`,
  `start_server.py`, `run_http.py`, `mcp_call.py`, `.vscode/`, `scry_mcp_gen/`, `tests/`.
- **Store** takes that list and **removes**: `tests/` (the whole test suite), `pyproject.toml`,
  `requirements-dev.txt`, `.vscode/`, `bootstrap.sh`, `install-agent.ps1`, and
  `LICENSE` / `README.md` / `README.en.md`; it **adds** `LICENSE-STORE`, `README-STORE.md` and
  `README-STORE.en.md`, which are **renamed inside the package** to `LICENSE` / `README.md` /
  `README.en.md` (a store package carries exactly one license and one README, and they must be the
  store ones).
- **Neither** distribution contains `package-agent.py` / `package-agent.ps1` (the packaging scripts
  themselves), `.gitattributes`, `README-STORE*.md`, `LICENSE-STORE` (open-source side) or this file —
  they are not in `INCLUDE`, so they are repository-only files, not something the store edition
  specifically trimmed.
- **What this means in practice**: the store package has **no `tests/`**, no test dependencies
  (`requirements-dev.txt`) and no packaging metadata (`pyproject.toml`). So **to run the tests from a
  package, use the open-source edition** (or work from the repository source); the store package only
  ships what is needed at runtime.
- **License and disclaimer files**: `DISCLAIMER.md` is **bundled in both editions** (it states no
  license terms, so it holds for both). The license file differs: the open-source package carries the
  repository's root `LICENSE` (non-commercial), while the store package carries exactly one `LICENSE`
  (whose content is `LICENSE-STORE`).

### Keeping the two in step

The code (`scry_mcp_gen/`) being **byte-identical apart from the license file** is a hard requirement:

```bash
# Compare blob hashes on each side; do not compare working-tree bytes (line endings will mislead you)
git ls-tree -r HEAD -- scry_mcp_gen/
```

The documentation, by contrast, is **separate**: the open-source edition uses `README.md` /
`README.en.md`, the store edition uses `README-STORE.md` / `README-STORE.en.md`. `docs/reference.md` is
shared by both, so it **must not** contain a repository address, a packaging manifest, or any mention
that another edition exists (`tests/test_store_no_oss_leak.py` scans for this). Content like that
belongs in this file — which does not ship.

---

## 3. Packaging

```bash
# Open-source (skill import package)
python package-agent.py
# Store edition
python package-agent.py --store

# Windows equivalents: package-agent.ps1 / package-agent.ps1 -Store
```

`scry-mcp-gen-agent.zip` is built by `package-agent.py` (cross-platform) or `package-agent.ps1`
(Windows) — the two scripts have identical manifests and identical output, so either will do; the
contents match the skill folder. **Official packages are attached to GitHub Releases** (from `v0.1.0`
onward, each tag carries its own zip), so users can just download one instead of pulling the
repository and packaging it themselves.

> Both licenses are **self-authored usage-boundary statements and have not been reviewed by a lawyer** —
> obtain legal review before relying on either as the sole legal basis for a specific deployment.
> Please also read the disclaimer (scope of use, credential handling warning, no warranty, limitation of
> liability) — **both editions' packages bundle `DISCLAIMER.md`**, and the repository root carries the
> same file.

---

## 4. Project structure

```
web-api-extractor/
├─ SKILL.md                     # Agent runbook index (follow step by step)
├─ README.md                    # Human entry point (open-source edition)
├─ README-STORE.md              # Same, store edition (renamed to README.md inside the package)
├─ README.en.md / README-STORE.en.md
├─ PACKAGING.md                 # This file (maintainer docs, ships with no package)
├─ docs/reference.md            # Technical reference shipped with packages (shared, no repo pointers)
├─ runbook/                     # SKILL's per-step modules, loaded on demand
│                               #   00 env / 01 auth / 02 capture / 03 analyze / 04 crypto
│                               #   05 generate / 06 iterate / 90 reference / 99 troubleshooting
├─ bootstrap.py / .ps1 / .sh    # Environment bootstrap (pure-Python immune to restricted envs; .sh unsupported, unverified)
├─ start_server.py              # The recommended way to start the HTTP service (escapes the shell job object)
├─ run_http.py                  # Equivalent HTTP launcher (do not run it as a background task)
├─ mcp_call.py                  # MCP tool driver (@file / stdin arguments, 404 self-healing)
├─ install-agent.ps1            # Install deps + Chromium (for agent import)
├─ package-agent.py / .ps1      # Package into a distributable zip (identical manifests, identical output)
├─ pyproject.toml               # Packaging metadata (incl. license / readme / classifiers)
├─ requirements.txt             # Runtime dependencies (fastmcp / httpx / playwright)
├─ requirements-dev.txt         # Test dependencies (-r requirements.txt + pytest / pytest-asyncio)
├─ LICENSE / LICENSE-STORE      # Custom terms of use (not SPDX / OSI): open-source / store
├─ .gitignore / .gitattributes  # Ignore runtime artifacts; pin line endings (*.sh must be LF)
├─ .vscode/mcp.json             # Registers this server as a stdio MCP server (no absolute local paths)
├─ tests/                       # pytest suite (38 files)
└─ scry_mcp_gen/
   ├─ __main__.py               # CLI: doctor | serve-http | (default) stdio
   ├─ server.py                 # MCP server and tool registration
   ├─ auth.py                   # Login flows (user-confirmed completion, never automatic) + measured login mode on disk
   ├─ capture.py                # Playwright/CDP capture
   ├─ analyzer.py               # Parameterization / noise tagging / login detection / "can we POST?" two-layer verdict
   ├─ crypto_analyzer.py        # Encryption detection + PEM public-key extraction
   ├─ generator.py              # Registry-driven project generation (incl. interactive-login artifacts)
   ├─ project.py                # Registry single source of truth (diff / merge / export)
   ├─ redaction.py / bodies.py  # Redaction (preserving shape metadata) / request body parsing
   ├─ dialog.py                 # Native OS confirmation dialog (shared by login and capture)
   ├─ doctor.py                 # Environment self-check
   ├─ domain.py / probe.py / proxy_env.py
   ├─ audit.py / storage.py / config.py
   └─ site_profiles/            # Site profiles (optional, none ship in the repository)
```

---

## 5. Tests

```bash
# pytest config lives in pyproject.toml (testpaths + asyncio_mode=auto)
uv run --with pytest --with pytest-asyncio --with httpx --with playwright \
       --with fastmcp python -m pytest tests -q

# Or if the environment is already set up:
python -m pytest tests -q
```

Three things to note:

- **Test and runtime dependencies are split**: `requirements.txt` holds only runtime dependencies
  (`fastmcp` / `httpx` / `playwright`), while `pytest` / `pytest-asyncio` live in
  `requirements-dev.txt` (i.e. `pyproject.toml`'s `[project.optional-dependencies].test`). **The
  bootstrap installs runtime dependencies only by default**; to run the tests, opt in explicitly with
  `python bootstrap.py --with-tests`, `pip install -r requirements-dev.txt`, or
  `pip install -e ".[test]"`. Without a test runner, `asyncio_mode=auto` is silently ignored and every
  async test fails.
- The suite is unit-level and **never launches a browser**.
- **What the tests do not cover** (stated plainly — do not read "untested" as "fine"):
  - the **session and capture** tools in `server.py` (probe / login / capture / analyze /
    update_endpoint / extract_crypto) still have no tests — they need a real browser; **the 4
    project tools and doctor are covered** (`tests/test_iterate_tools.py`, `tests/test_doctor.py`,
    which point the data directory at a temporary directory before importing `server.py` so the
    local `~/.scry` is untouched);
  - the iteration chain (`runbook/06-iterate.md`), user-mode isolation, and `locked` rejection are
    covered by `tests/test_iterate_chain.py` (previously uncovered; added in this round);
  - `test_proxy_env.py` has one POSIX-only case that is skipped on Windows (expected).
  - the capture browser's **proxy mode** (`auto` by default: start direct, fall back to the system
    proxy once on a proxy-shaped failure / explicit `direct` and `system` do not fall back / the
    diagnosis when both fail / a clear error for an invalid setting) is covered by
    `tests/test_capture_proxy.py`: launch arguments and the fallback sequence are read off a **fake
    playwright**, so the suite still **never launches a browser**.
  - `mcp_call.py`'s **output encoding** is covered by `tests/test_mcp_call_driver.py`: the non-TTY
    case runs a real subprocess pipe and asserts **strict UTF-8 decoding**; the real-console cases
    call `AllocConsole()` to create a hidden real console, point a child process's stdout at
    `CONOUT$`, run the actual output path, and read back the **characters in the screen buffer**
    (asserting what a human would see is Chinese). Those skip on non-Windows.
