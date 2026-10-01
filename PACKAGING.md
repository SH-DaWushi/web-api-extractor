# 打包与项目结构

本文件面向**维护者与二次开发者**：仓库怎么组织、怎么打包、两个发行版本差在哪。

它**不随任何分发包发出**（不在 `package-agent.py` 的 `INCLUDE` 里）—— 因为它描述的正是
仓库自身的组织方式，而商店版必须在文档上自足且不引出开源版。使用者看 `README.md`，
随包分发的技术语义看 `docs/reference.md`。

---

## 一、从源码取用

**本项目未发布到 PyPI，必须先从源码取用。**

```bash
git clone https://github.com/SH-DaWushi/web-api-extractor.git
cd web-api-extractor
```

作为 Python 库可编辑安装：

```bash
pip install -e .
python -m playwright install chromium
```

此时入口为 `scry-mcp-gen`（stdio，见 `pyproject.toml` 的 `[project.scripts]`）与
`python -m scry_mcp_gen serve-http`；仓库内的驱动脚本（`mcp_call.py`、`start_server.py`
等）不在发行包里。运行时依赖只有 `fastmcp / httpx / playwright`；测试运行器（`pytest` /
`pytest-asyncio`）是**可选**的，`pip install -e .` **不会**装，要装用
`pip install -e ".[test]"`（等价于 `pip install -r requirements-dev.txt`），否则
`asyncio_mode=auto` 会被静默忽略（详见 `docs/reference.md` 的「测试」）。

---

## 二、发行版本与许可

本项目有**两个发行版本**，条款不同 —— **以你手上那份包里的 `LICENSE` 为准**：

| 版本 | 载体 | 适用许可 |
|---|---|---|
| 开源版 | 本仓库、GitHub Releases 的技能导入包 | 仓库根目录的 `LICENSE`（自拟**非商用**条款） |
| 商店版 | 技能商店分发的包 | 包内 `LICENSE`，内容即 `LICENSE-STORE`（自拟**商店分发许可**） |

商店版授予商店收录与最终用户使用（含内部业务用途），保留署名与免责声明，禁止转售、转出该商店、再许可与分发修改版（自用修改可以）。

**两个版本是相互独立的**：商店版不介绍开源版，也不给出任何指向本仓库的线索
（README、授权文本、技术参考全部各用各的）。这条由 `tests/test_store_no_oss_leak.py`
拿真包扫一遍强制保证。

两个版本不止许可不同，**打进包里的内容也不同**。清单的权威来源是 `package-agent.py` 的 `INCLUDE`（开源版）与 `--store` 的裁剪逻辑（`STORE_EXCLUDE` / `STORE_ADD` / `STORE_RENAME`；与 `package-agent.ps1` 逐项一致，见 `tests/test_package_agent.py`）：

- **开源版**打包 `INCLUDE` 的顶层项：`pyproject.toml`、`requirements.txt`、`requirements-dev.txt`、`README.md` / `README.en.md`、`SKILL.md`、`docs/`、`runbook/`、`LICENSE`、`DISCLAIMER.md`、`bootstrap.py` / `bootstrap.ps1` / `bootstrap.sh`、`install-agent.ps1`、`start_server.py`、`run_http.py`、`mcp_call.py`、`.vscode/`、`scry_mcp_gen/`、`tests/`。
- **商店版**在开源清单上**去掉**：`tests/`（整个测试套件）、`pyproject.toml`、`requirements-dev.txt`、`.vscode/`、`bootstrap.sh`、`install-agent.ps1`，以及 `LICENSE` / `README.md` / `README.en.md`；**新增** `LICENSE-STORE`、`README-STORE.md`、`README-STORE.en.md`，并在包内**改名为** `LICENSE` / `README.md` / `README.en.md` —— 商店包只能带一份授权、一份 README，且必须是商店版那几份。
- 两个分发包**都不包含** `package-agent.py` / `package-agent.ps1`（打包脚本本身）、`.gitattributes`、`README-STORE*.md`、`LICENSE-STORE`（开源版）与本文件 —— 它们不在 `INCLUDE` 里，只是仓库文件，**不是**被商店版单独裁掉的。
- **对使用者的实际影响**：商店包**没有 `tests/`**，也没有测试依赖（`requirements-dev.txt`）与打包元数据（`pyproject.toml`）。因此**想在包里跑测试请用开源版**（或直接用仓库源码）；商店包只提供运行所需文件。
- **授权与免责文件**：`DISCLAIMER.md` **两个版本都内置**（它不含任何许可条款，对两版都成立）。授权文件不同：开源包内是仓库根的 `LICENSE`（非商用），商店包内只有一份 `LICENSE`（内容即 `LICENSE-STORE`）。

### 保持两版一致

代码（`scry_mcp_gen/`）**除授权文件外逐字节相同**是硬要求：

```bash
# 两边分别比 blob 哈希；不要比工作区字节（行尾会骗人）
git ls-tree -r HEAD -- scry_mcp_gen/
```

文档则是**各自独立**的：开源版用 `README.md` / `README.en.md`，商店版用
`README-STORE.md` / `README-STORE.en.md`；`docs/reference.md` 两版共享，因此它**不得**
出现仓库地址、打包清单或「另有一个版本」这类说法（`tests/test_store_no_oss_leak.py` 会扫）。
需要写这类内容时，写进本文件 —— 本文件不随包分发。

---

## 三、打包

```bash
# 开源版（技能导入包）
python package-agent.py
# 商店版
python package-agent.py --store

# Windows 等价：package-agent.ps1 / package-agent.ps1 -Store
```

`scry-mcp-gen-agent.zip` 由 `package-agent.py`（跨平台）或 `package-agent.ps1`（Windows）
打出 —— 两份脚本的清单与产物一致，用哪份都行；内容与技能文件夹相同。
**官方包挂在 GitHub Releases**（`v0.1.0` 起，每个 tag 挂一份对应的 zip），使用者直接下载即可，
不必自己拉仓库再打包。

> 两份许可都是**自拟的使用边界声明，未经律师审阅**；需要正式法律约束前请先做法务审核。
> 请一并阅读免责声明（适用范围、凭据处理警告、无担保与责任限制）—— 两个版本的分发包都内置
> `DISCLAIMER.md`，仓库根目录也有同一份。

---

## 四、项目结构

```
web-api-extractor/
├─ SKILL.md                     # Agent 操作手册主索引（按步骤照做）
├─ README.md                    # 人类入口：这是什么、怎么用起来（开源版）
├─ README-STORE.md              # 同上，商店版（包内改名为 README.md）
├─ README.en.md / README-STORE.en.md
├─ PACKAGING.md                 # 本文件（维护者文档，不随包分发）
├─ docs/reference.md            # 随包分发的技术参考（两版共享，不得含仓库线索）
├─ runbook/                     # SKILL 的分步模块，按需加载
│                               #   00 环境 / 01 登录 / 02 抓包 / 03 分析 / 04 加密
│                               #   05 生成 / 06 迭代 / 90 参考 / 99 排错
├─ bootstrap.py / .ps1 / .sh    # 环境引导（纯 Python 版免疫受限环境；.sh 不受支持、未验证）
├─ start_server.py              # 启动 HTTP 服务的推荐方式（脱离 shell job object）
├─ run_http.py                  # 等价的 HTTP 启动器（勿用后台任务方式直接跑）
├─ mcp_call.py                  # MCP 工具驱动（@file / stdin 传参，404 自愈）
├─ install-agent.ps1            # 装依赖 + Chromium（供 Agent 导入）
├─ package-agent.py / .ps1      # 打包成可分发的 zip（清单一致，产物相同）
├─ pyproject.toml               # 打包元数据（含 license / readme / classifiers）
├─ requirements.txt             # 运行依赖（fastmcp / httpx / playwright）
├─ requirements-dev.txt         # 测试依赖（-r requirements.txt + pytest / pytest-asyncio）
├─ LICENSE / LICENSE-STORE      # 自拟使用条款（非 SPDX / OSI）：开源版 / 商店版
├─ .gitignore / .gitattributes  # 忽略运行产物；锁定行尾（*.sh 必须为 LF）
├─ .vscode/mcp.json             # 把本服务注册为 stdio MCP（无本机绝对路径）
├─ tests/                       # pytest 套件（38 个文件）
└─ scry_mcp_gen/
   ├─ __main__.py               # CLI：doctor | serve-http |（默认）stdio
   ├─ server.py                 # MCP Server 与工具注册
   ├─ auth.py                   # 登录流程（用户确认完成，不自动判定）+ 实测登录方式落盘
   ├─ capture.py                # Playwright/CDP 抓包
   ├─ analyzer.py               # 参数化 / 噪音标记 / 登录识别 / 「能不能构造请求登录」两层判据
   ├─ crypto_analyzer.py        # 加密检测 + PEM 公钥提取
   ├─ generator.py              # registry 驱动的项目生成（含交互式登录产物）
   ├─ project.py                # registry 唯一事实源（diff / merge / export）
   ├─ redaction.py / bodies.py  # 脱敏（保留形态元数据）/ 请求体解析
   ├─ dialog.py                 # 系统原生确认对话框（登录与抓包共用一份实现）
   ├─ doctor.py                 # 环境自检
   ├─ domain.py / probe.py / proxy_env.py
   ├─ audit.py / storage.py / config.py
   └─ site_profiles/            # 站点档案（可选加载，仓库不内置）
```

---

## 五、测试

```bash
# pytest 配置在 pyproject.toml（testpaths + asyncio_mode=auto）
uv run --with pytest --with pytest-asyncio --with httpx --with playwright \
       --with fastmcp python -m pytest tests -q

# 装了环境的话直接：
python -m pytest tests -q
```

注意三点：

- **测试依赖与运行依赖已分离**：`requirements.txt` 只有运行时依赖（`fastmcp` / `httpx` /
  `playwright`），`pytest` / `pytest-asyncio` 移到 `requirements-dev.txt`（也就是
  `pyproject.toml` 的 `[project.optional-dependencies].test`）。**bootstrap 默认只装运行依赖**，
  要跑测试需显式开启：`python bootstrap.py --with-tests`、或 `pip install -r requirements-dev.txt`、
  或 `pip install -e ".[test]"`。缺了测试运行器时 `asyncio_mode=auto` 会被静默忽略、异步用例全部失败。
- 套件是单元级的，**不会启动浏览器**。
- **测试没覆盖什么**（如实说明，别把「没测到」当成「没问题」）：
  - `server.py` 的**会话与抓包类**工具（probe / login / capture / analyze / update_endpoint /
    extract_crypto）仍无测试 —— 它们要真实浏览器；**项目类 4 个工具与 doctor 已覆盖**
    （`tests/test_iterate_tools.py`、`tests/test_doctor.py`，导入 `server.py` 前把数据目录
    指到临时目录，不碰本机 `~/.scry`）；
  - 迭代链路（`runbook/06-iterate.md`）、用户态隔离、`locked` 拒绝由
    `tests/test_iterate_chain.py` 覆盖（此前无覆盖，本轮补上）；
  - `test_proxy_env.py` 有一条 POSIX-only 用例，在 Windows 上会被 skip（属预期）。
  - 抓包浏览器的**代理模式**（默认 `auto`：先直连、代理类失败自动回退系统代理 / 显式
    `direct`、`system` 不回退 / 两次都失败的诊断 / 非法设置值报错）由
    `tests/test_capture_proxy.py` 覆盖：启动参数与回退过程用**假 playwright** 截取，
    **不真的开浏览器**（套件仍是单元级的）。
  - `mcp_call.py` 的**输出编码**由 `tests/test_mcp_call_driver.py` 覆盖：非 TTY 走
    子进程管道做**严格 UTF-8 解码**；真控制台那几条会 `AllocConsole()` 建一个隐藏的
    真控制台、把 `CONOUT$` 当子进程 stdout 跑一遍输出路径、再读回**屏幕缓冲区里的字符**
    （断言「人眼看到的是中文」）。这一条在非 Windows 上 skip。
