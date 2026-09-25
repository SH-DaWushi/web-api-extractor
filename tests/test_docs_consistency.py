# -*- coding: utf-8 -*-
"""文档不得与代码漂移。

README / docs/reference.md / runbook 是本仓库唯一的对外说明，但曾多次出现与实现
不符的陈述，且每次都是人工偶然发现：

- reference 教用户 `pip install web-api-extractor` —— 该发行版从未发布到 PyPI；
- reference 的 clone 地址指向已改名的旧库，而 README 通篇没有任何仓库地址；
- README 承诺「密码不由它保存或转发」，而 `http_login` 会把账号密码明文写进
  `auth_states/*.json`（README 与 reference 互相矛盾）；
- runbook 让 Agent 按 `auth_mode == "form"` 且 `confidence >= 0.8` 分支，而 `probe.py`
  只返回 none / interactive、confidence 上限 0.75 —— 该判据在任何站点上都不成立；
- 生成的子项目 README 同时说 token「不写入磁盘」和「DPAPI 加密存入 token_cache.bin」；
- README 让使用者自己 `git clone`、跑 `package-agent.ps1`、再 `bootstrap.py` / `start_server.py` ——
  这些都是 Agent 或技术同事的事，使用者只需要把技能拖进 Agent。

这些错法的共同点是：**把会随代码变化的结论写死在文档里**。因此本文件只断言
**事实关系**（数字相等、集合包含、链接等于仓库、已证伪的原话不存在），
不断言措辞、章节顺序或表格列数 —— 正常改写文案不应让测试变红。
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_URL = "https://github.com/SH-DaWushi/web-api-extractor"

README = (ROOT / "README.md").read_text(encoding="utf-8")
REFERENCE = (ROOT / "docs" / "reference.md").read_text(encoding="utf-8")
SKILL_MD = (ROOT / "SKILL.md").read_text(encoding="utf-8")
RUNBOOK_AUTH = (ROOT / "runbook" / "01-authentication.md").read_text(encoding="utf-8")
RUNBOOK_ITERATE = (ROOT / "runbook" / "06-iterate.md").read_text(encoding="utf-8")
SERVER_SRC = (ROOT / "webapi_extractor" / "server.py").read_text(encoding="utf-8")
PROBE_SRC = (ROOT / "webapi_extractor" / "probe.py").read_text(encoding="utf-8")


class TestInstallInstructions:
    """安装路径必须真实存在。"""

    def test_repo_url_present(self):
        """README 曾经连一个仓库地址都没有，唯一那个还是旧库的。"""
        assert REPO_URL in README
        assert REPO_URL in REFERENCE

    def test_old_repo_identifier_gone(self):
        for text in (README, REFERENCE):
            assert "shdawushi-dotcom" not in text
            assert "WebAPIExtractor.git" not in text

    def test_no_unpublished_pip_install(self):
        """该发行版不在 PyPI 上，不能教用户这么装（`-`/`_` 两种写法都挡）。"""
        pattern = re.compile(r"pip\s+install\s+web[-_]?api[-_]?extractor\b")
        assert not pattern.search(README)
        assert not pattern.search(REFERENCE)

    def test_source_install_documented(self):
        assert "pip install -e ." in REFERENCE

    def test_readme_says_where_to_get_the_zip(self):
        """README 让使用者「把 zip 拖进技能页」，就必须给出 zip 的下载落点。

        之前只说「（或 zip）」，却没有任何渠道能拿到它 —— 对不懂命令的读者是死路。
        """
        if "zip" in README:
            assert re.search(r"releases/(latest|download)", README), \
                "README 提到了 zip，却没写它从哪下载"


class TestSecurityClaims:
    """README 曾做过与实现相反的承诺，禁止回归。"""

    REFUTED = ("不由它保存", "一律被抹成")

    def test_refuted_claims_absent(self):
        for phrase in self.REFUTED:
            assert phrase not in README, f"已核实为假的原话不得再出现：{phrase}"

    def test_admits_plaintext_auth_state(self):
        """`http_login` 会把账号密码明文写进 auth_states，README 必须承认。"""
        assert "auth_states" in README
        assert "明文" in README

    def test_states_redaction_scope(self):
        """URL 与响应体都不脱敏，必须写明。"""
        assert re.search(r"(URL|响应体).{0,20}不脱敏", README)

    def test_skill_md_limits_redaction_claim(self):
        """SKILL.md 不得把脱敏说成无条件的（只有 JSON / 表单体走脱敏）。"""
        for line in SKILL_MD.splitlines():
            if "脱敏" in line and "必然" in line:
                assert "JSON" in line or "表单" in line, line


class TestToolCount:
    """文档里的工具数必须等于 server.py 真实注册数（不硬编码，加工具时自动跟随）。"""

    def _actual(self) -> int:
        return len(re.findall(r"@mcp\.tool\(\)", SERVER_SRC))

    def _claimed(self) -> list[int]:
        both = README + REFERENCE
        found = [int(n) for n in re.findall(r"工具清单（(\d+) 个）", both)]
        found += [int(n) for n in re.findall(r"(\d+) 个工具的完整清单", both)]
        return found

    def test_claims_match_registration(self):
        actual = self._actual()
        claims = self._claimed()
        assert actual > 0, "未能从 server.py 数出工具注册，测试本身失效"
        assert claims, "文档必须声明工具总数"
        assert all(c == actual for c in claims), f"文档声称 {claims}，实际注册 {actual}"


class TestFileInventory:
    """目录树注释里的文件数必须等于磁盘实际数 —— 这类数字最容易漏改。"""

    def test_tests_dir_count_matches_disk(self):
        claimed = re.findall(r"tests/\s+#\s*pytest 套件（(\d+) 个文件）", REFERENCE)
        actual = len(list((ROOT / "tests").glob("*.py")))
        assert claimed, "reference 的目录树里找不到 tests/ 的文件数声明"
        assert all(int(c) == actual for c in claimed), f"reference 声称 {claimed}，实际 {actual}"

    def test_packaging_scripts_both_documented(self):
        """加了 .py 版打包脚本后，reference 不能只讲 .ps1（否则非 Windows 找不到出路）。"""
        for name in ("package-agent.py", "package-agent.ps1"):
            assert name in REFERENCE, f"reference 未提到 {name}"


class TestCoverageClaimsMatchTests:
    """「某某没有测试」是会随代码变化的结论 —— 补了测试就必须改文档。

    这类句子最容易骗人：读者据此以为不必核对，实际早就有测试守着了（反之更糟：
    以为测过了，其实没有）。判据只看 `tests/` 里是否真的存在对应覆盖，不锁措辞。
    """

    TESTS = ROOT / "tests"

    def _imports(self, module: str) -> bool:
        pattern = (rf"(?:from|import)\s+webapi_extractor\.{module}\b"
                   rf'|import_module\(["\']webapi_extractor\.{module}["\']\)')
        return any(re.search(pattern, path.read_text(encoding="utf-8"))
                   for path in self.TESTS.glob("*.py"))

    def test_server_tool_layer_claim_matches_reality(self):
        if self._imports("server"):
            assert "工具层本身无测试" not in REFERENCE
            assert "从不 import" not in REFERENCE

    def test_iterate_chain_claim_matches_reality(self):
        if (self.TESTS / "test_iterate_chain.py").exists():
            for text in (REFERENCE, RUNBOOK_ITERATE):
                assert "没有测试覆盖" not in text
                assert "只有实现、没有验证" not in text

    def test_documented_untested_modules_really_are_untested(self):
        """reference 点名的「无测试」模块，不能其实已经被 import 了。"""
        for module in re.findall(r"`(\w+)\.py`(?:`\s*/\s*`\w+`)*\s*(?:均)?无测试", REFERENCE):
            assert not self._imports(module), f"reference 说 {module}.py 无测试，实际有测试"


class TestProbeCriteriaInRunbook:
    """runbook 引用的 probe 判据必须真的可达。"""

    def _auth_modes(self) -> set[str]:
        return set(re.findall(r'auth_mode"\]\s*=\s*"(\w+)"', PROBE_SRC)) | \
               set(re.findall(r'"auth_mode":\s*"(\w+)"', PROBE_SRC))

    def _confidence_ceiling(self) -> float:
        values: list[float] = []
        for line in PROBE_SRC.splitlines():
            if "confidence" in line:
                values += [float(v) for v in re.findall(r"(\d+\.\d+)", line)]
        return max(values) if values else 0.0

    def test_referenced_auth_mode_exists(self):
        modes = self._auth_modes()
        assert modes, "未能从 probe.py 提取 auth_mode 取值，测试本身失效"
        for mode in re.findall(r'auth_mode\s*==\s*"(\w+)"', RUNBOOK_AUTH):
            assert mode in modes, f"runbook 引用了 probe 不可能返回的 auth_mode: {mode}"

    def test_confidence_threshold_reachable(self):
        ceiling = self._confidence_ceiling()
        assert ceiling > 0, "未能从 probe.py 提取 confidence，测试本身失效"
        for threshold in re.findall(r"confidence\s*>=\s*([0-9.]+)", RUNBOOK_AUTH):
            assert float(threshold) <= ceiling, \
                f"runbook 的门槛 {threshold} 超过实现上限 {ceiling}，该分支不可达"


class TestGeneratedReadmeSelfConsistent:
    """生成物自身不得矛盾（token 的持久化说法必须唯一）。"""

    HOST = "oa.example.com"

    def _readme(self) -> str:
        from webapi_extractor.generator import render_server

        registry = {
            "site_name": "portal",
            "registry_version": 1,
            "hosts": {self.HOST: {"scheme": None,
                                  "cookie_names": ["JSESSIONID", "loginToken"]}},
            "endpoints": [{
                "tool_name": "get_api_system_status",
                "method": "GET",
                "host": self.HOST,
                "path": "/api/system/status",
                "auth_required": True,
                "status": "active",
            }],
            "auth_login": {
                "method": "POST",
                "host": self.HOST,
                "path": "/api/login",
                "account_field": "username",
                "password_field": "password",
                "token_path": ["data", "token"],
                "query_params": {},
            },
        }
        return render_server(registry)["README.md"]

    def test_login_section_rendered(self):
        """先确保守卫非空转：不渲染「登录」节的话，下面那条断言毫无意义。"""
        assert "## 登录" in self._readme()

    def test_token_persistence_not_contradictory(self):
        """曾同时写「只保存在服务进程内存中，不写入磁盘」与「DPAPI 加密存入 token_cache.bin」。"""
        readme = self._readme()
        if "DPAPI" in readme or "token_cache.bin" in readme:
            assert "不写入磁盘" not in readme
            assert "仅存进程内存" not in readme


class TestDocsMatchCodeInventory:
    """文档里的模块/档案清单必须与代码一致。"""

    def test_dead_module_not_documented(self):
        """login_detector.py 是死代码（全仓无调用点），不该出现在项目结构里。"""
        assert "login_detector" not in REFERENCE

    def test_no_site_profiles_bundled(self):
        """文档称「仓库不内置任何档案」，这条断言的是文档claim本身成立。

        （顺带与 tests/test_param_alias.py 同向加固：真加了档案就得同时改文档。）
        """
        from webapi_extractor.site_profiles import _REGISTRY
        assert _REGISTRY == {}


class TestReadmeStaysUserFacing:
    """README 面向使用者，不得让使用者自己装库 / 起服务 / 跑命令。

    使用者的安装动作只有两个：把技能拖进「技能 / Skill」设置页，或拖进对话让 Agent 装。
    `bootstrap.py`、`start_server.py`、`mcp_call.py`、`pip install` 这些属于 Agent 内部流程
    或技术人员范畴，只能在 docs/reference.md 里出现（README 可以链接过去）。
    """

    OPERATOR_ONLY = ("bootstrap.py", "start_server.py", "mcp_call.py", "run_http.py",
                     "pip install", "uv run", "pytest", "git clone")

    def test_no_operator_commands_in_readme(self):
        for token in self.OPERATOR_ONLY:
            assert token not in README, \
                f"README 是使用者入口，不应出现运维/开发命令：{token}（应放 docs/reference.md）"

    def test_readme_tells_how_to_install_skill(self):
        """必须写清使用者实际要做的动作，而不是让他去找命令。"""
        assert "技能" in README
        assert "拖" in README

    def test_readme_links_reference(self):
        """README 必须把读者导向技术文档（原先只有一处，还埋在小节末尾）。"""
        assert "docs/reference.md" in README
        assert f"{REPO_URL}/blob/main/docs/reference.md" in README
