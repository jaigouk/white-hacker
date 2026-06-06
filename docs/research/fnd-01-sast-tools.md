# research:sast-tools

> Source: workflow `white-hacker-research` (wycjclbk6), agent `research:sast-tools`

## 2026 Static Analysis / SAST Landscape for Multi-Language Projects

This survey covers SAST engines and language-native security linters usable **locally and in CI** as of mid-2026, with explicit attention to OSS-vs-paid status, install/run commands, language coverage, and whether a Claude Code / MCP integration exists. Version numbers and tool names are verified against current 2026 pages.

### Cross-engine SAST tools

| Tool | OSS / Paid | Install / Run | Languages | MCP / Claude Code (2026) |
|---|---|---|---|---|
| **Semgrep CE** | OSS core (LGPL-2.1) + paid Pro | `pip install semgrep` / `brew install semgrep`; `semgrep scan --config auto` | 30+ | Yes — official plugin bundles MCP + hooks + skills |
| **Opengrep** | Fully OSS (LGPL-2.1) | `curl ... | bash` installer or Docker; `opengrep scan` | 30+ (incl. VB.NET) | Indirect (Semgrep-compatible rules; no official plugin) |
| **CodeQL** | Source-available; free for OSS/public/academic only | `gh extension` / CodeQL CLI bundle; `codeql database create` + `analyze` | C/C++, C#, Go, Java/Kotlin, JS/TS, Python, Ruby, Swift, Rust | Via GitHub MCP server / code-scanning APIs |
| **Snyk Code** | Paid (free tier: 100 SAST tests/mo, unlimited for public repos) | `npx -y snyk@latest mcp configure --tool=claude-cli` | 16 incl. JS/TS, Py, Java, Go, C#, C/C++, PHP, Ruby, Swift, Kotlin, Scala, Rust | Yes — official Snyk MCP server (Snyk Studio) |
| **SonarQube** | Community Build OSS (LGPL-3.0) + paid editions/Cloud | Docker `sonarqube`; scanner CLI. Cloud free <50k LOC | 30+ | Yes — official SonarQube MCP server (25 tools) |

#### Semgrep & Opengrep
**Semgrep Community Edition** remains the most popular pattern-based SAST engine. CE is the free LGPL-2.1 CLI with ~3,000 community rules ([semgrep-rules](https://github.com/semgrep/semgrep-rules), Semgrep Rules License), single-file analysis, and CI/CD support. The paid platform adds cross-file/cross-function dataflow ("Pro rules"), a managed dashboard, and in 2026 a beta **AI-powered detection** for business-logic flaws (IDOR/broken authz). Pricing: free CE, **Team at $35/contributor/mo**, custom Enterprise ([pricing](https://semgrep.dev/pricing/)). Strengths: fast, easy custom rules (YAML pattern syntax), huge ruleset, polyglot. Weakness: deep interprocedural/taint analysis is gated behind the paid tier.

**Opengrep** is the 2025 community fork created after Semgrep relicensed parts of CE; it is governed by a 10+ vendor consortium (Aikido and others) so features can't be re-gated. It **restores to OSS** the features Semgrep moved out of CE — intrafile/interprocedural taint, fingerprinting, Windows support — under LGPL-2.1, and keeps Semgrep rule-format compatibility ([opengrep/opengrep](https://github.com/opengrep/opengrep), [appsecsanta review](https://appsecsanta.com/opengrep)). Recent 2026 releases: **v1.21.0 (May 11 2026)** exposed taint-intrafile over LSP; **v1.20.0 (Apr 21 2026)** added Python `match/case` (PEP 634) parsing. Strength: free taint analysis + VB.NET support. Weakness: no first-party Claude Code plugin or managed platform; you wire it in via CLI/CI.

#### CodeQL
GitHub's semantic, query-based engine. **Split licensing**: the CLI and standard query packs are free for analysis of **open-source/public repos and academic research only**; private-repo scanning requires **GitHub Advanced Security (GHAS)**, licensed per active committer in Enterprise plans ([codeql.github.com](https://codeql.github.com/), [appsecsanta](https://appsecsanta.com/github-codeql)). Languages: C/C++, C#, Go, Java/Kotlin, JS/TS, Python, Ruby, Swift, Rust. Strength: deepest dataflow/taint of any tool here, excellent for finding real injection chains; native GitHub code-scanning. Weakness: license restricts free local use on private code; slow (must build a database); steep query language. Claude Code access is indirect via the GitHub MCP server / code-scanning alerts API rather than a dedicated CodeQL MCP.

#### Snyk Code
Commercial AI-assisted SAST. Free plan allows 100 SAST tests/mo (unlimited for public/OSS), with **Team at $25/dev/mo** and custom Enterprise ([snyk.io/plans](https://snyk.io/plans/)). 16 languages incl. Apex, Dart, Elixir, Scala. Strength: fast, low-false-positive AI engine with autofix, strong IDE story, and a **mature official MCP server** (`npx -y snyk@latest mcp configure --tool=claude-cli`) that lets Claude Code scan and auto-fix generated code; at RSAC 2026 Snyk added **Agent Scan** (MCP-server governance) and **Agent Guard**. Weakness: free local SAST is test-capped on private code; full value requires a paid plan.

#### SonarQube / Sonar
**Community Build** (renamed from Community Edition) is OSS (LGPL-3.0), 20+ languages, but **lacks taint/SAST-grade injection analysis and branch analysis**. Real security (taint analysis) starts at Developer Edition (~$2,500/yr/100k LOC) or **SonarQube Cloud** (free <50k LOC, **Team ~EUR 30/mo**, [pricing](https://www.sonarsource.com/plans-and-pricing/)). 30+ languages incl. IaC (Terraform, Docker, K8s). Latest: **SonarQube Server 2026.2 (Mar 2026)**, 2026.1 LTA. Strength: best-in-class breadth (quality + security + IaC), and an **official SonarQube MCP server** (~25 tools, Docker-based, works with Claude Code/Cursor/Windsurf — [docs](https://docs.sonarsource.com/sonarqube-mcp-server/quickstart-guide/claude-code)). Weakness: the genuinely useful security tier is paid; heavier to self-host.

### Language-native linters with security rules

| Language | Tool(s) | OSS | Install / Run | Notes (2026) |
|---|---|---|---|---|
| **Go** | gosec, golangci-lint | Yes | `go install github.com/securego/gosec/v2/cmd/gosec@latest`; golangci-lint installer | gosec **v2.26.1** (May 1 2026) added a **taint analysis engine** (v2.23.0) + new checks G124/G708-G710; bundled in golangci-lint |
| **Python** | bandit, ruff (`S` rules) | Yes | `pip install bandit` → `bandit -r .`; ruff: `extend-select=["S"]` | Ruff's `S` rules port flake8-bandit, 10-100x faster; bandit still wins for Django/SQLAlchemy/PyTorch/HF patterns |
| **JS/TS** | eslint-plugin-security | Yes (MIT) | `npm i -D eslint-plugin-security`; `pluginSecurity.configs.recommended` | Editor-time baseline (eval, child_process, Buffer, bidi/trojan-source); pair with Semgrep in CI |
| **Java** | SpotBugs + Find Security Bugs, PMD | Yes | SpotBugs + FSB plugin via Maven/Gradle; PMD CLI | FSB adds 144 vuln types / 826+ API signatures across Spring/Struts/JSF (OWASP Top 10); SpotBugs needs compiled bytecode, PMD works on source |

**Go** — `gosec` is the de-facto Go security linter (AST + SSA, now with taint analysis as of 2026); usually run via **golangci-lint** which bundles gosec alongside style/bug linters ([securego/gosec](https://github.com/securego/gosec), [appsecsanta](https://appsecsanta.com/gosec)). Default for CI.

**Python** — **Ruff** has ported most of flake8-bandit under the `S` prefix; if you already run Ruff, enabling `extend-select=["S"]` gives free, near-instant security linting. **Bandit** is still recommended where framework-specific detectors matter (Django, raw SQLAlchemy, PyTorch, Hugging Face) since ~6 bandit rules have no Ruff equivalent ([pydevtools](https://pydevtools.com/handbook/how-to/how-to-enable-ruff-security-rules/), [ruff vs bandit](https://mcginniscommawill.com/posts/2026-02-10-ruff-bandit-vs-traditional/)).

**JS/TS** — `eslint-plugin-security` (maintained by eslint-community) provides cheap editor/CI pattern checks (eval, non-literal `exec`, `Buffer`, unicode bidi/trojan-source). It's regex-ish, not dataflow-aware, so the prevailing 2026 advice is **ESLint in editor + Semgrep/Opengrep in CI** ([github](https://github.com/eslint-community/eslint-plugin-security)).

**Java** — **SpotBugs + Find Security Bugs** (OWASP, GoSecure-supported) is the standard OSS combo; FSB adds 144 vuln categories over Spring/Struts/JSF. SpotBugs analyzes **compiled bytecode**, so it needs a build; pair with **PMD** (source-level style/complexity + some security rules) ([find-sec-bugs](https://github.com/find-sec-bugs/find-sec-bugs), [OWASP](https://owasp.org/www-project-find-security-bugs/)).

### Recommended minimal cross-language default set

For a generic white-hat review agent that must work across TS/Go/Python/Java and backend/frontend/AI repos, optimize for **OSS, zero-login, fast, polyglot, taint-capable**:

1. **Primary engine: Opengrep** (or Semgrep CE) — one binary covers all four languages with free taint analysis, Semgrep-compatible rules, and CI portability. Opengrep avoids the CE feature-gating; Semgrep CE is the choice if you want the official Claude Code plugin/MCP.
2. **Per-language fast linters as a second pass** (catch idioms the generic engine misses):
   - Go → `golangci-lint` (with `gosec` enabled, now taint-aware)
   - Python → `ruff` with `S` rules, plus `bandit` if framework-heavy/AI (PyTorch/HF) code is present
   - JS/TS → `eslint-plugin-security`
   - Java → `spotbugs` + `find-sec-bugs`
3. **Optional deep/managed layer**: CodeQL for public repos (free, deepest dataflow), or SonarQube Cloud / Snyk Code where the team already pays and wants an MCP-driven "vibe then verify" autofix loop in Claude Code.

This gives broad, free, local+CI coverage with one taint-capable polyglot engine plus thin native linters, and a clear paid escalation path with first-party Claude Code MCP integrations (Semgrep, Snyk, SonarQube).

## Key takeaways

- For a generic, OSS-first, polyglot agent, a single pattern+taint engine (Opengrep or Semgrep CE) covers TS/Go/Python/Java in one binary with Semgrep-compatible rules and CI portability — make this the default first pass.
- Opengrep (2025 community fork, LGPL-2.1, 10+ vendor consortium) restores taint/interprocedural/fingerprinting/Windows to OSS that Semgrep moved behind its paid tier; v1.21.0 (May 2026) added LSP taint, v1.20.0 added Python match/case parsing.
- Semgrep CE stays free (LGPL-2.1, ~3,000 rules) but cross-file dataflow and AI business-logic detection (IDOR/authz beta) are paid (Team $35/contributor/mo). It ships the only first-party Claude Code plugin bundling MCP + hooks + skills.
- CodeQL has the deepest dataflow/taint but a license trap: CLI is free only for public/OSS/academic — private-repo local scanning needs paid GitHub Advanced Security. Treat it as a public-repo-only or GHAS-customer option.
- Three commercial tools ship official, Claude-Code-ready MCP servers in 2026: Snyk (npx snyk mcp configure --tool=claude-cli, autofix loop), SonarQube (~25 tools, Docker), and Semgrep (uvx semgrep-mcp / claude mcp add). Design the agent to optionally consume these when the user already pays.
- Layer thin language-native security linters as a cheap second pass: golangci-lint+gosec (Go, now taint-aware v2.26.1), ruff S-rules + bandit (Python), eslint-plugin-security (JS/TS), spotbugs+find-sec-bugs (Java).
- Python guidance: prefer ruff 'S' rules (10-100x faster, shares AST) for speed, but keep bandit for framework/AI code (Django, raw SQLAlchemy, PyTorch, Hugging Face) since ~6 bandit detectors have no ruff equivalent — relevant for AI projects.
- Java's find-sec-bugs needs COMPILED bytecode (SpotBugs plugin) — the agent must build the project first; PMD works on source. This is an operational gotcha for a generic agent that may only see source.
- eslint-plugin-security is pattern/regex-level, not dataflow-aware; the 2026 consensus is ESLint in-editor + Semgrep/Opengrep in CI for real JS/TS security depth.
- SonarQube Community Build (LGPL-3.0) lacks taint/injection SAST and branch analysis — real security starts at paid Developer Edition or SonarQube Cloud; don't assume the free self-hosted build gives security-grade results.
- For a vendor-neutral default that is fully OSS, zero-login, fast, and CI-friendly, recommend: Opengrep (engine) + per-language linters, with CodeQL/Snyk/Sonar as optional deeper or MCP-driven escalation layers.
- All recommended OSS tools run identically locally and in CI via a single CLI invocation, which suits an agent that shells out (semgrep/opengrep scan, gosec, ruff, eslint, spotbugs) rather than depending on a cloud platform.

## Sources

- https://semgrep.dev/pricing/
- https://semgrep.dev/products/community-edition/
- https://github.com/semgrep/semgrep-rules
- https://semgrep.dev/docs/release-notes/march-2026
- https://www.opengrep.dev/
- https://github.com/opengrep/opengrep
- https://appsecsanta.com/opengrep
- https://www.aikido.dev/blog/launching-opengrep-why-we-forked-semgrep
- https://semgrep.dev/docs/faq/comparisons/opengrep
- https://codeql.github.com/
- https://github.com/github/codeql
- https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/about-the-codeql-cli
- https://appsecsanta.com/github-codeql
- https://snyk.io/plans/
- https://snyk.io/snyk-for-claude-code/
- https://docs.snyk.io/integrations/snyk-studio-agentic-integrations/quickstart-guides-for-snyk-studio/claude-code-guide
- https://weavai.app/blog/en/2026/04/30/snyk-code-2026-review-ai-sast-free-plan-value/
- https://www.sonarsource.com/plans-and-pricing/
- https://docs.sonarsource.com/sonarqube-mcp-server
- https://docs.sonarsource.com/sonarqube-mcp-server/quickstart-guide/claude-code
- https://github.com/SonarSource/sonarqube-mcp-server
- https://appsecsanta.com/sonarqube
- https://github.com/securego/gosec
- https://appsecsanta.com/gosec
- https://golangci-lint.run/docs/linters/
- https://pydevtools.com/handbook/how-to/how-to-enable-ruff-security-rules/
- https://mcginniscommawill.com/posts/2026-02-10-ruff-bandit-vs-traditional/
- https://github.com/eslint-community/eslint-plugin-security
- https://www.npmjs.com/package/eslint-plugin-security
- https://github.com/find-sec-bugs/find-sec-bugs
- https://owasp.org/www-project-find-security-bugs/
- https://spotbugs.github.io/
- https://github.com/semgrep/mcp
- https://semgrep.dev/docs/mcp

