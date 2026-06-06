# Plan: Generic Multi-Language white-hacker Security Agent for Claude Code

Status: DRAFT for approval
Date: 2026-06-06
Owner: ping@jaigouk.kim

Goal: evolve the current Go/alto-specific `white-hacker` agent into a **generic, polyglot, multi-project-type** security agent that (a) works on any TS/Go/Python/Java/AI repo, backend or frontend, (b) is composable as a set of skills, and (c) plugs into a TL/QA/Dev/white-hacker team workflow. Methodology is anchored on Anthropic's defending-code harness spine — **threat-model -> discovery (recall) -> verification (precision) -> triage -> patch (+re-attack)** — plus the 2026 research takeaways (OWASP 2025/LLM-2025/Agentic-2026, Opengrep, Trivy 0.71, supply-chain worms).

Design north star: **detection is cheap; verification, triage, and remediation are the bottleneck.** Spend complexity there, not on yet another scanner.

---

## 1. Gap Analysis — what the current profile lacks to be generic

The current profile is a competent single-pass Go reviewer. To be generic it has eight concrete gaps:

| # | Gap | Current state | Why it blocks "generic" |
|---|-----|---------------|--------------------------|
| G1 | **Language coupling** | Hard-codes `govulncheck`, `golangci-lint gosec`, Go-only checklist sinks (filepath, exec.Command). | Useless on TS/Py/Java; no fallback when Go toolchain absent. |
| G2 | **No language/framework auto-detection** | Assumes Go + alto repo. | Cannot pick the right native scanner or per-language checklist. |
| G3 | **Single-pass, not recall/precision-separated** | One agent does find + judge + report in one context. | Combining discovery and verification causes self-censorship that drops true positives; no adversarial verifier -> high FP rate. |
| G4 | **No threat-model stage** | No THREAT_MODEL.md ingest/synthesis; severity is self-assessed by the finder. | Well-documented threat models drove ~90% exploitable findings; without it, severity inflates and scan is unscoped ("shoot before you aim"). |
| G5 | **No AI/LLM/MCP/Agentic coverage** | Zero prompt-injection, improper-output-handling, lethal-trifecta, MCP token-passthrough, RAG-poisoning checks. | A 2026 generic agent must map to OWASP LLM Top 10 (2025), MCP Top 10 (beta), Agentic Top 10 (ASI, 2026). |
| G6 | **No first-class API / web checks** | No OWASP API Top 10 (BOLA/BFLA/BOPLA), JWT alg-confusion, SSRF/DNS-rebind, CORS, mass-assignment, security-headers. | These are the dominant real-world classes across all stacks. |
| G7 | **No FP discipline / exclusion list / PoC gate** | "Create P1 bead, propose fix." No confidence band, no DO-NOT-REPORT list, no dedup rule, no PoC/re-attack. | This is the single highest-leverage element; without it the report is noise an engineer ignores. |
| G8 | **No structured output / dedup / variant hunt** | Free-form prose + bead ticket. | No machine-consumable JSON for CI gating, no dedup-by-root-cause, no post-fix variant search. |
| G9 | **Trivy-only tool table, MCP-only, no degradation** | mcp__trivy__* table; no SAST, no secrets, no SCA fallback to CLI. | Trivy has no SAST; agent must degrade gracefully when a tool is missing and pair Trivy with a code-level engine. |
| G10 | **No prompt-injection self-defense** | Reviews content as if trusted. | The reviewer itself is an injection target (Microsoft 2026-06-05 PoC exfiltrated ANTHROPIC_API_KEY via /proc/self/environ; fixed in Claude Code 2.1.128). Must treat all reviewed text as untrusted and enforce Agents Rule of Two. |

**Verdict:** keep the orchestration spine and the team-mode plumbing; replace everything language-specific and add the four missing stages (threat-model, separate verification, structured triage, patch+re-attack) plus the AI/API/supply-chain coverage.

---

## 2. Proposed Artifact Architecture — one agent + composable skills

### 2.1 Primitive-selection rule (from the research)
- **Agent** (`*.md` with `name`+`description`, read-only `tools`): the *identity* — the senior-security-engineer persona, posture, and stage-dispatch logic. Reusable three ways: `/security-review` skill, delegated subagent, and agent-team teammate.
- **Skill**: a reusable *procedure/prompt* for one stage. Stages are distinguished only by tool-allowlist + prompt (no named subagent classes). Chains via on-disk JSON artifacts.
- **Command**: only `/security-review` as the thin human entry point (mirrors Anthropic shipping the action + slash command from one prompt).

Decision: **define the agent ONCE** as `agents/white-hacker.md`; ship `/security-review` as a command that invokes the discovery->triage chain; ship the per-stage logic as **skills** so each can run standalone or be chained.

### 2.2 The skills (each one-level-deep `reference/` for language detail; SKILL.md < 500 lines)

| Skill | Purpose (one line) | Primitive | Tools tapered | Reads | Writes |
|-------|--------------------|-----------|---------------|-------|--------|
| `sec-threat-model` | Synthesize/ingest THREAT_MODEL.md from docs+git history+past CVEs; capture trust boundary, scoring standard, scope. | Skill (stateful bootstrap ok) | Read, Grep, Glob, Bash(git log/read-only) | repo, docs | `THREAT_MODEL.md` |
| `sec-detect` | Auto-detect languages/frameworks; pick native scanners; emit a scan plan. | Skill | Read, Glob, Bash(version probes) | repo root | `SCAN-PLAN.json` |
| `secrets-scan` | Fast secret pass (gitleaks) + verified pass (trufflehog --results=verified). | Skill | Read, Grep, Bash | repo | `SECRETS.json` |
| `deps-scan` | SCA via native low-FP gates (govulncheck/pip-audit/...) + OSV-Scanner/Trivy fallback. | Skill | Read, Bash | lockfiles | `DEPS.json` |
| `sec-vuln-scan` (discovery) | **Recall-optimized**, non-prescriptive: find everything across the partitioned attack surface. | Skill (fan-out) | Read, Grep, Glob (+Opengrep via Bash) | repo, `THREAT_MODEL.md`, `SCAN-PLAN.json` | `VULN-FINDINGS.json` |
| `sec-triage` (verification+triage) | **Precision-optimized**, adversarial N-of-N voting, dedup, precondition-counted severity, exclusion list. | Skill (fresh context) | Read, Grep ONLY | `VULN-FINDINGS.json`, `THREAT_MODEL.md` | `TRIAGE.json` |
| `ai-llm-review` | OWASP LLM/MCP/Agentic checks: prompt-injection, improper output handling, lethal trifecta, MCP token passthrough, RAG poisoning. | Skill | Read, Grep, Glob | repo, `SCAN-PLAN.json` | merged into `VULN-FINDINGS.json` |
| `sec-patch` | Patch ladder: build -> PoC-stops -> tests -> **re-attack**; root-cause fix; minimal diff. Write-gated to `./PATCHES/` only. | Skill (separate, opt-in) | Read, Write(./PATCHES/ only), Bash(sandbox) | `TRIAGE.json` | `PATCHES/`, `PATCH-STATE.json` |
| `sec-report` | Render `TRIAGE.json` -> human markdown + machine JSON; map to OWASP IDs. | Skill | allowed_tools=[] (pure reasoning) | `TRIAGE.json` | `SECURITY-REPORT.md` |

### 2.3 How they chain (artifact-backed, not conversational)

```
sec-threat-model ─► THREAT_MODEL.md
        │
sec-detect ─► SCAN-PLAN.json
        │
        ├─ secrets-scan ─► SECRETS.json ┐
        ├─ deps-scan    ─► DEPS.json    ├─► merged into VULN-FINDINGS.json
        ├─ sec-vuln-scan (RECALL, fan-out by partition) ─► VULN-FINDINGS.json
        └─ ai-llm-review (if AI repo) ──────────────────► VULN-FINDINGS.json
        │
sec-triage (PRECISION, fresh context, adversarial N-of-N) ─► TRIAGE.json
        │
sec-report ─► SECURITY-REPORT.md  (+ optional CI JSON gate)
        │
sec-patch (opt-in) ─► PATCHES/ + re-attack verdict
```

Key invariants:
- Each finding appears **exactly once**; duplicates reference a canonical id.
- `sec-triage` runs in a **fresh context with no shared history/filesystem state** from discovery (independence is the whole point of the verifier).
- `sec-patch` is **capability-removed**, not instructed: no `--apply`, no `git apply` in allowed-tools, writes whitelisted to `./PATCHES/`.

### 2.4 Default mode = static-analysis-only
The universal invariant is **no build/run/install/network during scanning**. "No PoC" is explicitly weak evidence — for high-confidence HIGHs the report recommends a human-built PoC. Execution-verified mode (real PoC detonation) is an **opt-in, sandboxed** escalation (section 4.4), not the default for side projects.

---

## 3. Language Auto-Detection Strategy (`sec-detect`)

Two-layer detect: **ecosystem manifest** -> **framework fingerprint** -> **scanner selection**.

### 3.1 Manifest -> language
| Signal file | Language |
|-------------|----------|
| `go.mod` / `go.sum` | Go |
| `package.json` + `tsconfig.json` | TypeScript (else JS) |
| `pyproject.toml` / `requirements*.txt` / `Pipfile` / `uv.lock` | Python |
| `pom.xml` / `build.gradle(.kts)` | Java/Kotlin (JVM) |
| `Cargo.toml` | Rust |
| `Dockerfile` / `*.tf` / `*.yaml`(k8s) / `.github/workflows/*` | IaC/CI layer (always scan) |

### 3.2 Framework fingerprint (drives the per-language checklist appendix)
- **TS/JS**: `next` (App Router? -> React2Shell + middleware-authz checks), `react`/`vue`/`angular` (XSS sinks), `express`/`fastify`/`nestjs`.
- **Python**: `django`/`flask`/`fastapi`/`drf` (authz per-handler), `sqlalchemy`/`.raw()`/`.extra()` (SQLi), `langchain`/`transformers`/`torch`/`openai`/`anthropic` -> **trigger `ai-llm-review`** + insecure-deser (pickle/torch.load).
- **Go**: `net/http`/`gin`/`chi`/`echo`, `database/sql`, `os/exec`, `text/template`.
- **Java**: `spring-boot`/`spring-security` (version-gate CVE-2025-41248/41249), `jackson` (default typing), `*ObjectInputStream*`.

### 3.3 Scanner selection (write into SCAN-PLAN.json)
| Stack | SAST (code) | SCA (deps, low-FP first) | Always |
|-------|-------------|--------------------------|--------|
| TS/JS | Opengrep (+eslint-plugin-security advisory) | npm/pnpm audit + OSV-Scanner | gitleaks, trufflehog --results=verified, Trivy fs/config |
| Go | Opengrep + gosec (taint, v2.23+) | **govulncheck** (reachability) | same |
| Python | Opengrep + ruff `S` (fast) + bandit (framework/AI) | **pip-audit** + OSV-Scanner | same |
| Java | Opengrep (+ spotbugs/find-sec-bugs only if compiled bytecode available — note: source-only repos skip it, PMD instead) | OSV-Scanner / Trivy on lockfile | same |
| IaC/CI | Trivy `config` + Checkov; zizmor/actionlint for Actions; hadolint for Dockerfiles | — | same |

Opengrep is the **single default cross-language engine** (Semgrep-compatible rules, taint/interprocedural restored in OSS, LGPL-2.1; v1.21.0 May 2026 added LSP taint). Native scanners are near-zero-cost gates layered on top.

---

## 4. Tool Strategy

### 4.1 Core-default tools (always available, zero-install)
Built-in **Read / Grep / Glob scoped to cwd** is a sufficient read-only scanning scaffold for any language — no MCP server or external SAST is required to get value. This is the guaranteed floor; everything else is an enhancer.

### 4.2 Recommended OSS toolbelt (install if missing, pinned)
Vendor-neutral, OSS-first, single-binary, SARIF-emitting:
- **SAST:** Opengrep (engine) + per-language linters (gosec / ruff-S+bandit / eslint-plugin-security / spotbugs+find-sec-bugs).
- **SCA:** native gate (govulncheck / pip-audit / cargo-audit / npm audit) **+** OSV-Scanner v2 (`go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`) as the cross-language fallback.
- **Secrets:** gitleaks (fast pre-commit pass) + trufflehog `--results=verified` (CI verification); detect-secrets baseline for brownfield repos.
- **Containers/IaC/SBOM:** Trivy (fs/image/config/repo), Checkov, hadolint, kubescape, syft+grype, cosign; zizmor/actionlint for CI.

### 4.3 Trivy: MCP vs CLI decision
**Default to CLI**, optionally consume the MCP if already configured.
- CLI gives full control of `--scanners vuln,misconfig,secret,license`, `--severity HIGH,CRITICAL`, `--ignore-unfixed`, `--format json`, `--exit-code 1` for gating, across `trivy fs|image|config|repo`. The agent shells out the same locally and in CI.
- The **official MCP** (`aquasecurity/trivy-mcp`, plugin install `trivy plugin install mcp`, start `trivy mcp`, latest **v0.0.20** Dec 2025) exposes **6 tools** surfacing as `mcp__trivy__*`: `scan_filesystem`, `scan_image`, `scan_repository`, `trivy_version`, `findings_list`, `findings_get`. Add via `claude mcp add trivy -- trivy mcp`. Use it when the user already runs it; the agent must detect presence and prefer it over CLI when both exist, but never depend on it.
- **Supply-chain hygiene (2026, non-negotiable):** Trivy latest stable **v0.71.0 (2026-06-01)**. **Avoid binary v0.69.4 and images 0.69.5/0.69.6 (malicious); safe = v0.69.2/0.69.3 and v0.70.0+.** Never auto-install from unpinned sources — prefer brew or a digest-pinned binary/image with GPG/signature verification (official Trivy action was compromised twice in March 2026; deb/rpm GPG keys rotated in v0.70.0).
- **Coverage caveat baked into the prompt:** Trivy = SCA + IaC + secrets + SBOM + license, **NO SAST**. A clean Trivy run is NOT full source coverage — always pair with Opengrep.

### 4.4 Execution-verified (opt-in) sandbox
For high-value HIGHs only: gVisor/Docker isolation, snapshot after setup, **remove network during scanning with egress locked to api.anthropic.com**. Per-vuln-class oracle (no single ASAN-style crash oracle in TS/Go/Py/Java): reproducing request+observed effect (SQLi/SSRF), privilege-boundary assertion (authz), behavioral execution check (prompt-injection). PoC must reproduce **3/3** before grading. Pass only the PoC artifact (not container state) to a fresh grader container.

### 4.5 Graceful degradation ladder (per category)
1. Native low-FP gate present? use it (best signal).
2. Else Opengrep/Trivy/OSV present? use it.
3. Else fall back to **Read+Grep+Glob heuristic pass** and **mark findings `tool_assisted:false, confidence capped`** in JSON so downstream knows the evidence is weaker.
The agent **never blocks** on a missing tool; it records `"tools_unavailable": [...]` in the report and lowers confidence rather than failing.

---

## 5. Generic Security CHECKLIST Structure

Organize by **root-cause category** (language-agnostic core), then **per-language appendices**, then **AI/LLM** and **API** appendices. Categories AND exclusions are **config-driven** (mirror the action's `custom-security-scan-instructions` + `false-positive-filtering-instructions` file inputs) so each side project tunes without forking.

### 5.1 Core categories (apply to ALL languages) — map to OWASP 2025 Web IDs
1. **Injection** — SQL/NoSQL/command/LDAP/XPath/XXE/template(SSTI)/path-traversal. (data is user-controlled, never the template/expression string)
2. **AuthN/AuthZ** — BOLA/IDOR, BFLA, BOPLA/mass-assignment (inbound DTO allowlist + outbound response DTO), privilege escalation, JWT (hard-coded expected alg, kid/jku allowlist, exp/iss/aud), session. *Dominant risk class; default-deny, re-verify principal server-side per object/function.*
3. **SSRF** — host allowlist, resolve-once-pin-IP, block RFC1918/loopback/link-local/169.254.169.254 (all encodings + IPv6), re-resolve each redirect hop (DNS rebinding), IMDSv2. (first-class even though merged into A01-2025)
4. **Crypto & secrets** — hardcoded creds, weak algos (md5/sha1 for passwords), `random` vs `secrets`, cert-validation bypass, key storage.
5. **Insecure deserialization / RCE** — pickle/yaml.load/readObject/BinaryFormatter; never natively deserialize untrusted input.
6. **XSS / output handling** — framework sinks (dangerouslySetInnerHTML, v-html, innerHTML, bypassSecurityTrust*); render-as-text/DOMPurify; validate href/src schemes.
7. **Config & headers** (A02-2025 #2) — HSTS, CSP nonce+strict-dynamic, nosniff, COOP/COEP/CORP, CORS (reflected-Origin+credentials, wildcard-credentialed, null origin, unanchored regex), disabled debug, default creds.
8. **Supply chain** (A03-2025) — lockfiles required, lifecycle-script abuse (Shai-Hulud worm family Sept'25/Nov'25/Mini May'26), `npm ci --ignore-scripts`, audit signatures, pinned Actions to commit SHA, pinned Docker base by digest.
9. **Error handling** (A10-2025) — fail-open logic, swallowed exceptions, error/stack leakage.
10. **Data exposure** — PII/secret logging, debug endpoints, over-exposed responses.
11. **Resource consumption** — pagination caps, body/upload/array size limits, GraphQL depth/complexity, ReDoS/zip-bomb. *(advisory-tier; not reported as HIGH alone — see exclusions)*

### 5.2 Per-language appendices (`reference/lang-*.md`, load on demand)
- **go.md** — `os.Root`/`os.OpenInRoot` (1.24) not `filepath.Join`; shell-only command injection; SSRF resolved-IP allowlist; `make([]byte,n)` length validation (go-safecast); run govulncheck + gosec (G115 advisory).
- **python.md** — f-string/`%`/format in `cursor.execute`, `.raw()/.extra()`, `text()`; `render_template_string`+request data (SSTI, CVE-2025-23211); pickle/yaml.load/torch.load(weights_only)/trust_remote_code; `eval/exec`; defusedxml; DEBUG=True.
- **typescript.md** — Next.js CVE-2025-29927 (middleware auth bypass <15.2.3) + React2Shell CVE-2025-66478/55182 (RSC deser RCE, App Router 15.x/16.x); prototype pollution (lodash CVE-2025-13465/2026-2950, devalue CVE-2025-57820); `eval/new Function/vm.runInThisContext`, vm2 abandoned -> isolated-vm; `exec` template strings / `shell:true`.
- **java.md** — Spring Security version-gate (CVE-2025-41248/41249 @PreAuthorize-on-generics); Jackson default typing w/o PolymorphicTypeValidator; `ObjectInputStream` w/o ObjectInputFilter; XXE default factories; SpEL `parseExpression(userInput)`; log4j-core >= 2.17.1; jackson-core deep-nest DoS (CVE-2025-52999); `@Query(nativeQuery=true)` concat.

### 5.3 AI/LLM appendix (`reference/ai-llm.md`) — map to OWASP LLM Top 10 (2025), MCP Top 10 (beta), Agentic/ASI Top 10 (2026)
- **LLM01 Prompt Injection** — no reliable general fix; flag architectural absence of dual-LLM/CaMeL/spotlighting/least-agency. Never trust a classifier as a boundary.
- **LLM05 Improper Output Handling (highest-yield code check)** — model/tool/RAG output flowing into eval/exec/subprocess (RCE), string-SQL (SQLi), unsanitized HTML/MD (XSS), file paths (traversal), URLs (SSRF), templates (SSTI), deserializers. Treat ALL model+tool+RAG output as untrusted; require schema-validated structured output before any sink.
- **Lethal trifecta / Agents Rule of Two** — flag any path combining private-data access + untrusted input + exfiltration/state-change without human approval.
- **MCP** — no token passthrough (RFC 8707 audience binding), tool-description/schema poisoning, confused-deputy (bind action to validated user identity), provenance pinning (rug-pulls/typosquatting).
- **Agentic (ASI)** — least agency, distinct short-lived per-agent identities, human-in-the-loop for money/admin/data-write/code-exec, sandboxed exec (ban eval/gate shell), circuit breakers between stages (cascading failures), rogue-agent observability.
- **RAG/vector** — KB poisoning, indirect injection via retrieved docs, embedding inversion, cross-tenant leakage (DB-layer tenant isolation).
- **LLM07/LLM10** — system prompts WILL leak (no secrets/logic in them); unbounded consumption (token/iteration/recursion caps, budget circuit breakers).

### 5.4 API appendix (`reference/api.md`) — OWASP API Security Top 10 **2023** (no 2025/2026 edition exists — distrust "API Top 10 2026" claims)
BOLA(#1)/BFLA/BOPLA, broken auth, unrestricted resource consumption (rate-limit/pagination), SSRF, improper inventory, unsafe consumption of third-party APIs. Highest-value generic check: every object/function access re-verifies authenticated principal server-side, scoped by owner/tenant, default-deny.

### 5.5 IaC/CI/supply-chain appendix (`reference/infra.md`)
Dockerfile (non-root numeric USER, multi-stage, `RUN --mount=type=secret`, .dockerignore), k8s/Helm (PSS Restricted, render `helm template | trivy config -` first), GitHub Actions (least-priv `permissions: contents: read`, OIDC, pull_request_target pwn-requests, no `${{ github.event.* }}` in `run:`), SLSA L2 attestations, Sigstore keyless signing.

---

## 6. Severity Rubric + False-Positive Discipline

### 6.1 Severity = precondition COUNTING, not impact guessing (adopt harness rubric)
Enumerate preconditions FIRST, then map:
- **0 preconditions + unauth remote** -> **HIGH/Critical**
- **1-2 preconditions OR authenticated** -> **MEDIUM**
- **3+ preconditions OR local-only** -> **LOW**
- A threat-model match may bump **at most one step**.
- Severity = `min(precondition_count_score, required_access_level_score)`, derived in **triage** from reachability across trust boundaries — **never** from the finder's self-assessed score.
- The scoring **standard is swappable** (CVSS 3.1/4.0 / OWASP / org bug-bar) — `sec-threat-model` asks which to use at run start; don't hard-code one.
- Keep **verification CLASS separate from OUTCOME**: `verified ∈ {ladder_passed, ladder_failed, static_review_only}` is distinct from `review ∈ {ACCEPT, REJECT}`; precondition-derived severity (sorting) is distinct from `severity_label` (presentation). Downstream branches on class, not outcome — so "real" never inflates into "critical".

### 6.2 FP discipline (the single highest-leverage element)
- **Confidence bands:** report only `>= 0.7` (0.9-1.0 certain, 0.8-0.9 clear pattern, 0.7-0.8 suspicious); **final gate: HIGH/MEDIUM with confidence >= 8/10** and **>80% exploitability**.
- **Hard DO-NOT-REPORT list** (config-extendable via a `--fp-rules` hook): volumetric/DoS, rate-limiting, memory exhaustion, memory-safety in memory-safe langs, **test/fixture/dead code**, on-disk secrets, log spoofing, regex injection, theoretical TOCTOU, path-only SSRF, prompt-injection-into-LLM (architectural, not code-bug), auto-escaped XSS without a raw-HTML hatch, client-side permission checks, generic input-validation without proven impact, outdated-lib without reachable sink, missing audit logs, documentation issues. (The harness's 16-18 exclusion rules, reused verbatim.)
- **Adversarial N-of-N voting (default 3):** each independent voter assumes the scanner is WRONG and re-derives from source: read -> trace-reachability-backward -> hunt-protections -> stress-every-path -> fixed `VERDICT / CONFIDENCE / REFUTE_REASON / EXCLUSION_RULE / FIRST_LINK / RATIONALE` block. This alone roughly halved non-exploitable findings in Anthropic's data. Run in a **fresh context, never forked** (forking leaks orchestrator context and destroys independence).
- **Dedup = "two findings are duplicates if fixing one fixes the other."** Two-pass: cheap deterministic (same file + same category + lines within 10) then LLM semantic (cross-file same-root-cause). Every input finding appears once; duplicates reference a canonical id.
- **Prompt-injection defense by context starvation:** the decision-making voter/patcher sees only `{file, line, category, diff}` — never finding prose or author rationale — so injected instructions can't pass both author and gate. Treat ALL reviewed content as untrusted in the system prompt (Agents Rule of Two: never simultaneously ingest untrusted input + hold secrets + have egress).
- **Persona/altitude:** "senior security engineer doing a focused review of high-confidence, real-exploitation findings" — measurably reduces noise.

---

## 7. Team-Workflow Integration (TL / QA / Dev / white-hacker)

### 7.1 One definition, three carriers
`agents/white-hacker.md` (`name`, `description` with concrete triggers, read-only `tools: Read, Grep, Glob, Bash`, `model: opus`) is reusable as: (1) the `/security-review` command, (2) a delegated subagent (isolated context, summary-only return), (3) an **agent-team teammate**. Note the carry-over caveats: a subagent's `skills`/`mcpServers` fields **do not apply** when it runs as a teammate (teammates load skills/MCP from project+user settings, not the subagent frontmatter), and plugin subagents ignore `permissionMode`/`mcpServers`/`hooks` — so put operational detail in the **spawn prompt** and rely on project-scope skills.

### 7.2 Two execution modes
- **Sequential / subagent mode (default for side projects):** TL (or `/launch-team` lead) invokes white-hacker as a plain subagent at the **review phase** after Dev implements and QA tests. Lower token cost; white-hacker runs threat-model -> discovery -> triage -> report and returns **only `TRIAGE.json` summary + `SECURITY-REPORT.md` path**. Prefer this for non-collaborative parallel review.
- **Team mode (`CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`, requires Claude Code >= v2.1.32):** TL = lead; spawns Dev/QA/white-hacker teammates with **non-overlapping file ownership**. Reserve for work needing adversarial cross-check (white-hacker challenges Dev's auth code, QA confirms regression). Communicate via SendMessage mailbox + shared task list; enforce gates with `TaskCompleted`/`TeammateIdle` hooks. Start 3-5 teammates.

### 7.3 What white-hacker RETURNS (contract for downstream tooling)
Strict JSON, **JSON only, no code fences**, every field required, `null` = not-applicable, severity as enum:
```json
{
  "summary": {"scanned_langs": [], "tools_used": [], "tools_unavailable": [],
              "scoring_standard": "CVSS4.0", "counts": {"high": 0, "medium": 0, "low": 0}},
  "findings": [{
    "id": "F-001", "canonical_of": null, "file": "", "line": 0,
    "severity": "HIGH", "category": "bola", "owasp": ["API1:2023", "A01:2025"],
    "preconditions": [], "access_required": "unauth-remote",
    "verified": "static_review_only", "confidence": 0.9,
    "exploit_scenario": "", "recommendation": "",
    "first_link": "path:line", "tool_assisted": true
  }]
}
```
`sec-report` renders this to markdown for humans; CI gates on `counts.high == 0` (`--exit-code 1`). Findings flow to a beads P1 ticket (existing behavior) — but only AFTER triage, never raw discovery output. white-hacker **proposes** fixes (or `PATCHES/` if `sec-patch` opted-in); **does not push** (capability removed, not instructed).

### 7.4 Posture preamble (always prepended)
Engagement/authorization + scope preamble: authorized targets only, read-only-by-default, no creds stored, responsible disclosure, review the developer's **own working tree/diff** (not arbitrary fetched branches). Opt into the `claude_code` system-prompt preset explicitly (Agent SDK v0.1.0+ no longer applies it by default). Diff-aware + context-aware: review changed lines, read surrounding files for context, compare against the project's existing secure patterns.

---

## 8. Phased Rollout + Folder Layout

### 8.1 Build order (ship value early, defer execution-verification)
- **Phase 0 — Skeleton (week 1):** `agents/white-hacker.md` (generic persona + posture preamble) + `/security-review` command that runs **discovery -> triage -> report** on the diff using only Read/Grep/Glob. This alone beats the current single-pass Go agent on any language. Port the core checklist (5.1) inline.
- **Phase 1 — FP discipline + structure (week 2):** add `sec-triage` adversarial N-of-N + exclusion list + precondition severity + strict JSON schema + dedup. *This is where the real quality lives.*
- **Phase 2 — Threat model + detect (week 3):** `sec-threat-model` (AskUserQuestion-driven, with `--auto`/`--fresh` fallbacks) + `sec-detect` (SCAN-PLAN.json) + per-language `reference/*.md`.
- **Phase 3 — Tool integration (week 4):** `secrets-scan`, `deps-scan`, Opengrep first pass, Trivy CLI (+optional MCP), graceful degradation ladder. Pin all tool versions; verify Trivy version/signature.
- **Phase 4 — AI/LLM + API appendices (week 5):** `ai-llm-review` skill + `reference/ai-llm.md` + `reference/api.md`, framework-triggered.
- **Phase 5 — Patch + re-attack (week 6, opt-in):** `sec-patch` ladder (build -> PoC-stops -> tests -> re-attack), capability-removed writes to `PATCHES/`, variant hunt (sibling call sites + same class) as standard post-fix step.
- **Phase 6 — Team mode + CI (week 7):** team-mode spawn prompts, hooks (`TaskCompleted`/`TeammateIdle`, `PreToolUse exit 2` to block dangerous Bash), and the CI GitHub Action sharing the same prompt (pin model = opus/dated id, pin `@anthropic-ai/claude-code`, pin Actions to commit SHA, "Require approval for external contributors").
- **Phase 7 — Eval (ongoing):** validate against a labeled finding set before each release; track FP rate.

### 8.2 Proposed folder layout (artifacts repo at `the repo root`)
```
white-hacker/
├── agents/
│   └── white-hacker.md                 # the ONE definition (persona, posture, dispatch)
├── commands/
│   └── security-review.md              # thin human entry -> discovery+triage chain
├── skills/
│   ├── sec-threat-model/SKILL.md
│   ├── sec-detect/SKILL.md
│   ├── secrets-scan/SKILL.md
│   ├── deps-scan/SKILL.md
│   ├── sec-vuln-scan/SKILL.md          # discovery (recall)
│   ├── sec-triage/SKILL.md             # verification+triage (precision)
│   ├── ai-llm-review/SKILL.md
│   ├── sec-patch/SKILL.md
│   ├── sec-report/SKILL.md
│   └── _shared/
│       ├── reference/
│       │   ├── core-checklist.md
│       │   ├── lang-go.md
│       │   ├── lang-python.md
│       │   ├── lang-typescript.md
│       │   ├── lang-java.md
│       │   ├── ai-llm.md
│       │   ├── api.md
│       │   └── infra.md
│       ├── severity-rubric.md
│       ├── exclusion-rules.md           # the DO-NOT-REPORT list (config-extendable)
│       └── finding-schema.json
├── ci/
│   └── security-review.action.yml       # pinned model + pinned deps + SHA-pinned actions
├── config/
│   ├── custom-scan-instructions.example.md
│   └── fp-rules.example.md
├── docs/
│   ├── research/                        # source takeaways
│   └── plan/PLAN.md                     # this file
└── .gitignore                           # MUST include .notes/
```
Distribution: store at user scope (`~/.claude/agents/`, `~/.claude/skills/`) or package as a **plugin** for cross-project reuse; project scope only when repo-specific. Identity comes from the `name` field, not the path.

### 8.3 Reproducibility / safety knobs to set
- Pin subagent model: `CLAUDE_CODE_SUBAGENT_MODEL` = a dated Opus id; use Opus for reasoning-heavy threat-model/triage stages, lighter model acceptable for discovery fan-out.
- File-backed checkpointing (`./.triage-state/`, `./.patch-state/`, `progress.json` as single source of truth; atomic `checkpoint.py` load/save/shard/append/reset/done; Write->`--from` pattern keeps target bytes out of Bash argv) so long polyglot runs resume after context exhaustion.
- Parallelize per-phase Tasks in one message; **partition the attack surface FIRST** (by endpoint/component/subsystem) then fan out, then one system-level cross-component pass; shard at ~40.

---

## Portability seam (the one idea that keeps this generic)
Keep orchestration **decoupled from language specifics**. Only four things vary per stack and must be parameterized: **(1) what signals a finding (the oracle), (2) the PoC format, (3) how to build+run, (4) which vuln classes are in scope.** Everything else — the find/triage/report/patch loop, dedup, severity, checkpointing, team plumbing — is generic and survives a language port unchanged. Detector + taxonomy prompts swap behind a stable orchestration layer mapped along six axes (vuln class, target shape, detection mechanism, input modality, isolation boundary, dedup signature).
