# PRD — white-hacker: a generic, self-improving white-hat security agent

> Living document. Maintained, not write-once. Today: 2026-06-09. Owner: ping@jaigouk.kim.
> Companions: `docs/ARD.md` (the *why* — ADR-001..023), `docs/plan/PLAN.md` (the build plan),
> `plugins/white-hacker/agents/white-hacker.md` (behavior source of truth). This PRD does not contradict them;
> where it restates a decision, ADR-NNN is cited.

---

## 1. Problem & goals

### 1.1 The problem
Security review for fast-moving side projects has two failure modes that compound each other:

1. **One-shot scanners are noisy and shallow.** A single pass that finds, judges, and reports in
   one context self-censors true positives and inflates false positives — the report becomes noise
   an engineer ignores. Detection is cheap; *verification, triage, and remediation* are the
   bottleneck, and that is exactly where one-shot tools spend the least effort.
2. **AI/agent attack knowledge decays weekly.** Prompt injection, indirect injection, tool/RAG
   poisoning, MCP confused-deputy, excessive agency, and supply-chain worms evolve faster than any
   static checklist. A reviewer frozen at authoring time is wrong within months — and the reviewer
   *itself* is now an injection target (Microsoft's 2026-06-05 PoC coerced an agent into exfiltrating
   `ANTHROPIC_API_KEY` via `/proc/self/environ`).

### 1.2 The two foundations (the whole point)
white-hacker is **two nested loops over plain-text artifacts behind open interfaces** (Agent Skills,
MCP). Everything else — especially specific scanner tools — is secondary and swappable.

| Loop | Source | What it does | Cadence |
|---|---|---|---|
| **INNER — review** | Anthropic `defending-code-reference-harness` | threat-model → discovery (recall) → verification (precision) → triage → patch (+re-attack) | per review |
| **OUTER — self-improvement** | Self-Improving Agent Architecture (Model/Harness/Context surfaces) | trace → reflect → propose text diffs → gate (eval keep-or-revert) → PR | across reviews / idle |

```
                    ┌─────────────────── OUTER LOOP (self-improvement) ───────────────────┐
                    │  trace → reflect → propose TEXT DIFFS → gate(eval) → PR (human)      │
                    │            EDITS the knowledge base / checklists / tool registry     │
                    └──────────────────────────────┬──────────────────────────────────────┘
                                                    │ edits text behind interfaces (no retraining)
                                                    ▼
   ┌──────────────────────────── INNER LOOP (one review) ─────────────────────────────────┐
   │ threat-model → detect → discovery(RECALL) → verification+triage(PRECISION) → report   │
   │                                  → patch(opt-in, +re-attack)                          │
   │            CONSUMES the knowledge base; chains via on-disk JSON artifacts             │
   └──────────────────────────────────────────────────────────────────────────────────────┘
```

They nest: **the inner loop CONSUMES the knowledge base; the outer loop EDITS it.** The KB-refresh
routine is the input arm that ingests "new ways to hack AI products." (ADR-001.)

### 1.3 Goals
- **G1 — Run the inner defending-code loop well** on any TypeScript/Go/Python/Java repo (backend,
  frontend, or AI/LLM/agent framework), with strict false-positive discipline.
- **G2 — Keep AI-attack knowledge current** via the outer loop, with every change a reviewable,
  dated, sourced git diff gated by a frozen eval corpus — *never* model retraining.
- **G3 — Stay portable and tool-agnostic.** Depend on *capabilities*, not brands; produce value with
  zero external tools (the Read/Grep/Glob floor) and improve gracefully when tools exist.
- **G4 — Compose into a team workflow** (TL/QA/Dev + white-hacker on a ticket), sequential/subagent
  mode by default, agent-team mode opt-in.
- **G5 — Be safe as an injection target.** Treat all reviewed content as untrusted; propose, never
  push; never co-locate untrusted input + secrets + egress (Agents Rule of Two).

---

## 2. Non-goals

- **NG1 — Not a fixed tool list.** The product is the *concept* (the two loops), not Trivy/Opengrep/
  OSV-Scanner/gitleaks or any named scanner. Every named tool is an illustrative example behind a
  capability and is swappable; the registry itself self-updates (ADR-015).
- **NG2 — No model retraining / fine-tuning.** All learning is a text edit on the Context/Harness
  surfaces. The Model surface is frozen (`claude-opus-4-8`); gradient updates are not reviewable,
  revertible, or auditable, which the white-hat posture forbids (ADR-001, ADR-004).
- **NG3 — Not a runtime/DAST/pentest platform.** Default mode is static-analysis-only (no build/run/
  install/network during scanning). Execution-verified PoC detonation is an opt-in sandboxed
  escalation, not the default (ADR-007).
- **NG4 — Not an auto-fixer / auto-merger.** white-hacker *proposes* patches to `./PATCHES/`; humans
  apply. The outer loop *proposes* KB diffs as PRs; humans merge. No autocommit, never the default
  branch (ADR-010, ADR-004).
- **NG5 — Not a general-purpose code reviewer.** Scope is security; correctness/style/perf are out.
- **NG6 — Not a compliance/audit-certification tool.** It maps to OWASP IDs for communication, not to
  certify SOC2/ISO/PCI posture.
- **NG7 — No new from-scratch orchestration runtime.** Built only from native Claude Code primitives
  (agents, skills, slash commands, hooks, scheduled routines) — no external DSPy/GEPA runtime (ADR-004).

---

## 3. Personas

| Persona | Who | Needs from white-hacker | Primary mode |
|---|---|---|---|
| **P1 — Solo dev** | Maintainer of a side project, one of TS/Go/Python/Java or an AI app | A `/security-review` over their working diff that returns *real, exploitable* findings only, with file:line evidence, in minutes, with zero tool setup | `/security-review` command |
| **P2 — TL/QA/Dev team** | A small team working a ticket; TL leads, Dev implements, QA tests, white-hacker reviews | A teammate that runs the loop at the review phase and returns the `TRIAGE.json` summary + `SECURITY-REPORT.md` path (not raw discovery), gating merge on `counts.high == 0` | Subagent (default) / agent-team (opt-in) |
| **P3 — The agent itself** | white-hacker reflecting on its own traces | A learning loop that captures FPs/misses/corrections/novel techniques/new tools and proposes dated, sourced, gated text diffs to its own KB/checklists/tool registry | Outer loop (`/sec-learn`, `/sec-kb-refresh`) |

P3 is deliberately a first-class persona: the outer loop's "user" is the agent improving itself, and
its requirements (gates, provenance, identity preservation) are as load-bearing as P1/P2's.

---

## 4. User stories

**Inner loop (P1/P2)**
- US-1: As a solo dev, I run `/security-review` on my diff and get only high-confidence exploitable
  findings, each with `{file, line, category, severity, exploit_scenario, recommendation}`.
- US-2: As a TL, I delegate review to white-hacker as a subagent after Dev+QA, and it returns a
  triage summary plus a report path I can gate CI on — never a wall of raw candidate findings.
- US-3: As a dev on an AI app, I want the agent to detect my LLM/agent/MCP code and run the AI/LLM
  pass (improper output handling, lethal trifecta, MCP token-passthrough, RAG poisoning).
- US-4: As a dev with no security tools installed, I still get value from the Read/Grep/Glob floor,
  with findings honestly marked `tool_assisted:false` and `tools_unavailable` listed.
- US-5: As a dev, when I ask for fixes, I get candidate patches in `./PATCHES/` that I review and
  apply myself — the agent never touches my working tree.
- US-6: As a TL, I want each finding's severity derived in triage from counted preconditions, under a
  scoring standard I chose at run start, so severity isn't inflated by the finder.

**Outer loop (P3)**
- US-7: As the agent, when I had to refute a false positive or missed a finding, I propose a dated KB
  /checklist diff via `/sec-learn`, gated by the eval corpus, as a PR — never auto-applied.
- US-8: As the agent, a scheduled `/sec-kb-refresh` polls authoritative AI-threat feeds, extracts NEW
  techniques, and drafts dated, source-linked KB entries for human approval.
- US-9: As the agent, when I discover a genuinely useful tool not in the registry, I propose adding it
  to the tool registry the same way I propose a new attack technique.
- US-10: As a reviewer of the agent's PRs, I see evidence (session ids, motivating FP/miss, before/
  after score table) and an Apply/Edit/Skip choice, with the decision journaled.

**Execution & resources (P1/P2)**
- US-11: As a dev on a modest laptop, when I ask for a full review the agent measures my machine and
  runs within a safe concurrency cap (or proposes a lighter plan) — it never spawns enough parallel
  work to OOM-freeze my host, even when RAM looks free.
- US-12: As a dev about to commit, I ask for "just the essentials" and get a fast, **sequential**
  secrets + high-yield-diff scan in seconds, with the heavy SCA/SAST deferred to CI.
- US-13: As a TL running white-hacker alongside other subagents, the review respects a **shared**
  concurrency ceiling I set, instead of each agent independently fanning out and oversubscribing the host.

---

## 5. Functional requirements (FR)

Each FR carries a one-line **Verification criterion (VC)** — checkable acceptance.

### 5.1 Inner loop — stages
- **FR-01 — Threat-model stage.** Ingest or synthesize `THREAT_MODEL.md` (assets, entry points, trust
  boundaries, in-scope vuln classes, **swappable scoring standard** asked at run start) from docs +
  git history + past fixes (`sec-threat-model`).
  *VC:* a run on a repo with no prior threat model produces `THREAT_MODEL.md` listing assets, trust
  boundaries, in-scope classes, and a named scoring standard; absent input it states assumptions.
- **FR-02 — Detect stage.** Auto-detect languages/frameworks from manifests; select native scanners;
  decide which reference appendices and the AI/LLM pass apply; emit `SCAN-PLAN.json` (`sec-detect`).
  *VC:* on a polyglot fixture, `SCAN-PLAN.json` lists each detected language and triggers `ai-llm-review`
  iff LLM/agent/MCP deps (`langchain`/`openai`/`anthropic`/`transformers`/MCP/...) are present.
- **FR-03 — Discovery stage (RECALL).** Partition the attack surface first (by endpoint/component/
  subsystem), then sweep each partition with simple non-prescriptive prompts to find everything,
  including unlikely cases; do not self-censor; emit `VULN-FINDINGS.json` (`sec-vuln-scan`).
  *VC:* discovery output records candidate findings even when unproven (flagged), and partitions are
  enumerated before the sweep (visible in the artifact).
- **FR-04 — Verification + triage stage (PRECISION).** Run in a **fresh context with no shared
  history** from discovery; assume each finding is a false positive and try to refute it; **adversarial
  N-of-N voting (default 3)**; decision-maker sees only `{file, line, category, diff}`; dedup by root
  cause; precondition-counted severity; apply the exclusion list; emit `TRIAGE.json` (`sec-triage`).
  *VC:* `TRIAGE.json` shows every input finding exactly once (duplicates reference a canonical id),
  each accepted finding has a triage-derived severity and ≥3 voter verdicts, and the verifier prompt
  contains no finding prose.
- **FR-05 — Report stage.** Render `TRIAGE.json` to human `SECURITY-REPORT.md` + machine JSON; map
  findings to OWASP IDs (Web 2025 / API 2023 / LLM 2025 / Agentic ASI 2026) (`sec-report`).
  *VC:* report contains both markdown and the strict-JSON contract (§5.4); CI can gate on
  `counts.high == 0`.
- **FR-06 — Patch stage (opt-in).** Only when explicitly asked. Patch ladder: build → original PoC no
  longer triggers → existing tests pass → **re-attack with a fresh agent**; root-cause fix + variant
  hunt; minimal diff; writes whitelisted to `./PATCHES/` only (`sec-patch`).
  *VC:* `sec-patch` produces patches only under `./PATCHES/`, never the working tree; a patch is
  marked `ladder_passed` only when all four ladder tiers are clean.
- **FR-07 — Artifact-backed chaining.** Stages chain via on-disk JSON artifacts:
  `THREAT_MODEL.md → SCAN-PLAN.json → VULN-FINDINGS.json → TRIAGE.json → PATCHES/ → SECURITY-REPORT.md`
  (ADR-009).
  *VC:* each stage reads its predecessor's artifact and writes its own; a run is resumable from any
  artifact without re-running prior stages.

### 5.2 Coverage
- **FR-08 — Core OWASP Web coverage (all languages).** Injection (SQL/NoSQL/command/LDAP/XPath/XXE/
  SSTI/path-traversal), AuthN/AuthZ (BOLA/IDOR, BFLA, BOPLA/mass-assignment, JWT, sessions), SSRF,
  crypto & secrets, insecure deserialization/RCE, XSS/output handling, config & headers/CORS, supply
  chain, error handling (fail-open), data exposure, resource consumption (advisory-tier).
  *VC:* the core checklist applies to every detected language; a labeled web fixture for each class is
  caught at the expected severity.
- **FR-09 — AI/LLM/MCP/Agentic coverage.** **LLM05 improper output handling** as the highest-yield
  code check (model/tool/RAG output → eval/exec/SQL/HTML/path/URL/template/deserializer); lethal
  trifecta; prompt injection (architectural defenses only — flagged as a design gap, not a code bug);
  MCP token-passthrough / tool-description poisoning / confused-deputy; RAG/vector poisoning &
  cross-tenant leakage; unbounded consumption; excessive agency. Grounded in the living KB
  (`ai-llm-review` + `ai-attack-kb`).
  *VC:* on an AI-app fixture, an LLM-output-into-sink path is reported with a `kb_refs` link; a bare
  prompt-injection-into-LLM is *not* reported as a code bug (exclusion applied).
- **FR-10 — API coverage.** OWASP API Top 10 **2023** (no 2025/26 edition exists): BOLA/BFLA/BOPLA,
  broken auth, unrestricted consumption, SSRF, unsafe third-party consumption (`reference/api.md`).
  *VC:* findings carry API-2023 OWASP IDs where applicable; the agent does not claim an "API Top 10
  2026."
- **FR-11 — Supply-chain & IaC/CI coverage.** Lockfiles, lifecycle-script abuse (Shai-Hulud family),
  pinned Actions to commit SHA, Docker base by digest; Dockerfile/k8s/Helm/GitHub-Actions checks
  (`reference/infra.md`); SCA via the dependency capability.
  *VC:* an unpinned GitHub Action and a vulnerable lockfile entry in a fixture are each reported with
  the correct OWASP/category mapping.

### 5.3 Tooling — capability discovery + degradation (ADR-003, ADR-015)
- **FR-12 — Capability-based tool discovery.** At runtime, detect which tools are installed and map
  each to a capability (SAST · SCA · secrets · IaC · AI-redteam); never hard-depend on a brand or MCP
  server (`_shared/reference/tool-registry.md`).
  *VC:* on a machine with only a subset of tools, the run uses what is present and records
  `tools_used`; removing a tool changes `tools_used`/`tools_unavailable` but does not error.
- **FR-13 — Graceful degradation to the floor.** When a capability has no tool, fall back to the
  Read/Grep/Glob floor, mark findings `tool_assisted:false`, cap confidence, and list
  `tools_unavailable`; never block on a missing tool.
  *VC:* a run with **zero** external tools completes and produces findings, all marked
  `tool_assisted:false` with `tools_unavailable` populated and confidence capped.
- **FR-14 — Self-updating tool registry.** New/unknown tools enter the registry as dated, sourced,
  reviewable diffs via `/sec-learn` and `/sec-kb-refresh`, exactly like new attack techniques.
  *VC:* a proposed registry addition appears as a PR with `added(date,source)` metadata and a changelog
  line; it is never auto-applied.

### 5.4 Structured output
- **FR-15 — Strict machine-consumable contract.** Emit JSON only (no code fences) with a `summary`
  block (`scanned_langs`, `tools_used`, `tools_unavailable`, `scoring_standard`, `counts`) and a
  `findings[]` array; severity as enum; verification *class* (`ladder_passed`/`ladder_failed`/
  `static_review_only`) kept separate from *outcome* (`ACCEPT`/`REJECT`) and from the severity label.
  *VC:* output validates against `_shared/finding-schema.json` (real schema lands in T-1.1; stub today);
  every required field present; `null` = not-applicable; no code fences in the JSON.

```json
{
  "summary": {"scanned_langs": [], "tools_used": [], "tools_unavailable": [],
              "scoring_standard": "CVSS4.0", "counts": {"high": 0, "medium": 0, "low": 0}},
  "findings": [{
    "id": "F-001", "canonical_of": null, "file": "", "line": 0,
    "severity": "HIGH", "category": "bola", "owasp": ["API1:2023", "A01:2025"],
    "preconditions": [], "access_required": "unauth-remote",
    "verified": "static_review_only", "confidence": 0.9,
    "exploit_scenario": "", "recommendation": "", "first_link": "path:line",
    "tool_assisted": true, "kb_refs": []
  }]
}
```

### 5.5 Outer loop — KB refresh & learn
- **FR-16 — KB refresh (input arm).** *(status: skill BUILT + human-triggerable; **autonomous**
  scheduling pending-wiring — wh-hxt.12 mechanism + wh-hxt.8 capture-hook registration. The
  `/sec-kb-refresh` path runs and proposes a PR when a human invokes it; it does **not** self-fire
  today — a dogfood RCA confirmed ingestion currently depends on a human noticing,
  `docs/research/20260610_hades_shai_hulud_pypi.md` §5 RC1.)* A scheduled routine polls authoritative
  AI-threat feeds (OSV.dev, GitHub Advisory DB, MITRE ATLAS, arXiv cs.CR, OWASP GenAI, practitioner
  blogs — see `docs/research/si-07-threat-feeds.md`), incrementally diffs (last-seen markers), extracts
  NEW techniques, and proposes **dated, source-linked** KB entries for human approval; touches the fast
  tier only; never auto-merges (`sec-kb-refresh`, ADR-012).
  *VC:* a proposed KB entry carries mandatory `metadata.source` (matching `AML\.T\d+|ASI\d+|CVE-\d{4}-\d+`)
  + `url` + `retrieved`; an unsourced threat claim is refused; the proposal is a PR, not a live edit.
- **FR-17 — Learn loop (reflection arm).** *(status: skill BUILT + human-triggerable; depends on
  capture-hook registration for input — wh-hxt.8. `/sec-learn` runs on demand, but the trace-capture
  hooks that feed it are scripted-not-registered today, so it currently harvests zero traces — same
  RCA, `docs/research/20260610_hades_shai_hulud_pypi.md` §5 RC1.)* Mine recent sessions for
  false-positives, missed findings, user corrections, novel techniques, and useful unknown tools; emit
  *structured rationale* (why missed / why FP fired); propose dated diffs to
  KB/checklists/skills/tool-registry as a reviewable PR with a before/after score table (`sec-learn`,
  ADR-004).
  *VC:* `/sec-learn` opens a PR (feature branch, not default) containing a diff + evidence (session
  ids, motivating FP/miss) + a before/after eval score table; nothing is written to the live KB
  directly.
- **FR-18 — Eval keep-or-revert gate.** Every proposed KB/checklist self-edit runs against a frozen,
  agent-read-only paired corpus (vulnerable + benign look-alike, ≥~100 cases); score = Youden's J;
  asymmetric thresholds (hard-revert on >2pp recall loss or >1pp FPR gain or any locked-case regression;
  keep only on non-inferior J + improvement or new sink coverage). *Scope note:* supply-chain DATA edits
  (registry/watchlist rows) have no corpus-measurable contribution and are out of this gate's scope —
  they require the deterministic primary-source + schema Gate-2 (wh-562;
  `docs/research/20260609_supply_chain_loop_leverage.md` §4.1).
  *VC:* an edit that drops recall >2pp or adds >1pp FPR on the frozen corpus is rejected/reverted and
  logged to `evals/rejected.md`; the agent cannot write to `evals/corpus/**` or the gate script.
- **FR-19 — Progressive-disclosure procedural memory.** Skills and KB references load on demand (one
  level deep), so durable knowledge costs ~0 tokens until a task triggers it; the inner loop consumes
  this KB during `ai-llm-review`.
  *VC:* `SKILL.md` files stay < 500 lines, `description`+`when_to_use` ≤ 1,536 chars, `reference/` is
  one level deep; a `lint_skill`/`validate_kb` check enforces caps as a PreToolUse gate.

### 5.6 Team workflow
- **FR-20 — Sequential / subagent mode (default).** Invoked at the review phase; returns only the
  `TRIAGE.json` summary + the `SECURITY-REPORT.md` path (not raw discovery); findings flow to a ticket
  only after triage.
  *VC:* a subagent invocation returns the triage summary + report path; raw `VULN-FINDINGS.json` is not
  surfaced to the caller.
- **FR-21 — Agent-team mode (opt-in).** On first turn `ToolSearch({query:"select:SendMessage"})`; if it
  fails to load, reply that SendMessage is unavailable and exit; route findings to the **tech-lead**,
  not the dev; exit cleanly on WAIT states.
  *VC:* in team mode the agent loads `SendMessage` before routing and addresses the tech-lead; without
  `SendMessage` it degrades to a clean refusal rather than erroring.

### 5.7 Resource-aware execution (concurrency planning)
Run tasks in parallel only when the host can take it; under pressure go sequential, skip/defer the heavy
ones, or ask — never blindly fan out into an OOM-freeze. Source of truth: `plugins/white-hacker/agents/white-hacker.md`
§ "Execution budget"; continuous with the tool-degradation posture (ADR-003, FR-13).
- **FR-22 — Measure the host, don't guess.** Before any fan-out, probe the host *deterministically* —
  CPU count, free memory, load average — cross-platform (`getconf`/`nproc`/`sysctl`, `free`/`vm_stat`,
  `uptime`); never assume capacity (Policy 5: code answers a deterministic question).
  *VC:* the agent obtains measured cores/free-mem/load before spawning subagents or heavy scanners; its
  plan references those measured values, not assumptions.
- **FR-23 — Bounded concurrency + OOM-safety.** Cap parallelism at `min(cores − headroom, free_mem ÷
  per-task footprint, a hard ceiling)`; treat **each LLM subagent as the heaviest unit**; drop to
  **sequential** under memory/load pressure; never fan out unbounded even when RAM looks free.
  *VC:* a full review on a constrained or already-loaded host runs within the computed cap (or
  sequentially) and never spawns concurrent heavy units beyond it; the host does not OOM-freeze.
- **FR-24 — Execution modes by user intent.** Support **ESSENTIALS/pre-commit** (critical + cheap,
  sequential, fast — for a quick commit), **CRITICAL-ONLY** (high-severity classes, bounded parallel),
  **FULL** (whole loop, all partitions/scanners, cap-bounded), **DEFERRED** (queue heavy scans for
  CI/later, return fast results now).
  *VC:* "essentials" runs only secrets + the diff's high-yield classes, sequentially, in seconds;
  "deferred" returns fast results and lists the queued heavy scans.
- **FR-25 — Plan-and-ask interaction.** When the plan is non-obvious, costly, or host-risky, surface a
  **one-line plan** (measured host capacity + mode options + fan-out width) and let the user choose;
  never silently freeze the host, never silently skip.
  *VC:* on a large scope or constrained host the agent emits a one-line plan with measured capacity +
  mode options before launching, and proceeds on the user's choice or a safe lighter default.
- **FR-26 — Shared budget in team/multi-agent mode.** As a teammate or when spawning helpers, treat the
  resource budget as **shared**: the lead sets the global concurrency ceiling; coordinate, account for
  peers' running work, do not independently fan out.
  *VC:* in team mode the agent's concurrency respects a lead-set ceiling and does not launch heavy units
  that, combined with peers, exceed it.
- **FR-27 — Honest degradation under resource limits.** Any check skipped/deferred under pressure is
  recorded (a skipped/deferred list + reason) with confidence capped; never report a class "clean" that
  was not run — **SKIP ≠ PASS** (continuous with FR-13 / NFR-03 tool-degradation).
  *VC:* a resource-constrained run lists every skipped/deferred check with a reason and caps confidence;
  no skipped class appears as "clean" in the report.

---

## 6. Non-functional requirements (NFR)

Each NFR carries a one-line **Verification criterion (VC)**.

- **NFR-01 — Portability / language-agnostic.** Orchestration is decoupled from language specifics;
  only four things vary per stack: the oracle (what signals a finding), the PoC format, build/run, and
  the in-scope vuln classes.
  *VC:* the same agent + skills run unchanged across TS/Go/Python/Java/AI fixtures; only per-language
  `reference/*.md` and the detect step differ.
- **NFR-02 — Tool-agnostic capability layer.** No hard dependency on any named tool or MCP server;
  capabilities are the durable interface (ADR-015).
  *VC:* `grep`-ing the agent/skills shows tools referenced only as capability-mapped *examples*; no code
  path errors when a named tool is absent.
- **NFR-03 — Graceful degradation.** Always works at the Read/Grep/Glob floor; enhancers are additive
  (ADR-003).
  *VC:* the zero-tool run (FR-13) produces a valid report; degraded findings are honestly marked.
- **NFR-04 — False-positive discipline + confidence gates.** Report only confidence ≥ 0.7; final gate
  HIGH/MEDIUM with confidence ≥ 8/10 and > 80% exploitability; honor the DO-NOT-REPORT exclusion list
  (config-extendable via `config/fp-rules.*`).
  *VC:* a finding below the confidence/exploitability gate or matching an exclusion rule is absent from
  the final report; the exclusion that fired is traceable.
- **NFR-05 — Safety / least-privilege / injection-resistance.** Read-only by default; authorized
  targets only (own working tree/diff); propose-not-push (capability removed, not instructed); treat
  all reviewed content as untrusted; never co-locate untrusted input + secrets + egress (Agents Rule
  of Two); never store credentials in output/logs/tickets/KB.
  *VC:* the agent has no working-tree write / `git apply` capability; the triage decision-maker sees
  only `{file,line,category,diff}`; an injection payload embedded in reviewed code does not alter agent
  behavior; no secret value appears in any artifact.
- **NFR-06 — Self-improvement guardrails.** Identity preservation (edits cannot alter the agent's role/
  guardrail prose); size caps enforced mechanically; confinement of self-writes to KB/registry/memory
  dirs via PreToolUse hooks; human-in-the-loop PR, never autocommit, never the default branch; rejected
  hypotheses logged so losers aren't re-proposed (ADR-004, ADR-005).
  *VC:* a self-write outside the allowed dirs, or one that edits role/guardrail prose, or one exceeding
  a size cap, is blocked at PreToolUse (exit 2); every accepted edit is a PR on a feature branch.
- **NFR-07 — Reproducibility.** Pinned subagent model (dated Opus id); pinned, signature-verified tool
  versions (ADR-006); file-backed checkpointing so long polyglot runs resume; deterministic dedup and
  precondition-counted severity.
  *VC:* re-running a fixture with the same inputs yields the same accepted-finding set and severities;
  tool versions are pinned and verified, not auto-installed from unpinned sources.
- **NFR-08 — Performance / context budget.** Always-loaded surface stays small (progressive
  disclosure); fan-out parallelizes per partition; shard large repos (~40).
  *VC:* the preloaded skill index is ~100 tokens/skill; references load only on demand; a large-repo run
  shards rather than exhausting context.
- **NFR-09 — Auditability / provenance.** KB entries are dated and source-linked; an append-only
  `CHANGELOG.md` + git history + audit log record who/when/why for every change.
  *VC:* every active KB entry has `source`+`url`+`retrieved`; each accepted self-edit appears in the
  changelog/audit log with its motivating evidence.
- **NFR-10 — Anti-drift / freshness.** Fast-tier KB entries carry a `review_by` expiry; a weekly
  passive-drift re-score guards against silent regression from model/provider changes; refresh routines
  touch the fast tier only.
  *VC:* an entry past `review_by` is flagged stale by CI; the weekly re-score runs against the same
  asymmetric thresholds.
- **NFR-11 — Resource safety (OOM avoidance).** The agent must never oversubscribe the host into an
  OOM/freeze; concurrency is bounded by a *measured* cap (FR-22/23) and degrades to sequential/deferred
  under pressure rather than failing the host. Complements NFR-08 — the cap governs the per-partition
  fan-out NFR-08 describes.
  *VC:* on a memory-constrained or already-loaded host, a full review completes without OOM-killing or
  freezing the machine, and observed concurrency never exceeds the computed cap.

---

## 7. Success metrics

| Metric | Target / definition | How measured |
|---|---|---|
| **M1 — False-positive rate** | Final-report FPR ≤ baseline; FPR_gain on any self-edit ≤ 1pp (hard-revert above) | Frozen paired corpus (vulnerable + benign look-alike); Youden's J; paired bootstrap k=3–5 |
| **M2 — Recall on eval corpus** | Severity-weighted recall ≥ baseline; recall_loss on any self-edit ≤ 2pp (hard-revert above) | Same frozen corpus, ≥~100 paired cases incl. CVE regression anchors |
| **M3 — KB freshness** *(target; autonomous arm pending-wiring — wh-hxt.12/.8; RCA §5 RC1)* | 0 active fast-tier entries past `review_by`; refresh routine processes feed deltas on cadence (daily JSON/RSS, weekly blogs, monthly frameworks). **Today the cadence is human-driven, not scheduled** — the staleness check gates, but feed-delta processing only runs when a human invokes `/sec-kb-refresh`. | `staleness_check.py` in CI; `feed-state.json` delta markers |
| **M4 — Triage precision lift** | Adversarial N-of-N verification measurably reduces non-exploitable findings vs. discovery raw count | Compare `VULN-FINDINGS.json` count → accepted `TRIAGE.json` count per run |
| **M5 — Floor value** | Zero-tool run still surfaces true positives on a labeled fixture | Run FR-13 path against the corpus; count caught labeled cases |
| **M6 — Safety** | 0 secret values leaked to any artifact; 0 successful injection-driven behavior changes | Injection-payload fixtures + secret-leak grep over all emitted artifacts |
| **M7 — Self-edit acceptance fidelity** | Human Apply/Edit/Skip decisions agree with the gate's verdict (track toward graduated autonomy) | Audit log review across PRs |
| **M8 — Resource safety** | 0 host OOM-freezes across review runs; observed concurrency ≤ the computed cap | Full reviews on a constrained host / under synthetic load; assert no OOM-kill + cap adherence |

---

## 8. Out of scope (v1)

- Runtime DAST / live pentesting / fuzzing as a default (PoC detonation is opt-in, sandboxed — ADR-007).
- Auto-applying patches or auto-merging KB PRs (graduated autonomy is earned per-step, later — ADR-004 §5).
- Languages beyond TS/Go/Python/Java as first-class (others via the floor + generic core checklist).
- A fixed/curated tool matrix as a requirement (rejected — ADR-015; the registry self-updates instead).
- Model fine-tuning / RLHF / any weight update (NG2).
- Compliance certification, SBOM attestation signing, and ticketing-system integration beyond the
  post-triage P1 ticket hand-off.
- Cross-machine sync of auto-memory (machine-local by design; durable learnings go to the git-tracked KB).
- OS-level resource *enforcement* (cgroups / `ulimit` / `nice`): the concurrency budget is planned from a
  *measured* probe and honored by the agent, not kernel-enforced (v1). A deterministic `resource_probe`
  helper (prints cores/free-mem/load + a suggested cap) is a candidate enhancer for FR-22, not a v1 requirement.

---

## 9. Traceability

| Source of truth | Anchored requirements |
|---|---|
| `docs/ARD.md` ADR-001 (two nested loops) | G1, G2, FR-01..07, FR-16..18 |
| ADR-003 (graceful degradation → extended to compute) | FR-13, FR-27, NFR-03, NFR-11 |
| ADR-004 (self-improvement, human-in-loop) | FR-17, FR-18, NFR-06, §8 |
| ADR-005 (size caps) | FR-19, NFR-06 |
| ADR-006 (tool pinning) | NFR-07 |
| ADR-007 (static-only default) | NG3, §8 |
| ADR-008 (recall/precision separation) | FR-03, FR-04, M4 |
| ADR-009 (one agent + JSON-chained skills) | FR-07, FR-20 |
| ADR-010 (patch by capability-removal) | FR-06, NFR-05 |
| ADR-012 (living KB, dated/sourced) | FR-16, NFR-09, NFR-10 |
| ADR-015 (capability layer, self-updating registry) | NG1, FR-12, FR-14, NFR-02 |
| `plugins/white-hacker/agents/white-hacker.md` (incl. § "Execution budget") | FR-01..27, NFR-04, NFR-05, NFR-11 |
| `docs/research/si-07-threat-feeds.md` | FR-16, M3 |

> Maintenance note: when an ADR changes or a skill is added/renamed, update the matching FR/NFR and
> this table in the same PR. This PRD is the *what/why-for-users* view; `docs/ARCHITECTURE.md` (the
> *how*) and `docs/plan/PLAN.md` (the *build order*) are its companions.
