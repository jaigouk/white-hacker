# white-hacker

A **generic, self-improving white-hat security agent** for Claude Code. It reviews any
TypeScript / Go / Python / Java repo (backend, frontend, or AI/LLM framework) for **real,
high-confidence, exploitable** findings, composes into a TL/QA/Dev team workflow, and
**keeps its AI-attack knowledge current** over time.

## The concept: two nested loops

The whole design is **two nested loops over plain-text artifacts behind open interfaces**
(Agent Skills, MCP). It rests on **two foundations** — keep both in view:

1. **Anthropic's `defending-code-reference-harness` methodology** — the **INNER review loop**.
   Threat-model → discovery (recall) → verification (precision; fresh context; adversarial
   N-of-N; PoC-driven false-positive reduction) → triage (dedup by root cause;
   precondition-counted severity; exclusion list) → patch (+ re-attack).
2. **The Self-Improving Agent Architecture** — the **OUTER loop**. No retraining: it edits
   *text behind interfaces* across the Model / Harness / Context surfaces. Trace → reflect →
   propose text diffs → gate (eval keep-or-revert, size caps, identity preservation) → PR.

They nest: **the inner loop *consumes* the knowledge base; the outer loop *edits* it.** The
KB-refresh routine is the input arm that ingests "new ways to hack AI products." Canonical
statement: `docs/ARD.md` ADR-001.

```
                       OUTER LOOP  (self-improvement — edits the KB; no retraining)
   trace ─► reflect ─► propose text diffs ─► gate (eval keep/revert, size caps) ─► PR
     ▲                                                                            │
     │   /sec-learn (FPs / misses / corrections)   /sec-kb-refresh (threat feeds) │
     │                                                                            ▼
   ┌──────────────────────────────  KNOWLEDGE BASE  ──────────────────────────────────┐
   │   ai-attack-kb/reference/ (dated, sourced, status-tagged)  +  _shared/reference/ │
   │   + tool-registry.md (tools are knowledge too — the registry self-updates)       │
   └──────────────────────────────────────────────────────────────────────────────────┘
     │                          consumes ▲
     ▼                                   │
   INNER LOOP  (per review — defending-code methodology)
   threat-model ─► discovery (RECALL) ─► verification + triage (PRECISION,
        fresh context, adversarial N-of-N) ─► report ─► patch (+ re-attack, opt-in)
```

Everything else — *especially* specific scanner tools — is secondary and swappable.

---

## What it is

- **One agent** (`plugins/white-hacker/agents/white-hacker.md`, ADR-009): a senior-security-engineer
  identity + stage dispatch. Reusable three ways — as `/security-review`, a delegated
  subagent, and an agent-team teammate — from a single definition.
- **~12 composable skills** (`plugins/white-hacker/skills/`), one per stage, chained via on-disk
  JSON so each runs standalone, resumes after context exhaustion, and is CI-gateable.
- **A living KB** (`ai-attack-kb/reference/`): dated, source-linked, status-tagged AI-attack
  technique entries, progressive-disclosure loaded only when an LLM/agent/MCP repo is reviewed.

**Artifact chain** (the inner loop's plain-text spine):

```
THREAT_MODEL.md → SCAN-PLAN.json → VULN-FINDINGS.json → TRIAGE.json → PATCHES/ → SECURITY-REPORT.md
```

---

## Why

- **Generic.** No language coupling. `sec-detect` fingerprints the stack from manifest files
  and selects scanners; the same find → triage → report → patch loop survives a language port
  unchanged. Only four things vary per stack (the oracle, PoC format, build/run, in-scope classes).
- **Self-improving.** The outer loop edits text behind open interfaces (Context + Harness
  surfaces), not the weights — cheap, testable, reversible. Every change is a reviewable diff
  behind an eval keep-or-revert gate and size caps; never auto-merged (ADR-004). Procedural
  memory lives as progressive-disclosure skills; the KB and the tool registry both self-update.
- **AI-aware.** First-class OWASP **LLM (2025)**, **MCP (beta)**, and **Agentic/ASI (2026)**
  coverage — improper output handling (the highest-yield code check), the lethal trifecta,
  MCP token-passthrough, RAG poisoning, excessive agency, unbounded consumption — grounded in
  the living KB that refreshes from authoritative threat feeds.
- **Disciplined.** Recall and precision are *separate stages* (ADR-008); triage is adversarial
  ("assume false positive"), runs in a fresh context, and the decision-maker sees only
  `{file,line,category,diff}` — context starvation that also defeats prompt injection. The
  agent treats *all* reviewed content as untrusted (Agents Rule of Two) because it is itself
  an injection target.

---

## Quick start

The agent has three carriers, one definition.

**1 — Slash command (human entry point)**

```
/security-review                 # review the current working-tree diff
/security-review path/to/subdir  # audit a target path
```

Runs discovery → triage → report and returns **only triaged findings** (never raw discovery
output) plus the `SECURITY-REPORT.md` path. CI gates on `counts.high == 0`. When installed as a
plugin the commands are namespaced — `/white-hacker:security-review` (see **Install & onboarding**
below); the bare form shown here applies under `--plugin-dir` dev mode or user-scope install.

**2 — Delegated subagent**

```
Use the white-hacker subagent to do a security review of the changes on this branch.
```

It runs the inner loop in an isolated context and returns the `TRIAGE.json` summary +
`SECURITY-REPORT.md` path — a summary, not the transcript.

**3 — On a TL / QA / Dev team** (the main use case — a ticket on a side project)

- **Sequential / subagent mode (default):** the tech-lead invokes white-hacker at the review
  phase, *after* Dev implements and QA tests. Lower token cost; non-collaborative parallel review.
- **Team mode (opt-in):** set `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` (Claude Code ≥ v2.1.32).
  TL = lead; spawns Dev / QA / white-hacker teammates with non-overlapping file ownership.
  white-hacker routes findings to the **tech-lead** (not the dev) via `SendMessage`. Reserve
  for work needing adversarial cross-check. See `docs/plan/PLAN.md` §7.

The agent **proposes** fixes; it **does not push or apply** — the write capability is *removed*,
not merely instructed (ADR-010). Patches land in `./PATCHES/` only.

---

## Capability-based tooling (swappable — not the story)

Tools are an **implementation detail behind capability interfaces** (ADR-015). The agent
depends on a *capability* (SAST · SCA · secrets · IaC · AI-redteam), **never a brand**.

- **Floor (always works):** built-in **Read / Grep / Glob** scoped to cwd — a sufficient
  read-only scaffold for any language. **Zero install; the floor alone produces value.**
- **Discover, map, degrade (ADR-003):** the agent detects which tools are installed at
  runtime, maps each to a capability, and falls back to the floor when a capability has no
  tool — it **never blocks**. Degraded findings are marked `tool_assisted:false` with capped
  confidence, and `tools_unavailable` is recorded in the report.
- **Tools are knowledge too.** The registry is part of the self-improving loop: `sec-learn`
  and `sec-kb-refresh` add newly-discovered tools just as they add new attack techniques —
  *there will always be tools we don't know.*

Examples *today* (illustrative defaults, not requirements): Opengrep (SAST), Trivy /
OSV-Scanner (SCA/IaC), gitleaks / trufflehog (secrets), native gates (govulncheck / pip-audit /
npm audit). Whatever the repo or user already has plugs in behind the same capability — see
**`plugins/white-hacker/skills/_shared/reference/tool-registry.md`** for the full mapping and the rules
(pin versions, never auto-install from unpinned sources, ADR-006).

Default scanning is **static-analysis-only** (ADR-007): no build / run / install / network.
Execution-verified PoC detonation is an opt-in, sandboxed escalation for high-value HIGHs.

---

## Repo layout

The repo root **is** the marketplace; the shipped artifacts live under `plugins/white-hacker/`
(payload), separate from this repo's own thin `.claude/` (dev config). Identity comes from the
agent's `name` field, not the path (ADR-017).

```
white-hacker/                            # repo root == the marketplace
├── .claude-plugin/marketplace.json      # catalog (lists the white-hacker plugin)
├── plugins/white-hacker/                # the shipped plugin PAYLOAD
│   ├── .claude-plugin/plugin.json       # ONLY the manifest lives here
│   ├── agents/white-hacker.md           # the ONE definition (persona, posture, dispatch)
│   ├── commands/security-review.md      # thin /security-review entry point
│   ├── hooks/                           # PreToolUse guardrails + capture + SessionStart-detect
│   └── skills/
│       ├── sec-init/                    # → <repo>/.white-hacker/project-profile.json (onboarding)
│       ├── sec-threat-model/            # → THREAT_MODEL.md (scope + scoring standard)
│       ├── sec-detect/                  # → SCAN-PLAN.json (stack + scanner selection)
│       ├── secrets-scan/  deps-scan/    # → SECRETS.json / DEPS.json
│       ├── sec-vuln-scan/               # discovery — RECALL → VULN-FINDINGS.json
│       ├── ai-llm-review/               # AI/LLM/MCP/Agentic pass (merged into findings)
│       ├── sec-triage/                  # verification + triage — PRECISION → TRIAGE.json
│       ├── sec-report/                  # → SECURITY-REPORT.md + machine JSON
│       ├── sec-patch/                   # opt-in patch ladder → PATCHES/
│       ├── ai-attack-kb/reference/      # living KB (dated, sourced AI-attack entries)
│       ├── sec-learn/  sec-kb-refresh/  # OUTER loop: reflect / refresh feeds
│       └── _shared/reference/           # stable checklists, severity rubric, finding schema,
│                                        #   tool-registry.md (capability → tools)
├── .claude/                             # THIS repo's own dev/dogfood config (thin; NOT shipped)
├── packaging/                           # stdlib manifest/marketplace validator (+ tests)
├── config/                              # custom-scan-instructions + fp-rules examples
├── ci/                                  # security-review.action.yml (pinned model + SHA-pinned)
└── docs/                                # ARD, plan/, research/ (spikes, PoCs, takeaways)
```

---

## Install & onboarding

white-hacker ships as a **Claude Code plugin distributed through a marketplace** (ADR-017,
superseding ADR-014; see `docs/research/spike-07-agent-distribution-and-init-2026-06.md`).
This repo *is* the marketplace: the catalog is `.claude-plugin/marketplace.json` (marketplace
name `white-hacker-marketplace`) and the shipped payload is `plugins/white-hacker/`.

### 1 — Install (end users)

```
/plugin marketplace add jaigouk/white-hacker
/plugin install white-hacker@white-hacker-marketplace
```

The first line registers this GitHub repo as a marketplace; the second installs the
`white-hacker` plugin from it. Once installed, skills are **namespaced** under the plugin:

```
/white-hacker:security-review            # the review entry point
/white-hacker:sec-init                   # per-project onboarding (below)
```

> Fallback (legacy, no marketplace): copy `plugins/white-hacker/{agents,skills,commands,hooks}/`
> into your **user scope** (`~/.claude/`) for cross-project reuse. This is the pre-ADR-017
> model and is no longer the primary path — prefer marketplace install so updates flow through
> `/plugin`.

### 2 — Dev / dogfood loop (no install)

Run the plugin straight from the working tree — no marketplace registration, no copy:

```
claude --plugin-dir ./plugins/white-hacker
```

This is how the repo dogfoods its own agent. The repo's own `.claude/` is *dev* config only
(conventions + agent-memory); the **shipped** behavior all comes from `plugins/white-hacker/`.

### 3 — Project onboarding with `/sec-init`

After install, run once per repository you want to review:

```
/white-hacker:sec-init     # (or /sec-init when run via --plugin-dir)
```

`sec-init` **detects the project** — languages, frameworks, which scanners are installed, and
whether the repo has an AI/LLM/MCP/agentic surface — and writes a **gated, project-scope
companion** at `<repo>/.white-hacker/project-profile.json`. The generic agent *consumes* this
profile to specialize a review (pruned scanner registry, the right language appendices, a
threat-model seed, the scoring standard, and the AI-pass flag) **without ever rewriting the
shipped agent identity** (ADR-004): the profile is factual project context, never imperative
instructions, and `posture`/`tools` keys are schema-rejected.

A project-scope **SessionStart hook** can surface that profile as factual context at the start
of each session (the agent still treats injected content as untrusted). Register it at
**project scope, not plugin scope**, per the Claude Code bug
[anthropics/claude-code#16538](https://github.com/anthropics/claude-code/issues/16538).
As an alternative one-time onboarding carrier, the `claude --init-only` **Setup-hook** path can
run the same detection once at launch instead of via the user-invoked skill.

### Dev (`.claude/`) vs ship (`plugins/white-hacker/`)

| Path | Role | Shipped to users? |
|------|------|-------------------|
| `plugins/white-hacker/.claude-plugin/plugin.json` | the plugin **manifest** (only file under `.claude-plugin/`) | yes |
| `plugins/white-hacker/{agents,skills,commands,hooks}/` | the **payload** — component dirs at the **plugin root** | yes |
| `.claude-plugin/marketplace.json` | the **catalog** (this repo == the marketplace) | yes (resolves the source path) |
| `.claude/` | this repo's **dev/dogfood** config (CLAUDE.md conventions + agent-memory) | **no** |
| `CLAUDE.md` (repo root / `.claude/`) | **dev conventions only** — a plugin-root `CLAUDE.md` is **not loaded** by Claude Code, so identity lives in the agent + skills, not a CLAUDE.md | **no** |

Because a plugin-root `CLAUDE.md` is not loaded, the agent's identity and posture are carried
entirely by `agents/white-hacker.md` + the skills (ADR-017). The repo `CLAUDE.md` is dev-only.

Caveat: a subagent's `skills` / `mcpServers` frontmatter does **not** apply when it runs as a
team teammate (teammates load skills/MCP from project + user settings); plugin subagents ignore
`permissionMode` / `mcpServers` / `hooks`. Put operational detail in the spawn prompt and rely
on project-scope skills. See `docs/plan/PLAN.md` §7.1.

---

## Status

**Phases 0–9 done (verified)** — both loops complete: the inner review loop + team/CI packaging + the
eval baseline, and the outer self-improvement loop with its frozen keep-or-revert gate: `sec-threat-model` + `sec-detect` (real `SCAN-PLAN.json` emitter + schema,
incl. MCP detection) scope and calibrate a review, `sec-vuln-scan` (recall) and `sec-triage`
(precision, adversarial, schema-gated, deduped) split discovery from verification, the **tooling
layer is a swappable capability** (`deps-scan`/`secrets-scan` + SAST/IaC selection) that prefers
installed tools and **degrades to the floor** — never blocking, and `ai-llm-review` consumes the
**living `ai-attack-kb`** (dated, sourced, schema-validated entries) to flag LLM05 sinks /
lethal-trifecta / MCP token-passthrough with `kb_refs` (mapped to OWASP LLM 2025 / Agentic 2026 /
MCP / MITRE ATLAS), and the optional `sec-patch` stage proposes verified, root-cause fixes via the
patch ladder (build → PoC-stops → tests → re-attack) writing **only** to `PATCHES/` for a human to
apply (ADR-010/016; confinement is structural + a PreToolUse tripwire). Phase 6 packages it for
**team mode + CI** (`sec-report` → `SECURITY-REPORT.md`, `ci_gate.py` fail-on-HIGH, a fully-pinned
GitHub workflow running our own `/security-review`, and the `guard_bash`/`gate_review` review-posture
hooks), and Phase 7 stands up the **eval baseline** (a 32-case labeled corpus + a deterministic
`score.py` TPR/FPR/Youden's-J scorer + a recorded `baseline.json` regression gate). Phases 8–9 add the **outer loop**: KB lint/dedup/staleness gates,
the `sec-learn` reflective pass + `sec-kb-refresh` feed poller (both PR-gated, never auto-merge),
deterministic capture + confinement hooks, and the **frozen 103-case corpus + asymmetric
keep-or-revert gate + 10-gate pre-commit checklist** that lets the KB ratchet up without drift.
**373 tests green**; polyglot + SCA + IaC + AI/MCP + patch-ladder + eval runs logged under
`docs/research/` + `evals/`. All ten phases are built:

| Phase | Focus | Status |
|-------|-------|--------|
| 0 | Skeleton: generic persona + `/security-review` (discovery→triage→report on Read/Grep/Glob) | ✅ done |
| 1 | FP discipline + structure: adversarial N-of-N, exclusion list, precondition severity, JSON schema, dedup | ✅ done |
| 2 | Threat-model + detect (per-language `reference/*.md`) | ✅ done |
| 3 | Tool integration: secrets/deps scan, capability discovery, degradation ladder | ✅ done |
| 4 | AI/LLM + API appendices + living `ai-attack-kb` (framework/MCP-triggered) | ✅ done |
| 5 | Patch + re-attack (opt-in, capability-removed writes) | ✅ done¹ |
| 6 | Team mode + CI Action (sec-report, ci_gate, pinned workflow, posture hooks) | ✅ done¹ |
| 7 | Eval baseline (32-case labeled corpus, score.py TPR/FPR/Youden's J, baseline gate) | ✅ done |
| 8 | Self-improvement (KB lint/dedup/staleness, sec-learn, sec-kb-refresh, capture+confine hooks) | ✅ done¹ |
| 9 | Frozen 103-case corpus + keep-or-revert gate + 10-gate pre-commit + drift/ratchet | ✅ done¹ |

¹ Phases 5 & 6 tasks are done + verified; the one shared open item is **activating** the PreToolUse
hooks (`confine_patch_writes`, `guard_bash`, `gate_review`; Phase 8 adds capture + `confine_self_writes`)
+ `permissions.deny` in committed `.claude/settings.json` (ADR-016). Each hook's *logic* is committed +
tested; the *registration* is one self-modifying startup-config write that awaits explicit operator
authorization (batched into a single approval).

Full gap analysis, skill specs, tooling, and rollout: **`docs/plan/PLAN.md`**.

---

## Doc index

| Doc | What it is | Status |
|-----|------------|--------|
| `.claude/CLAUDE.md` | Project conventions + the key concept | Written |
| `.claude/agents/white-hacker.md` | The agent definition — behavior source of truth | Written |
| `docs/ARD.md` | Architecture Decision Records (ADR-001…015) — the *why* | Written |
| `docs/plan/PLAN.md` | Foundation plan: gap analysis, skills, tooling, phased rollout | Written |
| `docs/research/` | Spikes (`spike-01..04`), PoCs (`poc-tool-detection`, `poc-trivy-sca`, `poc-floor-review`, `poc-iac-scan`), foundation (`fnd-*`) + self-improvement (`si-*`) takeaways | Written |
| `docs/PRD.md` | Product requirements (FR/NFR + verification criteria) | Written |
| `docs/DDD.md` | Domain model (ubiquitous language, bounded contexts) | Written |
| `docs/ARCHITECTURE.md` | The *what/how* (companion to ARD) | Written |
| `docs/plan/phase-0..9` | Phased plan, 53 tasks, each with verification criteria | Written |

> This is a **living document** — keep it in sync with the agent definition and the ADRs as
> the rollout progresses. ADRs are append-only; do not contradict them here.
