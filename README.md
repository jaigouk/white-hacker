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

- **One agent** (`.claude/agents/white-hacker.md`, ADR-009): a senior-security-engineer
  identity + stage dispatch. Reusable three ways — as `/security-review`, a delegated
  subagent, and an agent-team teammate — from a single definition.
- **~12 composable skills** (`.claude/skills/`), one per stage, chained via on-disk JSON so
  each runs standalone, resumes after context exhaustion, and is CI-gateable.
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
output) plus the `SECURITY-REPORT.md` path. CI gates on `counts.high == 0`.

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
**`.claude/skills/_shared/reference/tool-registry.md`** for the full mapping and the rules
(pin versions, never auto-install from unpinned sources, ADR-006).

Default scanning is **static-analysis-only** (ADR-007): no build / run / install / network.
Execution-verified PoC detonation is an opt-in, sandboxed escalation for high-value HIGHs.

---

## Repo layout

Artifacts live under `.claude/` so they work *here* (ADR-014); identity comes from the agent's
`name` field, not the path.

```
white-hacker/
├── .claude/
│   ├── agents/white-hacker.md          # the ONE definition (persona, posture, dispatch)
│   ├── commands/security-review.md     # thin /security-review entry point
│   ├── hooks/                          # PreToolUse guardrails + capture (planned)
│   └── skills/
│       ├── sec-threat-model/           # → THREAT_MODEL.md (scope + scoring standard)
│       ├── sec-detect/                 # → SCAN-PLAN.json (stack + scanner selection)
│       ├── secrets-scan/  deps-scan/   # → SECRETS.json / DEPS.json
│       ├── sec-vuln-scan/              # discovery — RECALL → VULN-FINDINGS.json
│       ├── ai-llm-review/              # AI/LLM/MCP/Agentic pass (merged into findings)
│       ├── sec-triage/                 # verification + triage — PRECISION → TRIAGE.json
│       ├── sec-report/                 # → SECURITY-REPORT.md + machine JSON
│       ├── sec-patch/                  # opt-in patch ladder → PATCHES/
│       ├── ai-attack-kb/reference/     # living KB (dated, sourced AI-attack entries)
│       ├── sec-learn/  sec-kb-refresh/ # OUTER loop: reflect / refresh feeds
│       └── _shared/reference/          # stable checklists, severity rubric, finding schema,
│                                       #   tool-registry.md (capability → tools)
├── config/                             # custom-scan-instructions + fp-rules examples
├── ci/                                 # security-review.action.yml (pinned model + SHA-pinned)
└── docs/                               # ARD, plan/, research/ (spikes, PoCs, takeaways)
```

---

## Distribution (ADR-014)

- **Copy to user scope** — `~/.claude/agents/` + `~/.claude/skills/` — for cross-project reuse.
- **Package as a plugin** — same artifacts, distributed as a unit.
- **Project scope** (this repo's `.claude/`) — when the configuration is repo-specific.

Caveat: a subagent's `skills` / `mcpServers` frontmatter does **not** apply when it runs as a
team teammate (teammates load skills/MCP from project + user settings); plugin subagents ignore
`permissionMode` / `mcpServers` / `hooks`. Put operational detail in the spawn prompt and rely
on project-scope skills. See `docs/plan/PLAN.md` §7.1.

---

## Status

**Phases 0–5 done (verified)** — the full inner loop *aims, finds, refutes, tools-up, covers the
AI surface, and remediates* end-to-end: `sec-threat-model` + `sec-detect` (real `SCAN-PLAN.json` emitter + schema,
incl. MCP detection) scope and calibrate a review, `sec-vuln-scan` (recall) and `sec-triage`
(precision, adversarial, schema-gated, deduped) split discovery from verification, the **tooling
layer is a swappable capability** (`deps-scan`/`secrets-scan` + SAST/IaC selection) that prefers
installed tools and **degrades to the floor** — never blocking, and `ai-llm-review` consumes the
**living `ai-attack-kb`** (dated, sourced, schema-validated entries) to flag LLM05 sinks /
lethal-trifecta / MCP token-passthrough with `kb_refs` (mapped to OWASP LLM 2025 / Agentic 2026 /
MCP / MITRE ATLAS), and the optional `sec-patch` stage proposes verified, root-cause fixes via the
patch ladder (build → PoC-stops → tests → re-attack) writing **only** to `PATCHES/` for a human to
apply (ADR-010/016; confinement is structural + a PreToolUse tripwire). 136 tests green; polyglot +
SCA + IaC + AI/MCP + patch-ladder runs logged under `docs/research/`.
The remaining skills are stubs; the rest lands over the rollout:

| Phase | Focus | Status |
|-------|-------|--------|
| 0 | Skeleton: generic persona + `/security-review` (discovery→triage→report on Read/Grep/Glob) | ✅ done |
| 1 | FP discipline + structure: adversarial N-of-N, exclusion list, precondition severity, JSON schema, dedup | ✅ done |
| 2 | Threat-model + detect (per-language `reference/*.md`) | ✅ done |
| 3 | Tool integration: secrets/deps scan, capability discovery, degradation ladder | ✅ done |
| 4 | AI/LLM + API appendices + living `ai-attack-kb` (framework/MCP-triggered) | ✅ done |
| 5 | Patch + re-attack (opt-in, capability-removed writes) | ✅ done¹ |
| 6 | Team mode + CI Action | next |
| 7 | Eval (ongoing — validate against a labeled finding set, track FP rate) | planned |

¹ Phase 5 tasks T-5.1…T-5.4 are done + verified; the only open item is **activating** the
`confine_patch_writes` PreToolUse hook + `permissions.deny` in committed `.claude/settings.json`
(ADR-016) — that write is self-modifying startup config, so it awaits explicit operator authorization.

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
