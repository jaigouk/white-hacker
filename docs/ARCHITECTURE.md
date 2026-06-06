# ARCHITECTURE — white-hacker

> The *what & how* of the white-hacker agent. Companion to `docs/ARD.md` (the *why* —
> ADR-001..015) and `docs/plan/PLAN.md` (the build plan). Living document; maintained, not
> write-once. Today is 2026-06-06.

white-hacker is a **generic, self-improving white-hat security agent** for Claude Code. The
product is not a scanner — it is **two nested loops over plain-text artifacts behind open
interfaces** (Agent Skills, MCP). Specific tools are a swappable capability layer (ADR-015);
the loops are the whole point.

> **Current build state (2026-06-06): Phases 0–3 done (verified).** Built on disk today: the agent
> definition; the inner-loop skill *bodies* for `sec-threat-model`, `sec-detect`, `sec-vuln-scan`
> (discovery/recall incl. SAST+IaC capability selection), `sec-triage` (precision), `deps-scan`
> (SCA capability + Trivy normalizer), and `secrets-scan` (secrets capability + redaction); the
> `_shared/reference/*` content (core-checklist, severity-rubric, exclusion-rules, the four
> `lang-*.md` appendices, `infra.md`, tool-registry) and the real `finding-schema.json`;
> `sec-detect`'s `detect_tools.py` + `scan-plan-schema.json`, the shared `degradation.py` glue, and
> the SCA/secrets normalizers, all with tests (95 tests green); and the `/security-review` command
> wired to run threat-model→detect→discovery→triage→report on the floor. **Still stubs / planned**
> (see `docs/plan/`): `ai-llm-review`, `sec-patch`, `sec-report`, the `ai-attack-kb` entries,
> `.claude/hooks/` scripts, `.claude/settings.json` guardrail wiring, and `evals/`. Sections below
> describe the intended design in present tense — treat anything in the "planned" list as not-yet-built.

- **INNER loop** (per review) — Anthropic's `defending-code-reference-harness` methodology:
  threat-model → discovery (recall) → verification (precision) → triage → patch (+re-attack).
- **OUTER loop** (across reviews / on a schedule) — the Self-Improving Agent Architecture:
  trace → reflect → propose text diffs → gate (eval keep-or-revert) → PR. No retraining — all
  durable learning is a reviewable git diff on the Context/Harness surfaces.

The inner loop **consumes** the knowledge base; the outer loop **edits** it (ADR-001).

---

## 1. The two nested loops

```
                         ┌──────────────────────── OUTER LOOP (self-improvement, ADR-001/004) ─────────────────────────┐
                         │                                                                                              │
                         │   feeds ──► sec-kb-refresh ──► dated KB / tool-registry diffs ─┐                             │
                         │  (OSV/GHSA, ATLAS, OWASP,                                       │                            │
                         │   arXiv, practitioner blogs)                                    ▼                           │
                         │                                                        ┌───────────────┐                    │
                         │                                                        │  GATE          │  keep-or-revert   │
                         │   review traces ──► sec-learn ──► proposed text diffs ─►│  eval corpus  │──► PR (human)      │
                         │  (FPs refuted, misses,            (KB / checklist /     │  (frozen,     │   never auto-merge │
                         │   user corrections)                tool-registry)       │  read-only)   │                   │
                         │                                                        └───────────────┘                    │
                         │            ▲                                                   │                            │
                         └────────────┼───────────────────────────────────────────────  │ ───────────────────────────┘
                                      │ EDITS the KB                          CONSUMES    │ the KB
                                      │                                                   ▼
   ┌────────────────────────────────────────── INNER LOOP (per review, defending-code harness) ───────────────────────┐
   │                                                                                                                   │
   │   threat-model ──► detect ──► discovery (RECALL) ──► verification + triage (PRECISION) ──► report ──► patch       │
   │   THREAT_MODEL.md  SCAN-PLAN  VULN-FINDINGS.json     TRIAGE.json (fresh ctx, adversarial   REPORT.md   PATCHES/   │
   │   (assets, scope,  .json      (partition then        N-of-N, dedup by root cause,          (OWASP IDs) (opt-in,   │
   │    scoring std)               fan-out, find all)      precondition-counted severity)                    re-attack)│
   │                                                                                                                   │
   └───────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

The loops share one substrate: **plain-text files behind stable interfaces.** The inner loop
reads the KB and checklists to do a review; the outer loop rewrites those same files when a
review (or a feed) teaches it something. Because every learning is a text edit gated by an eval
corpus, the system stays auditable, testable, and reversible — and never needs model retraining
(ADR-001, ADR-004).

---

## 2. Learning-surface mapping (Model / Harness / Context → Claude Code primitives)

The Self-Improving Agent Architecture names three learning surfaces. white-hacker maps each to
native Claude Code primitives. **The Model surface is frozen** (we use hosted `claude-opus-4-8`;
there is no fine-tune path, and gradient updates are not reviewable, revertible, or auditable).
All durable learning happens on the Context and Harness surfaces — as git diffs (ADR-004).

| Surface | Holds | Claude Code primitive | Concrete artifact |
|---------|-------|------------------------|-------------------|
| **Context** | *what the agent knows* | Skills + `reference/` (progressive disclosure), per-repo auto-memory | `ai-attack-kb/reference/ai-threats/*.md`, `_shared/reference/*` checklists, `_shared/reference/tool-registry.md`, `~/.claude/projects/<repo>/memory/*` |
| **Harness** | *how it captures signal & enforces guardrails deterministically* | Hooks, `settings.json` permissions, slash commands, scheduled routines | capture hooks (`PostToolUse`/`SessionEnd`), `PreToolUse` guardrails (exit 2 / deny), `/sec-learn` + `/sec-kb-refresh` commands, the cloud kb-refresh routine |
| **Model** | the weights | (frozen — out of scope) | none — retraining rejected (ADR-001) |

Key principle (from the research takeaways): **guardrails belong in the Harness, never in the
Context.** CLAUDE.md and memory are *advisory* — the model may ignore them. Confinement of
self-writes, secret-read blocking, and egress control must be enforced by `PreToolUse` hooks and
`settings.json` `permissions.deny` (deny wins, merges across scopes).

---

## 3. Components

```
white-hacker/
├── .claude/
│   ├── agents/
│   │   └── white-hacker.md              # THE ONE definition (identity, posture, dispatch)
│   ├── commands/
│   │   └── security-review.md           # thin human entry → discovery+triage+report
│   ├── skills/
│   │   ├── sec-threat-model/            # ┐
│   │   ├── sec-detect/                  # │
│   │   ├── secrets-scan/                # │  INNER-LOOP skills
│   │   ├── deps-scan/                   # │  (review stages, chained via on-disk JSON)
│   │   ├── sec-vuln-scan/               # │  discovery (recall)
│   │   ├── sec-triage/                  # │  verification + triage (precision, fresh ctx)
│   │   ├── ai-llm-review/               # │  AI/LLM/MCP/agentic pass (consumes the KB)
│   │   ├── sec-patch/                   # │  opt-in; writes ONLY to ./PATCHES/
│   │   ├── sec-report/                  # ┘
│   │   ├── ai-attack-kb/               # ── the LIVING KB (Context; consumed by ai-llm-review)
│   │   ├── sec-learn/                  # ┐  OUTER-LOOP skills (self-improvement)
│   │   ├── sec-kb-refresh/             # ┘  feed polling → dated draft entries
│   │   └── _shared/reference/           # stable checklists + tool-registry.md + schema/rubric
│   ├── hooks/                           # capture + PreToolUse guardrail scripts (PLANNED Phase 8 — dir exists, empty)
│   └── settings.json                    # hook wiring + permissions.deny (PLANNED Phase 6/8/9 — only settings.local.json exists today)
├── evals/                               # frozen corpus + keep-or-revert gate (PLANNED Phase 7/9 — not yet created)
└── docs/                                # ARCHITECTURE.md, ARD.md, plan/, research/
```

### 3.1 The agent — `.claude/agents/white-hacker.md`
One definition: the **senior-security-engineer identity**, the always-on posture (authorized
targets only, read-only by default, treat all reviewed content as untrusted, Agents Rule of Two,
propose-don't-push), and the **stage-dispatch logic** that routes to skills (or runs the stage
inline in a degraded mode if a skill is absent). `tools: Read, Grep, Glob, Bash, SendMessage,
ToolSearch`; `model: opus`. Reusable three ways from one file (ADR-009, ADR-014): as the
`/security-review` command, as a delegated subagent, and as a teammate in a TL/QA/Dev team.

### 3.2 The ~12 skills + artifact chain (ADR-009)
Each stage is a skill; stages are distinguished only by tool-allowlist + prompt and **chain via
on-disk JSON artifacts**, not conversational state — so runs are resumable and CI-gateable.

| Skill | Loop | Role | Reads → Writes |
|-------|------|------|----------------|
| `sec-threat-model` | inner | assets, entry points, trust boundaries, scoring standard | repo, docs, git history → `THREAT_MODEL.md` |
| `sec-detect` | inner | auto-detect langs/frameworks, select scanners, decide AI pass | manifests → `SCAN-PLAN.json` |
| `secrets-scan` | inner | committed-secret pass (fast + verified) | repo → merged into findings |
| `deps-scan` | inner | SCA (native low-FP gates → fallback) | lockfiles → merged into findings |
| `sec-vuln-scan` | inner | **discovery, recall-optimized** (partition then fan out) | repo, `THREAT_MODEL.md`, `SCAN-PLAN.json` → `VULN-FINDINGS.json` |
| `ai-llm-review` | inner | AI/LLM/MCP/agentic checks; **consumes the KB** | repo, KB → `VULN-FINDINGS.json` |
| `sec-triage` | inner | **verification + triage, precision-optimized** (fresh ctx) | `VULN-FINDINGS.json`, `THREAT_MODEL.md` → `TRIAGE.json` |
| `sec-report` | inner | render to human MD + machine JSON, map to OWASP IDs | `TRIAGE.json` → `SECURITY-REPORT.md` |
| `sec-patch` | inner | opt-in patch ladder + re-attack; **capability-removed writes** | `TRIAGE.json` → `PATCHES/` |
| `ai-attack-kb` | outer/Context | the living KB (loaded on demand during `ai-llm-review`) | — |
| `sec-learn` | outer | reflect on FPs/misses/corrections → propose gated diffs | review traces → branch/PR |
| `sec-kb-refresh` | outer | poll feeds → propose dated KB/registry entries | feeds → branch/PR |

```
sec-threat-model ─► THREAT_MODEL.md
        │
sec-detect ─► SCAN-PLAN.json
        │
        ├─ secrets-scan ───────────────────────┐
        ├─ deps-scan ──────────────────────────┤
        ├─ sec-vuln-scan  (RECALL, fan-out)     ├─► VULN-FINDINGS.json
        └─ ai-llm-review  (if AI/LLM repo) ─────┘     (each finding appears once)
        │
sec-triage  (PRECISION · fresh context · adversarial N-of-N · dedup · severity) ─► TRIAGE.json
        │
sec-report ─► SECURITY-REPORT.md  (+ machine JSON; CI gates on counts.high == 0)
        │
sec-patch  (opt-in) ─► PATCHES/   (build → PoC-stops → tests → re-attack)
```

Invariants: each finding appears exactly once (duplicates reference a canonical id); `sec-triage`
runs in a **fresh context with no shared history** from discovery (ADR-008); `sec-patch` is
**capability-removed**, not instructed (no `git apply`, writes whitelisted to `./PATCHES/`,
ADR-010).

### 3.3 `_shared/reference/` incl. the capability tool-registry
The **stable tier** of the Context surface (yearly cadence): language checklists
(`lang-{go,python,typescript,java}.md`), `ai-llm.md`, `api.md`, `infra.md`, the severity rubric,
exclusion rules, the finding schema, and **`tool-registry.md`** — the capability-layer view of
tools. The registry maps `capability → known tools`, names a zero-install **floor** per
capability, and is explicitly part of the self-improving loop: `sec-learn`/`sec-kb-refresh` add
new tools here as dated diffs, exactly as they add new attack techniques (ADR-015, §7).

### 3.4 The living KB — `.claude/skills/ai-attack-kb/`
The **fast tier** of the Context surface (monthly cadence; ADR-012). Dated, source-linked,
status-tagged (active/archived/deprecated) AI-attack technique entries, one file per
technique-class under `reference/ai-threats/`, loaded by progressive disclosure (≈0 tokens until
`ai-llm-review` triggers it). Each entry fuses Sigma+Semgrep front-matter (typed never-reused
id, `technique_class`, `severity`, `confidence`, `status`, `date`/`modified`/`review_by`,
mandatory `source`+`url`+`retrieved` provenance, `supersedes`, `detections[]`). A blocking
validator refuses to persist an unsourced threat claim. Aging-out moves entries to `archive/`,
never deletes. The KB is **consumed by the inner loop, edited by the outer loop.**

### 3.5 Hooks — capture + PreToolUse guardrails (Harness) — PLANNED (Phase 8; `.claude/hooks/` empty today)
Two distinct roles (ADR-004):
- **Capture (cheap, every session, ~0 LLM cost):** `PostToolUse`/`PostToolUseFailure` append
  each tool call and each failed exploit to JSONL traces; `SessionEnd`/`Stop` log user
  corrections and nudge "save what you learned"; `SessionStart` injects the freshness/CVE digest
  produced by the refresh routine. This is the raw signal `sec-learn` mines.
- **PreToolUse guardrails (enforced, deny wins):** confine self-writes to KB / `_shared/reference`
  / auto-memory; block reads of `**/.env`, `**/secrets/**`, private keys; block network egress
  except allow-listed feed hosts; block any write to the frozen `evals/` corpus or the gate
  script. These are the structural defenses behind §6 — enforced by the Harness, not advised in
  Context.

### 3.6 The scheduled kb-refresh routine
A **cloud Scheduled Routine** (`/schedule`; Anthropic infra, fresh clone, no local machine; min
cadence hourly) that runs `sec-kb-refresh`: poll authoritative feeds (`docs/research/si-07-threat-feeds.md`),
diff incrementally against last-seen markers, LLM-extract NEW techniques, draft dated entries with
provenance, run validate+dedupe, re-gate against the frozen corpus, and **open a draft PR — never
auto-merge.** Touches the **fast tier only** (the single biggest anti-drift rule). This is the
**input arm** that ingests "new ways to hack AI products," covering both *what to look for*
(techniques → KB) and *what to look with* (tools → registry).

### 3.7 The learn loop — `sec-learn`
The reflective COMMIT tier (human-gated). Runs in a forked context as a curator subagent; harvests
the captured traces; for each refuted FP / miss / correction emits **structured textual rationale**
(GEPA/TextGrad signal, not a pass/fail number); applies a pre-gate filter (seen ≥3 sessions, same
fix, 1–2 sentences, system unchanged) and a self-critique step (generalizable, not overfit); then
proposes a **minimal diff** to the KB, a checklist, or `tool-registry.md` — **defaulting to PATCH
over CREATE** to fight index sprawl. Writes to a branch and opens a PR with evidence; **never
writes the live KB and never merges itself.**

### 3.8 The eval corpus + keep-or-revert gate — PLANNED (Phase 7/9; not yet built)
The anti-gaming spine of the outer loop (ADR-004). A **frozen, read-only** corpus of ≥~100 paired
cases — every VULNERABLE case paired with a CLEAN look-alike (the look-alikes drive the
false-positive term that catches FP inflation, the #1 drift mode), plus AI/LLM sinks
(prompt-injection, skill/KB poisoning, excessive agency, insecure output) and real-CVE regression
anchors. The agent **cannot edit the corpus or the gate** (a hook blocks it). Every proposed diff
must pass:

```
HARD REVERT if:  recall_loss > 2pp  OR  FPR_gain > 1pp  OR  any single locked case regresses
KEEP only if:    Youden's J non-inferior  AND ( J improves > 0.01  OR  new sink coverage added )
SECURITY GATE:   severity-weighted recall ≥ baseline  AND  precision ≥ baseline − epsilon
```

The gate is a **guardrail (block regressions), not a benchmark maximizer.** A 3-valued verdict
(Pass/Fail/Inconclusive) from a paired bootstrap (k=3–5 runs/case) tolerates non-determinism. A
**second ratchet** promotes every newly-confirmed true finding into the frozen corpus, so the bar
rises and the KB cannot drift. A weekly full-corpus re-score catches **passive drift** from
model/provider updates, not just agent edits.

---

## 4. Single-review sequence (inner loop)

```
 user / TL / CI                white-hacker agent                     skills (chained via on-disk JSON)
      │                              │                                        │
      │  /security-review  or        │                                        │
      │  subagent / teammate spawn   │                                        │
      ├─────────────────────────────►                                        │
      │                              │  1. threat-model ─────────────────────►│ sec-threat-model
      │                              │◄──────────────────────── THREAT_MODEL.md
      │                              │  2. detect stack ─────────────────────►│ sec-detect
      │                              │◄──────────────────────── SCAN-PLAN.json (langs, scanners, AI pass?)
      │                              │                                        │
      │                              │  3. DISCOVERY (recall) ───────────────►│ sec-vuln-scan + secrets-scan
      │                              │     partition surface, fan out,         │ + deps-scan + ai-llm-review
      │                              │     do NOT self-censor                  │   (ai-llm-review LOADS the KB)
      │                              │◄──────────────────────── VULN-FINDINGS.json (candidates, flagged)
      │                              │                                        │
      │                              │  4. VERIFICATION + TRIAGE (precision) ─►│ sec-triage  ── FRESH CONTEXT
      │                              │     assume each finding is an FP;        │   decision-maker sees ONLY
      │                              │     adversarial N-of-N voting (3);       │   {file,line,category,diff}
      │                              │     dedup by root cause;                 │   (context starvation defeats
      │                              │     precondition-counted severity;       │    injected instructions)
      │                              │     apply exclusion list                 │
      │                              │◄──────────────────────── TRIAGE.json (canonical findings, severities)
      │                              │                                        │
      │                              │  5. report ───────────────────────────►│ sec-report
      │                              │◄──────────────────────── SECURITY-REPORT.md + machine JSON
      │                              │                                        │
      │                              │  6. patch (ONLY if asked) ────────────►│ sec-patch ── writes ./PATCHES/
      │                              │     build → PoC-stops → tests →          │   re-attack with a FRESH agent
      │                              │     re-attack; root-cause + variant hunt │   (no working-tree write)
      │                              │◄──────────────────────── PATCHES/ + verdict
      │◄─────────────────────────────┤  return TRIAGE summary + REPORT path     │
      │  (CI gates on counts.high==0; findings → P1 ticket only AFTER triage)   │
```

Default mode is **static-analysis-only**: no build/run/install/network during scanning (ADR-007).
"No PoC" is weak evidence, not proof of safety; execution-verified PoC detonation is an opt-in,
sandboxed escalation.

---

## 5. Self-improvement data flow (outer loop)

```
   ┌─────────── INPUT ARM (currency) ─────────────┐        ┌──────── REFLECTION ARM (quality) ────────┐
   │                                              │        │                                          │
   feeds (OSV/GHSA · ATLAS · OWASP · arXiv ·       │        │   review run ──► capture hooks ──► traces  │
   embracethered · simonwillison · MS/Google blogs)│        │  (every session)  (PostToolUse,    (JSONL) │
   │                                              │        │                    SessionEnd)            │
   ▼                                              │        │                          │                │
   sec-kb-refresh  (scheduled routine)            │        │                          ▼                │
   • diff incrementally (last-seen markers)       │        │   sec-learn  (/sec-learn, human-gated)     │
   • extract NEW techniques + map to class        │        │   • mine refuted FPs / misses / corrections│
   • draft dated entry (source+url+retrieved)     │        │   • emit textual rationale (not pass/fail) │
   • add NEW TOOLS to tool-registry.md            │        │   • pre-gate filter + self-critique        │
   • validate + dedupe                            │        │   • propose MINIMAL diff (PATCH > CREATE)  │
   └───────────────────────┬──────────────────────┘        └────────────────────┬─────────────────────┘
                           │                                                     │
                           ▼                                                     ▼
                    ┌──────────────────────────── KEEP-OR-REVERT GATE ───────────────────────────┐
                    │   run candidate KB/registry/checklist on the FROZEN eval corpus             │
                    │   asymmetric thresholds (recall/FPR/severity-weighted) · Youden's J         │
                    │   green? → open PR (branch, never default; never auto-merge)                 │
                    │   red?   → log to evals/rejected.md (never re-propose the same loser)        │
                    └─────────────────────────────────────┬───────────────────────────────────────┘
                                                          │ human reviews diff (Apply / Edit / Skip)
                                                          ▼
                    ai-attack-kb/reference/ · _shared/reference/ checklists · tool-registry.md
                                                          │
                                                          ▼  (next review CONSUMES the updated KB)
                                                   INNER LOOP review
```

Two arms feed one gate. The **input arm** keeps the agent *current* (feeds → kb-refresh); the
**reflection arm** keeps the agent *accurate* (review traces → sec-learn). Both produce text
diffs; both pass the same frozen keep-or-revert gate; both end as a human-reviewed PR. The updated
KB is consumed by the next inner-loop review — closing the loop. The registry self-updates the
same way the KB does: tooling knowledge evolves like attack-technique knowledge (ADR-015).

---

## 6. Trust boundaries + agent-as-injection-target defenses

**The reviewer is itself an injection target.** Reviewed code, comments, tickets, model/tool
output, retrieved docs, and even KB text can carry prompt injection (Microsoft's 2026-06-05 PoC
coerced an agent into reading `/proc/self/environ` and exfiltrating `ANTHROPIC_API_KEY`). Trust
boundaries and defenses:

| Boundary | Untrusted side | Defense |
|----------|----------------|---------|
| reviewed content → agent | all code/comments/tickets/model+tool+RAG output, KB text | treat as data, never instructions; posture preamble in the agent definition |
| discovery → triage | finder prose / author rationale | **context starvation** — the decision-maker sees only `{file,line,category,diff}`, never the prose; fresh context, never forked (ADR-008) |
| feeds → KB | feed content (poisonable) | mandatory `source`+`url`+`retrieved`; validate+dedupe; re-gate before proposing; human PR |
| agent → filesystem | self-writes | `PreToolUse` confinement: writes only to KB / `_shared/reference` / auto-memory; never the working tree |
| agent → eval corpus | self-grading | separate identity; hook blocks any agent write to `evals/**` and the gate script |
| agent → network | egress | egress blocked except allow-listed feed hosts (Harness) |

**Agents Rule of Two (ADR-001).** Never simultaneously (a) ingest untrusted input, (b) hold
secrets, and (c) have egress. white-hacker holds at most two of the three at any stage: the
discovery/triage stages ingest untrusted code but have no egress and no secrets; the refresh
routine has egress to feeds but ingests no working-tree secrets.

**Context starvation** is the architectural prompt-injection defense (ADR-008): isolate
source-derived text from the decision-making subagent so an injected instruction can pass neither
the author nor the gate.

**Capability-removal, not instruction (ADR-010).** Structural safety beats a sentence a prompt
injection could override. `sec-patch` has *no* working-tree write / `git apply` capability — it
writes only to `./PATCHES/`. The agent *proposes* fixes; humans apply them. The curator that runs
`sec-learn` has no permission to edit `.claude/rules/` security rules or CLAUDE.md (identity
preservation). Removing the capability is the enforcement; the instruction is just documentation.

---

## 7. The capability / degradation layer (tools are swappable; the floor always works)

Tools are an **implementation detail behind capability interfaces** (ADR-015). The agent depends
on a **capability** — SAST · SCA · secrets · IaC · AI-redteam — never on a brand. **Any named tool
is an illustrative example, not a requirement.**

```
   capability needed (durable interface)
            │
            ▼
   ┌─────────────────────────────────────────────────────────────┐
   │ 1. discover  — detect which tools are installed at runtime    │
   │ 2. map       — match each installed tool to a capability      │
   │               (via _shared/reference/tool-registry.md)        │
   │ 3a. tool present? ── use it (pin version; never auto-install   │
   │                       from unpinned sources — ADR-006)        │
   │ 3b. no tool for a capability? ── DEGRADE to the FLOOR:         │
   │      Read / Grep / Glob heuristic pass scoped to cwd          │
   │      → mark tool_assisted:false, cap confidence,              │
   │        record tools_unavailable[]  (NEVER block — ADR-003)    │
   └─────────────────────────────────────────────────────────────┘
```

| Capability | Floor (always works) | Illustrative tools *today* (examples only) |
|------------|----------------------|--------------------------------------------|
| SAST | Read/Grep/Glob heuristic pass (confidence capped) | a cross-language SAST engine + per-language linters |
| SCA | read manifests/lockfiles, reason from known-bad ranges | native low-FP gates → cross-language SCA fallback |
| Secrets | grep high-entropy + known key patterns | a fast pattern scanner + a live-verification scanner |
| IaC / CI | read Dockerfile/manifests/workflows + `reference/infra.md` | an IaC misconfig scanner + a Dockerfile/Actions linter |
| AI-redteam | static `ai-llm.md` + KB technique patterns over the code | a behavioral LLM red-team runner |

The **floor alone produces value** — built-in Read/Grep/Glob scoped to cwd is a sufficient
read-only scanning scaffold for any language, with zero external tools (ADR-003). Everything above
the floor is an enhancer the agent discovers, never assumes. Crucially, **the registry is part of
the self-improving loop**: there will always be tools we don't yet know, so `sec-kb-refresh` and
`sec-learn` add new tools to `tool-registry.md` as dated, gated diffs — the same mechanism that
adds new attack techniques to the KB (§5, ADR-015). The doc names specific tools only as examples;
the durable thing is the capability + the floor.

---

## 8. Distribution

One definition, three carriers, multiple scopes (ADR-009, ADR-014):

- **Carriers from one file:** `/security-review` slash command · delegated subagent
  (isolated context, summary-only return) · agent-team teammate (TL/QA/Dev + white-hacker).
  Identity comes from the `name` field, not the path.
- **Scopes:** active under this repo's `.claude/` (works here); copy to `~/.claude/` for
  user-scope cross-project reuse; or package as a **plugin**. Project scope only when config is
  repo-specific.
- **Team modes:** *sequential / subagent mode* is the default for side projects — the lead invokes
  white-hacker at the review phase and gets back only the `TRIAGE.json` summary + the
  `SECURITY-REPORT.md` path. *Team mode* is opt-in for adversarial cross-check; route findings to
  the tech-lead via SendMessage.
- **Carry-over caveats:** a subagent's `skills`/`mcpServers` frontmatter does **not** apply on the
  teammate path (teammates load skills/MCP from project+user settings); plugin subagents ignore
  `permissionMode`/`mcpServers`/`hooks`. Put operational detail in the spawn prompt and rely on
  project-scope skills.
- **CI:** the same agent definition backs a CI gate (gates on `counts.high == 0`). Pin the model to
  a dated Opus id, pin the Claude Code package, pin GitHub Actions to commit SHAs and Docker base
  images to digests (ADR-006), and require approval for external contributors (only review the
  developer's own working tree/diff).

---

### ADR cross-reference

| Topic | ADR |
|-------|-----|
| Two nested loops; no retraining | ADR-001 |
| Tool CLI-first, MCP optional (example) | ADR-002 |
| Graceful degradation; never block | ADR-003 |
| Self-improvement on Context+Harness, human-in-loop first | ADR-004 |
| Skill size-cap guardrails | ADR-005 |
| Tool supply-chain pinning | ADR-006 |
| Static-analysis-only default; PoC opt-in | ADR-007 |
| Separate discovery (recall) from triage (precision) | ADR-008 |
| One agent + composable skills chained via JSON | ADR-009 |
| Patch by capability-removal | ADR-010 |
| Cross-language SAST default (example) | ADR-011 |
| Living KB vs stable checklists; dated/sourced | ADR-012 |
| Plan-first process; living docs | ADR-013 |
| Scaffolding under `.claude/`; distribute by copy or plugin | ADR-014 |
| **Tools are a swappable capability layer; registry self-updates** | **ADR-015** |
