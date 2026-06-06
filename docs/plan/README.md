# white-hacker — Phased Plan (index)

> **Status:** living. Date: 2026-06-06. Owner: ping@jaigouk.kim.
> This directory is the **executable** plan. `PLAN.md` stays the **master narrative**
> (gap analysis, architecture, tool strategy, checklist structure, rollout) and is the
> source of section references below. `docs/research/si-08-design-synthesis.md` is the
> companion narrative for the self-improvement layer. **Do not contradict `docs/ARD.md`**
> (ADR-001..015) — every task here is downstream of an accepted ADR. In particular,
> ADR-015 governs every tool task: depend on a **capability** (SAST · SCA · secrets · IaC ·
> AI-redteam), never a brand; tasks read "wire capability X + degradation", not "install tool Y".

The work is split into **two nested loops** (ADR-001):

```
INNER LOOP (per review — Phases 0..5)        OUTER LOOP (self-improvement — Phases 8..9)
threat-model ─► discovery(recall) ─►         trace ─► reflect ─► propose text diffs ─►
verification/triage(precision) ─► report ─►  gate(eval keep-or-revert) ─► PR
patch(+re-attack)                            (Context + Harness surfaces; no retraining)
        │                                            ▲           │
        └────────── consumes the KB ─────────────────┘           └──── edits the KB
```

Phase 6 (team mode + CI) and Phase 7 (eval baseline) bridge the loops; Phases 8–9 are the
self-improvement build. The KB-refresh routine is the **input arm** that ingests "new ways
to hack AI products" (`docs/research/si-07-threat-feeds.md`).

---

## Phases

| Phase | File | Theme | Maps to |
|-------|------|-------|---------|
| 0 | [`phase-0-skeleton.md`](phase-0-skeleton.md) | Skeleton: generic agent + `/security-review` running discovery→triage→report on Read/Grep/Glob | PLAN §8.1 P0, §5.1, §7.4 |
| 1 | [`phase-1-fp-discipline.md`](phase-1-fp-discipline.md) | FP discipline + structure: `sec-triage`, exclusion list, precondition severity, strict JSON schema, dedup | PLAN §8.1 P1, §6 |
| 2 | [`phase-2-threat-model-detect.md`](phase-2-threat-model-detect.md) | `sec-threat-model` + `sec-detect` + per-language `reference/*.md` | PLAN §8.1 P2, §3, §5.2 |
| 3 | [`phase-3-tooling.md`](phase-3-tooling.md) | `secrets-scan`, `deps-scan`, Opengrep pass, Trivy CLI (+optional MCP), degradation ladder | PLAN §8.1 P3, §4 |
| 4 | [`phase-4-ai-llm-api.md`](phase-4-ai-llm-api.md) | `ai-attack-kb` (stable seed) + `ai-llm-review` + `reference/ai-llm.md` + `reference/api.md` | PLAN §8.1 P4, §5.3, §5.4; ADR-012 |
| 5 | [`phase-5-patch-reattack.md`](phase-5-patch-reattack.md) | `sec-patch` ladder, capability-removed writes to `PATCHES/`, variant hunt | PLAN §8.1 P5 |
| 6 | [`phase-6-team-ci.md`](phase-6-team-ci.md) | Team mode spawn prompts, gate hooks, CI GitHub Action | PLAN §8.1 P6, §7 |
| 7 | [`phase-7-eval-baseline.md`](phase-7-eval-baseline.md) | Labeled finding set; FP-rate tracking before each release | PLAN §8.1 P7 |
| 8 | [`phase-8-self-improvement.md`](phase-8-self-improvement.md) | KB structure & lint; `sec-learn` reflective loop; `sec-kb-refresh` feed poller; capture hooks | si-08 §1–§5; ADR-004/005/012 |
| 9 | [`phase-9-eval-guardrails.md`](phase-9-eval-guardrails.md) | Frozen eval corpus; keep-or-revert gate; `PreToolUse` confinement guardrails; passive-drift re-score | si-08 §6, §3.4, §5.2; ADR-004 |

**Ordering note.** Phases 0–5 are the inner loop and ship value first (Phase 0 alone beats
the legacy single-pass Go agent on any language). Phase 7 stands up a *minimum* eval baseline
for inner-loop releases; **Phase 9 hardens it into the frozen keep-or-revert corpus** that the
outer loop (Phase 8) requires. Therefore: **Phase 9's corpus + gate must exist before any
`sec-learn`/`sec-kb-refresh` change is allowed to merge** (si-08 §7: "nothing graduates to
autonomy until [the corpus] exists"). Build order for the outer loop is **8 (capture+structure)
→ 9 (gate) → graduated autonomy**, but the two phase files cross-reference and may be built in
parallel up to the merge gate.

---

## How status works

Each task carries a **`Status:`** field. The lifecycle is:

```
todo ──► in-progress ──► blocked(<T-id>) ──► done
```

- **`todo`** — not started.
- **`in-progress`** — actively being built.
- **`blocked(T-x.y)`** — cannot proceed until the named task is `done`.
- **`done`** — **only** when *every* checkbox under **Verification criteria** is demonstrably
  checked off (tests pass, eval green, lint passes, scanner clean on fixture, schema validates,
  doc updated). This mirrors `.claude/CLAUDE.md` "Working rules" and ADR-013: a task is `done`
  only when its criteria are met, not when code merely exists.

Editing rules:
- Flip a task to `done` by checking **all** its boxes and changing `**Status:** todo` →
  `**Status:** done`. Leave the checkboxes visible (auditable history).
- If a verification command changes, update it in place — this is a **living** document.
- New tasks append with the next `T-<phase>.<n>` id; never renumber existing tasks (ids are
  referenced by `Depends on:`). This mirrors the KB's "typed, never-reused IDs" discipline
  (ADR-012 / si-08 §2.2).

---

## Task-block template (use EXACTLY this shape)

```markdown
### T-<phase>.<n> · <task name>
- **Goal:** one sentence — what this task makes true.
- **Artifact:** the file(s) created/edited (absolute or repo-relative paths).
- **Depends on:** T-x.y, T-x.z (or — if none).
- **Verification criteria:**
  - [ ] objective, runnable check #1 — `the command to run`
  - [ ] objective, runnable check #2 — `the command to run`
- **Status:** todo
```

**What makes a verification criterion valid** (every box must satisfy all three):
1. **Objective** — pass/fail is unambiguous, not a judgement call.
2. **Runnable** — names the exact command (or the exact file/line condition) a reviewer runs.
3. **Tied to the artifact** — proves *this* task's artifact, not a neighbour's.

Conventions for the commands:
- Python executables (skill `scripts/`, hooks, eval runner, feed poller) run via **`uv run pytest`**
  / **`uv run python`** per `.claude/CLAUDE.md`; TDD — failing test first, **>1 test**, edge cases
  (ADR-013). Each `scripts/` package gets a colocated `pyproject.toml` so `uv` can resolve it.
- Skill front-matter caps are checked by `lint_skill` (ADR-005: `description`+`when_to_use`
  ≤ 1,536 chars; `description` ≤ 1,024; `name` ≤ 64; `SKILL.md` < 500 lines; `reference/`
  one level deep). Built in T-8.1.
- JSON artifacts validate against `_shared/reference/finding-schema.json` (built in T-1.1) via a
  schema-check command.
- Scanner-on-fixture checks use the PoCs already on disk
  (`docs/research/poc-tool-detection/`, `docs/research/poc-trivy-sca/`) as ready fixtures.

---

## Real artifacts this plan builds on (already scaffolded under `.claude/`)

All skills below exist as **stubs** (front-matter + a shared "Verification criteria" contract +
a `STATUS: STUB` banner). Phases fill in the body, `scripts/`, and `reference/`:

- **Agent:** `.claude/agents/white-hacker.md` (already the full generic identity — Phase 0 wires
  the command to it).
- **Command:** `.claude/commands/security-review.md` (stub).
- **Inner-loop skills:** `sec-threat-model`, `sec-detect`, `secrets-scan`, `deps-scan`,
  `sec-vuln-scan`, `sec-triage`, `sec-report`, `sec-patch`, `ai-llm-review`.
- **Outer-loop skills:** `ai-attack-kb` (+ `reference/{prompt-injection,tool-poisoning,`
  `rag-poisoning,excessive-agency,data-exfil}.md`), `sec-learn`, `sec-kb-refresh`.
- **Shared reference (stubs, 3 lines each):** `_shared/reference/{core-checklist,severity-rubric,`
  `exclusion-rules,lang-go,lang-python,lang-typescript,lang-java,ai-llm,api,infra}.md` +
  `finding-schema.json`.
- **Empty dirs awaiting content:** `.claude/hooks/` (Phase 6 + Phase 9), `config/` has
  `fp-rules.example.md` + `custom-scan-instructions.example.md`, `ci/security-review.action.yml`
  (stub, Phase 6), no `evals/` yet (Phase 7/9 creates it).
- **`.gitignore`** already excludes the artifact chain (`THREAT_MODEL.md.bak`, `SCAN-PLAN.json`,
  `VULN-FINDINGS.json`, `TRIAGE.json`, `SECRETS.json`, `DEPS.json`, `SECURITY-REPORT.md`,
  `PATCHES/`, `.triage-state/`, `.patch-state/`, `*.sarif`) and `.notes/`.

> **Layout reconciliation (important).** The on-disk KB uses `ai-attack-kb/reference/` (singular,
> one level deep) per **ADR-012**. The si-08 design proposed `references/ai-threats/` + a separate
> `checklists/` tier. This plan keeps the **on-disk `reference/` path** as authoritative and folds
> the si-08 *two-tier idea* (fast AI-threat tier vs. stable checklist tier) into that path: stable
> checklists stay in `_shared/reference/` (web/CWE — yearly cadence), the fast AI-threat tier stays
> in `ai-attack-kb/reference/` (monthly cadence, refresh routine scoped here only). See T-8.2.
