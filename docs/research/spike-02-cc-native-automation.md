# Spike S-02 — Can Claude Code run the self-improvement outer loop natively?

- **Status:** ✅ RESOLVED (feasible; start human-in-loop)
- **Date:** 2026-06-06
- **Confidence:** High for the primitives; Medium for fully-unattended autonomy

## Question / assumption

The self-improvement design needs: (a) capture review traces/feedback, (b) a
reflection pass that proposes KB/checklist edits, (c) a scheduled refresh that
polls AI-threat feeds, (d) guardrails, all as **reviewable diffs**. Can Claude
Code do this with native primitives, or does it need an external runtime?

## Evidence (verified)

| Need | Native primitive | Verified by |
|---|---|---|
| Living KB w/ progressive disclosure | **Skills** (`SKILL.md` + `reference/`, body+refs load on demand) | [skills docs](https://code.claude.com/docs/en/skills) |
| Agent self-maintained memory | **Auto memory** (`MEMORY.md` index + topic files, Claude writes it) | [memory docs](https://code.claude.com/docs/en/memory); in use this session |
| Reflective consolidation | **`consolidate-memory`** skill (merge dups, fix stale, prune index) | present in this session's skill list |
| Deterministic capture | **Hooks** PostToolUse / Stop / SessionStart / PreCompact | [hooks docs](https://code.claude.com/docs/en/hooks) |
| Hard guardrails | **PreToolUse hook** (exit 2 / deny) + `settings.json` permissions | hooks docs ("to block regardless of what Claude decides, use a PreToolUse hook") |
| Scheduled autonomous refresh | **`schedule`** skill / routines (cron remote agents) | present in this session's skill list |
| Recurring polling | **`loop`** skill (interval or self-paced) | present in this session's skill list |
| Manual trigger | **slash command / skill** (`/sec-learn`, `/sec-kb-refresh`) | skills docs |
| Reviewable diffs | git branch + PR via `gh` (the review/keep-or-revert gate) | standard |

## Decision

- The outer loop is **implementable natively** — no external orchestrator required.
- **Map to surfaces:** Context = KB/checklist/skill edits; Harness = hooks +
  settings + scheduled routine. Model retraining stays out of scope.
- **Start human-in-the-loop, graduate autonomy:**
  - v1: `/sec-learn` (manual) proposes KB/checklist diffs from recent sessions;
    `/sec-kb-refresh` (manual) polls feeds → proposes dated KB entries. Human
    approves the PR.
  - v2: schedule `/sec-kb-refresh` as a routine (e.g. weekly) that opens a PR for
    human review — never auto-merges.
  - v3 (optional): autonomous keep-or-revert gated by the eval corpus (S-05),
    still PR-based.
- **Guardrail placement:** enforce size caps / write-scope with a **PreToolUse
  hook** (Harness), because memory/skills are *context, not enforced config*.

## Residual uncertainty

- Exact degree of unattended PR creation by a scheduled routine depends on the
  routine's permissions/environment. → Keep the human-approval gate for v1–v2;
  treat full autonomy as a later, separately-verified step.
- Auto-memory's exact min version / default-on status was a single-source research
  claim — not load-bearing here (we rely on explicit skills + hooks we control).

→ Feeds **ADR-004** (self-improvement on Context+Harness surfaces, human-in-loop first).
