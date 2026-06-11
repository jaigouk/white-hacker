---
name: handoff
description: Write an end-of-wave handoff to .notes/handoff-<slug>.md — the team's record (tickets, files, findings, follow-ups, next entry point) PLUS a retro that feeds the outer-loop self-improvement
allowed-tools: Bash, Read, Grep, Glob, Write, SendMessage
---

# /handoff <slug>

Write a session-summary handoff to `.notes/handoff-<slug>.md`. This is **Phase 7 of `/launch-team`**
— the last checkpoint of a multi-agent wave — but it also works for a solo session. The handoff is
the team's shared record, not one agent's notes: it captures what every teammate reported over
`SendMessage`, so the next session resumes without re-reading the transcript. It ALSO carries a
**Retro** — what to improve in the tickets / templates / agents / skills — so each wave feeds the
project's outer-loop self-improvement (`/sec-learn`).

## When to Use

- **End of a team wave** — the **tech-lead** runs this after Phase 6 (`bd close`), having collected
  each teammate's final report.
- **End of a solo session** — run it yourself as the "Hand off" step.

## Slug

- Single-ticket wave → the ticket ID (`wh-k6l`).
- Multi-ticket wave → a short wave name (`batch-1`, `wave-b1-hades`, `epic-wh-5ox`).

Output path is always `<repo-root>/.notes/handoff-<slug>.md`.

> **`.notes/` is gitignored and LOCAL-ONLY for a reason** — a handoff records machine paths, the tool
> inventory, gate output, and internal posture. It must NEVER be committed or moved under `docs/`. Keep
> it repo-relative where you can, but it is the one place machine detail may appear (it never leaves the
> host). Do NOT echo secrets/tokens.

## Process

### Step 1 — Collect the Team's Record

The team communicates via `SendMessage` (routing from the launch prompt): devs report **completion**
to qa-engineer + white-hacker; QA + white-hacker report **findings** to the tech-lead; the TL
**triages** and assigns fixes; fix rounds loop dev ↔ QA/WH (max 3/issue).

The TL running `/handoff` already holds these in context. If any report is missing, `SendMessage` the
teammate for a one-line final status BEFORE writing — do not invent outcomes. For each teammate capture:
- **dev-<id>** — what was implemented, RED/GREEN/REFACTOR done, the per-package gate it self-verified, test-count delta.
- **qa-engineer** — tiers run (unit/artifact/live/adversarial) + BICEP edges, findings, verdict (PASS / open).
- **white-hacker** — security surface reviewed (the **dogfood** on our own diff), findings, verdict.
- **tech-lead** — triage decisions, fix rounds spent (N/3), final gate result.

If run solo, collapse these into your own record of what you did and verified.

### Step 2 — Gather Hard Facts (don't rely on memory)

```bash
SLUG="<slug>"
# Tickets in this wave — status + close reason
bd show <each-ticket-id>
# What actually changed
git diff --stat HEAD
git status --short
# Per-package gate (only if not already run this turn) — the REAL gates, NOT ruff/mypy/coverage
nice -n 10 uv run --project plugins/white-hacker/skills/<skill>/scripts --with pytest \
  pytest plugins/white-hacker/skills/<skill>/scripts/tests -q 2>&1 | tail -5
uv run python packaging/validate_manifest.py .
claude plugin validate ./plugins/white-hacker
# Follow-ups filed during the wave (route them through /design-ticket — launch-team Rule 8)
bd list --status open | grep -iE "<relevant keywords>"
```

Cite real paths, line counts, and ticket IDs — no placeholders.

### Step 3 — Write `.notes/handoff-<slug>.md`

Use the Write tool with the template below. Fill EVERY section with real data. **One file per wave** —
overwrite if re-run; don't fork copies.

### Step 4 — Report

Print the absolute path of the saved file and a 2-line summary (tickets closed, next entry point) so
the user sees it without opening the file. Surface the Retro's top improvement explicitly.

## Handoff Template

```markdown
# Handoff — <slug>

> **Date:** <YYYY-MM-DD> · **Wave:** <ticket-id(s)> · **Author:** <tech-lead | solo>
> **HEAD:** <sha> · **Status:** <COMPLETE | PARTIAL — see Unresolved>
> Local-only (`.notes/`, gitignored). Source of truth = beads + git. **Git is operator-gated** —
> the team commits/pushes nothing.

## Tickets

| Ticket | Title | Status | Close reason |
|---|---|---|---|
| <id> | <title> | <closed / in_progress / blocked> | <reason or "open: ..."> |

## What Shipped

- <one bullet per ticket: the actual behavior change, in domain terms>

## Files Changed

| File | Package/Layer | +/− | Note |
|---|---|---|---|
| <repo-relative path> | <skill / hooks / _shared / evals / docs> | <+N/−M> | <what changed> |

Test-count delta: <before> → <after> (+<N>).

## Team Record (SendMessage outcomes)

| Role | Reported | Verdict |
|---|---|---|
| dev-<id> | <impl summary, package gate self-verified> | <done> |
| qa-engineer | <tiers + BICEP edges checked, findings> | <PASS / open> |
| white-hacker | <dogfood security surface, findings> | <CLEAN / open> |
| tech-lead | <triage, fix rounds N/3, final gates> | <closed / escalated> |

## Quality Gates (final — the REAL gates, NOT ruff/mypy/coverage)

- [ ] Per touched package: `uv run --project plugins/white-hacker/skills/<skill>/scripts --with pytest pytest …/tests -q` — <PASS/FAIL, count>
- [ ] `uv run python packaging/validate_manifest.py .` — <PASS/FAIL>
- [ ] `claude plugin validate ./plugins/white-hacker` — <PASS/FAIL>
- [ ] Outer-loop edits (KB/registry/eval): `evals/score.py` + `evals/keep_or_revert.py` — <PASS / N/A>

## Unresolved / Risks

- <open findings not fixed this wave: severity + why deferred>
- <fix rounds that hit the 3/issue cap and were escalated>
- <documented residuals (ADR-016 tripwire-class): name them — honest, no false-green>

## Follow-ups Filed

- <bd-id> — <title> (filed via `/design-ticket --type=<…>` — launch-team Rule 8; NOT an ad-hoc bd create)

## Retro — process improvement (feeds the outer loop)

The wave's lessons, so the next one is smoother and the agent/templates/skills get better. Be specific
and actionable — a vague "went well" helps nobody. This is a structured trace for `/sec-learn`.

### What worked (keep doing)
- <a template / command / agent behavior that measurably helped — e.g. "groom caught the stale path before launch">

### Friction (what slowed us or nearly broke)
- <stale ticket needing re-groom · missing/wrong template section · ambiguous or flaky gate · coordination
  gap · a missing tool · an ambiguous AC · a dev blocked on a file outside its ownership>

### Improvements to make (actionable — where + action)
| # | Improvement | Where (file / command / agent / skill) | Action |
|---|---|---|---|
| 1 | <e.g. groom didn't flag X> | `.claude/commands/groom.md` | filed wh-… / edited |

### Dogfood signal (the shipped white-hacker on our own diff)
- <what the product found reviewing OUR code; a product GAP is fixed IN the product, never forked (ADR-029)>
- <feeds `/sec-learn` (FPs/misses → KB/skill diffs) and `/sec-kb-refresh` (new techniques/tools)>

## Next-Session Entry Point

- <the now-unblocked successor ticket, or the next logical step>
- Resume: `bd ready` · `bd show <next-id>` · `/groom <next-id>` · `/launch-team <next-id>`
- Git: NOT committed/pushed — **operator-gated** (the operator reviews + commits).
```

## Rules

1. **Facts over memory.** Every ticket status, file path, and line count comes from `bd show` / `git diff --stat`, not recollection.
2. **Capture the team, not just yourself.** The Team Record reflects actual `SendMessage` reports. If one is missing, ask for it before writing.
3. **The Retro is mandatory and actionable.** A handoff with an empty or hand-wavy Retro is incomplete — name a concrete improvement and where it lands. The Retro is how a wave improves the next wave (outer loop).
4. **No silent skips (Policy 12).** If a gate FAILED or a test was SKIPPED, say so plainly and set Status `PARTIAL` — never report green when it isn't. SKIP is never PASS.
5. **Name the next step.** A handoff with no "Next-Session Entry Point" is incomplete. For a blocking chain, name the ticket the just-closed work unblocked.
6. **Operator-gated git.** The handoff records git state; it NEVER commits/pushes (`.claude/CLAUDE.md`; the operator owns git).
7. **One file per wave; `.notes/` only.** Overwrite `.notes/handoff-<slug>.md` if re-run. Never commit it, never move it under `docs/` (it leaks machine/posture detail).

## References

- [`.claude/commands/launch-team.md`](launch-team.md) — Phase 7 invokes this; the SendMessage routing the Team Record reflects
- [`.claude/commands/design-ticket.md`](design-ticket.md) — how follow-ups in this handoff must be filed (templates, not ad-hoc)
- `plugins/white-hacker/skills/sec-learn/` — the outer-loop reflection arm the Retro feeds (FPs/misses → proposed text diffs, gated)
- `.claude/CLAUDE.md` § QA flow / Security posture — dogfood, no-machine-data-in-committed-files, operator-gated git
