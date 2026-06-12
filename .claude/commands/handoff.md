---
name: handoff
description: Write an end-of-wave handoff to .notes/handoff-<slug>.md — the team's record (tickets, files, findings, follow-ups, next entry point) PLUS a retro that drives the operator-gated PROCESS self-improvement of our .claude/agents, commands, templates, and gates
allowed-tools: Bash, Read, Grep, Glob, Write, SendMessage
---

# /handoff <slug>

Write a session-summary handoff to `.notes/handoff-<slug>.md`. This is **Phase 7 of `/launch-team`**
— the last checkpoint of a multi-agent wave — but it also works for a solo session. The handoff is
the team's shared record, not one agent's notes: it captures what every teammate reported over
`SendMessage`, so the next session resumes without re-reading the transcript. It ALSO carries a
**Retro** — what to improve in our `.claude/agents/*` role profiles, the `.claude/commands/*`, the
ticket templates, and the gates — so each wave drives the team's **operator-gated PROCESS
self-improvement** (root `CLAUDE.md` § Self-improvement loop). That is a DIFFERENT loop from
`/sec-learn` (the shipped reviewer's KB, which is hard-confined out of process artifacts) — see the
Retro section for the routing.

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

### Step 4 — Verify the Retro (grounding gate — do this BEFORE you finalize)

The writer is the one who hallucinates, so treat the Retro adversarially — this is a deliberate second
pass, not a re-read of your own prose. For **EACH Improvement row**:

1. **Open the `file:line` in its "Where" column** and confirm it EXISTS and actually says what the row
   assumes. Read the surrounding construct (the function / hook / gate / ADR), not just the one line.
2. **Confirm the proposed change does not contradict** the hook / gate / contract / convention living
   there. A fix a PreToolUse hook would block, or one an ADR already settled the other way, is not an
   improvement.
3. **If the item rests on an UNTESTED assumption** — a tool's behavior, a hook's firing scope, a
   convention nobody ran — you CANNOT verify it by reading. Do NOT record it as an Improvement; convert it
   to a **spike question** and file it via `/design-ticket --type=spike`.
4. **Annotate the row's verification** on the template's **"Retro verified (Step 4)"** line — the
   `file:line` you re-read + what it confirmed (or `row N → spike <id>`). A row with no annotation is not
   done. For a load-bearing process change, prefer an INDEPENDENT check (a fresh-context agent or the
   operator), not only your own re-read.

A Retro still carrying an unverified Improvement row is INCOMPLETE (Policy 12 — a skipped check is not a
pass): verify it, drop it, or downgrade it to a spike before Step 5. (This gate exists because a past wave
recorded a `--plugin-dir` "dogfood" item that one read of
`plugins/white-hacker/hooks/confine_self_writes.py:48` would have refuted.)

### Step 5 — Report

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

## Retro — team & process self-improvement (operator-gated)

The wave's lessons, so the next one is smoother and our **agent profiles / commands / templates / gates**
get better. Be specific and actionable — a vague "went well" helps nobody. Route by target:
- **Process-artifact items** (`.claude/agents/*`, `.claude/commands/*`, `docs/beads_templates/*`, a gate)
  go to the **operator-gated process loop** (root `CLAUDE.md` § Self-improvement loop): the tech-lead
  proposes the exact edit and WAITS for operator confirmation — **NOT `/sec-learn`**, which can only edit
  the shipped reviewer's KB/checklists and is structurally blocked from `.claude/`.
- **Reviewer FP/miss/technique signals** from the dogfood go to `/sec-learn` (see Dogfood signal below).

### What worked (keep doing)
- <a template / command / agent behavior that measurably helped — e.g. "groom caught the stale path before launch">

### Friction (what slowed us or nearly broke)
- <stale ticket needing re-groom · missing/wrong template section · ambiguous or flaky gate · coordination
  gap · a missing tool · an ambiguous AC · a dev blocked on a file outside its ownership>

### Improvements to make (actionable — owner + action)
Each item carries an **Owner** = who applies it. Role profiles, commands, templates, and gates change
ONLY via the operator (the tech-lead proposes; root `CLAUDE.md` § Self-improvement loop). The tech-lead
may add a test/gate probe directly.

**Ground every item before you write it (Policy 8 — read before you conclude).** A retro improvement is a
*claim*, not a hunch: VERIFY it against the artifact it names BEFORE recording it — read the `file:line` the
fix would touch and confirm the fix doesn't contradict an existing hook / gate / contract / convention. Put
that `file:line` in the **Where** column. An item written from memory ("we should load X" / "we should add
Y") that you have NOT checked is a **hallucinated retro item** — a process defect, held to the same bar as an
uncited "verified" on a ticket. If you can't verify it in-session, file it as a **spike question**, not an
Improvement row. (Worked failure: a `--plugin-dir` "true dogfood" item that, unchecked, would have blocked the
wave's own edits — `confine_self_writes` (`plugins/white-hacker/hooks/confine_self_writes.py:48`) denies every
Write/Edit outside the KB lane; reading the hook catches it before it's recorded.)

| # | Area | Improvement | Where (file) | Owner | Action |
|---|---|---|---|---|---|
| 1 | Agent profile | <e.g. TL broadcast contracts late, devs idled> | `.claude/agents/tech-lead.md` | operator | TL proposes edit → operator confirms |
| 2 | Workflow command | <e.g. groom didn't flag X> | `.claude/commands/groom.md` | operator | TL proposes edit → operator confirms |
| 3 | Quality gate | <e.g. an edge case slipped the gate> | <gate / test path> | tech-lead | add the BICEP case / a new probe |

**Top improvement (do this first):** <the single highest-leverage change>

**Retro verified (Step 4):** <one entry per Improvement row — the `file:line` re-read + what it confirmed,
or `row N → spike <id>` for an item that couldn't be verified by reading. Empty/"trust me" = the gate was
skipped (Policy 12). e.g. "row 1 → read `launch-team.md` File Ownership §, fix is additive ✓; row 2 →
unverifiable hook-scope assumption → spike wh-___">

**Applied this wave (operator-confirmed):** <process-artifact edits the operator confirmed + applied,
each with its source — e.g. "`.claude/agents/tech-lead.md` § Key Rules ← retro: 'TL broadcast contracts
late, devs idled'">, or "none — proposals pending operator confirmation". This line is the **provenance
trail**: role profiles / commands / templates / gates change ONLY via the operator-gated loop, so an
applied edit must name its source here.

### Dogfood signal → the PRODUCT loop (`/sec-learn` — distinct from the process loop above)
- <what the shipped white-hacker found reviewing OUR code; a product GAP is fixed IN the product, never forked (ADR-029)>
- This is the ONE retro channel that routes to `/sec-learn` (FPs/misses → KB/checklist diffs) and
  `/sec-kb-refresh` (new techniques/tools) — those edit the reviewer's KB, which is exactly what these signals are about.

## Next-Session Entry Point

- <the now-unblocked successor ticket, or the next logical step>
- Resume: `bd ready` · `bd show <next-id>` · `/groom <next-id>` · `/launch-team <next-id>`
- Git: NOT committed/pushed — **operator-gated** (the operator reviews + commits).
```

## Rules

1. **Facts over memory.** Every ticket status, file path, and line count comes from `bd show` / `git diff --stat`, not recollection.
2. **Capture the team, not just yourself.** The Team Record reflects actual `SendMessage` reports. If one is missing, ask for it before writing.
3. **The Retro is mandatory, actionable, and correctly routed.** A handoff with an empty or hand-wavy Retro is incomplete — name a concrete improvement, where it lands, and its **owner**. Process-artifact items (`.claude/agents/*`, commands, templates, gates) go to the **operator-gated process loop** (the TL proposes, the operator confirms; record applied edits in "Applied this wave"). Only genuine reviewer FP/miss/technique signals go to `/sec-learn` — don't route a process edit there, it can't apply it (root `CLAUDE.md` § Self-improvement loop).
4. **No silent skips (Policy 12).** If a gate FAILED or a test was SKIPPED, say so plainly and set Status `PARTIAL` — never report green when it isn't. SKIP is never PASS.
5. **Name the next step.** A handoff with no "Next-Session Entry Point" is incomplete. For a blocking chain, name the ticket the just-closed work unblocked.
6. **Operator-gated git.** The handoff records git state; it NEVER commits/pushes (`.claude/CLAUDE.md`; the operator owns git).
7. **One file per wave; `.notes/` only.** Overwrite `.notes/handoff-<slug>.md` if re-run. Never commit it, never move it under `docs/` (it leaks machine/posture detail).
8. **Retro items are grounded, not guessed (Policy 8).** Every Improvement row names a `file:line` the proposer actually READ, and a proposed fix is checked against the hooks / gates / contracts / conventions it would touch BEFORE it is recorded. An unverified plausible-sounding "we should do X" is a hallucinated retro item — drop it or downgrade it to a spike question. The same bar applies to a convention you cite as *justification*: if it's never been tested (e.g. "dev/team sessions load `--plugin-dir`" vs. what `confine_self_writes` actually blocks), say so and route it to a spike — don't repeat it as settled.

## References

- [`.claude/commands/launch-team.md`](launch-team.md) — Phase 7 invokes this; the SendMessage routing the Team Record reflects
- [`.claude/commands/design-ticket.md`](design-ticket.md) — how follow-ups in this handoff must be filed (templates, not ad-hoc)
- `CLAUDE.md` § Self-improvement loop — the **operator-gated PROCESS loop** for `.claude/agents/*` / commands / templates / gates (where process-retro items go; the TL proposes, the operator confirms)
- `plugins/white-hacker/skills/sec-learn/` — the **product** outer-loop reflection arm (reviewer FP/miss → KB/checklist diffs, gated); ONLY the Dogfood-signal items route here
- `.claude/CLAUDE.md` § QA flow / Security posture — dogfood, no-machine-data-in-committed-files, operator-gated git
