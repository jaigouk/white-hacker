---
name: next-wave
description: After a wave closes, reconcile the intent hierarchy (project goals → PRD FRs → epic goals → waves) against what just shipped, then select and groom the next wave. Use after /handoff (and /review) to choose what to work on next — it catches ripple-stale docs/tickets and re-aligns .notes/order.md to current product priority before /launch-team. Planning only: proposes doc edits, never ad-hoc bd-creates, never launches or commits.
allowed-tools: Agent, Bash, Read, Grep, Glob, Edit, Write
---

# /next-wave [--epic=<id>]

Close the planning loop after a wave lands. A finished wave **ripples**: it can outdate downstream
tickets (a sibling's assumptions), docs (a PRD FR status, an ARCHITECTURE build-state line), and
`.notes/order.md` — and the obvious "next" by momentum may not be the wave that best serves the current
top product priority. This walks the intent hierarchy top-down, reconciles the ripple, then selects +
grooms the next wave. It is the **project-manager**'s between-wave routine (the tech-lead owns in-wave +
close — `.claude/agents/`).

## Why This Exists

The lifecycle commands form a chain — `/design-ticket → /groom → /launch-team → /handoff → /review` — but
nothing closes `/review` back to the next `/design-ticket`/`/groom`. That link is supplied by hand every
wave, and `.notes/order.md` drifts (a stale "next", an outdated blocker, a downstream ticket whose premise
the last wave invalidated). `/next-wave` makes the **top-down re-evaluation + ripple reconciliation +
next-wave selection** one repeatable step grounded in `bd` (the source of truth), not in whatever
order.md last said.

## Usage

```
/next-wave                 # reconcile, then pick + groom the next wave across all open epics
/next-wave --epic=wh-5ox   # constrain selection to one epic
```

Run AFTER the wave's `/handoff` (and `/review`), once the wave is closed in `bd`.

## Process

The project-manager's routine. Phases 1–3 (the read-heavy reconcile + selection) may run as a
**project-manager** subagent; Phase 4 grooming runs via `/groom` at the invoking level (a subagent can't
invoke another command). Copy this checklist and track it:

```
- [ ] Phase 0  Anchor on the closed wave (handoff + diff)
- [ ] Phase 1  Top-down intent trace (goals → PRD → epics → order.md)
- [ ] Phase 2  Ripple reconciliation (fix order.md; flag stale docs/tickets)
- [ ] Phase 3  Select the next epic + wave (priority × unblocked × file-disjoint)
   ── a PM subagent STOPS here, returning a groom-ready recommendation ──
- [ ] Phase 4  Groom the selected tickets — /groom each at the INVOKING level (loop on NEEDS UPDATE/SPLIT)
- [ ] Phase 5  Re-sync order.md + report (+ operator decisions)
```

### Phase 0 — Anchor on the closed wave
Read the latest wave's handoff — the most recent `.notes/waves/*/*/handoff.md` — and the wave's `git --no-pager diff` range. Note what landed, which
files moved, and the follow-ups + retro it surfaced. This is the **ripple source**. **If the diff range
bundles co-committed PRIOR waves** (several waves pushed together, or a co-tenant file like
`supply_chain.py` carrying two waves' hunks — check the handoff's "Files changed" scoping), attribute
ripple ONLY to the closed wave's own files; a co-tenant wave's changes are not this wave's ripple.

### Phase 1 — Top-down intent trace (the in-line evaluation)
Walk the hierarchy; at each level confirm it still agrees with the level above AND with what just shipped:
- **Project goals** — `.claude/CLAUDE.md` (two-loops mission) + `docs/ARCHITECTURE.md` build-state. Did the wave move the build-state (an arm human-triggered → autonomous; a capability floor → tool-assisted)?
- **PRD** — `docs/PRD.md` §1.3 Goals + §5 functional requirements (`FR-NN`, each carrying an inline status). Per FR: is the status still true post-wave? Find the **highest-priority UNDER-served FR that has a TEAM-LAUNCHABLE ready ticket** (pending/partial, not blocked) — the product signal for which epic to feed next. A higher-priority FR whose only ready ticket is **operator-only / human-decision** is surfaced SEPARATELY (it is not a dev wave and must not mask the real next one).
- **Epic goals** — `bd show` each open epic. Does each still map to a live FR? Is any goal now partly satisfied (remaining waves lower-value)? Is its Execution Waves table stale vs the closed wave?
- **Waves** — reconcile `.notes/order.md` against `bd ready` / `bd blocked`. (Serial-lane tickets show "ready" in bd but file-contention serializes them — order.md is the truth there, not raw `bd ready`.)

Emit an **alignment table**: `PRD FR → serving epic → next ready wave → priority / serves-which-goal`,
plus a list of **ripple-stale artifacts**.

### Phase 2 — Ripple reconciliation
- Stale **doc** (PRD FR status, ARCHITECTURE build-state, a research doc): **PROPOSE** the exact edit and WAIT — docs are operator-committed (root `CLAUDE.md` § Self-improvement loop). Do not apply.
- Stale **downstream ticket** (assumptions outdated by the wave): mark it **NEEDS RE-GROOM** in its bd notes — never launch on a stale premise (Policy 8).
- Stale **`.notes/order.md`**: fix directly (PM scratchpad; gitignored).
- New follow-ups the handoff surfaced: ensure they're in order.md "To file"; route real ones via `/design-ticket` (never ad-hoc `bd create`).

### Phase 3 — Select the next epic + wave
From the alignment table, pick the epic serving the top under-served FR that has **ready, parallel-safe,
file-disjoint** tickets. Compose the wave honoring serial-lane / File-Ownership truth in order.md (not raw
`bd ready`). Surface any **priority-vs-architecture tension as an explicit operator decision** (e.g. a P1
ticket behind a P2 "spine-first" head with no hard dep) — do not resolve it silently (Policy 1).

### Phase 4 — Groom the selected tickets
Run `/groom <id>` on each selected ticket (one at a time — re-validate against the now-current state and
persist the verdict). A `NEEDS UPDATE` / `NEEDS SPLIT` verdict loops back through `/design-ticket` before
the wave is launch-ready (validator → fix → re-groom).

### Phase 5 — Re-sync order.md + report
Rewrite `.notes/order.md` to the **wave-board template** (`docs/beads_templates/order-board-template.md`)
— the `Status | Wave | Summary & why grouped | Notes` board (rows sorted ✅→▶→◐→⏸→⬚; a wave drops off once
pushed + closed — NOT a changelog) plus Base state · DO NEXT · Backlog · Invariants. Put the chosen wave at
the top of DO NEXT. **Verify EVERY wave's Status from bd + git** (`bd show <tickets>` · `git status`
ahead-count) — never carry a status over from the old order.md or memory; `✅ closing` means NOT-yet-closed
(still owes `git push` / `bd close` / the dogfood). Report: the alignment table, the ripple fixes, the chosen wave + why,
the groom verdicts, and any **operator decisions** (priority ties, proposed doc edits awaiting
confirmation). Hand the groomed wave to `/launch-team`.

## Rules

1. **Planning only.** Reconcile + select + groom + propose. NEVER `bd close`, `bd create` (route via `/design-ticket`), `/launch-team`, or `git commit`/`push` — other commands / operator-gated.
2. **bd is the source of truth; order.md is the plan.** Ground every claim in `bd ready`/`bd blocked`/`bd show`; fix order.md to match (Policy 7 — source wins).
3. **Doc edits are operator-gated.** PRD / ARCHITECTURE / ADR edits are PROPOSED and WAIT; only `.notes/order.md` is edited directly (root `CLAUDE.md` § Self-improvement loop).
4. **Top-down, not momentum.** Pick from the highest-priority under-served PRD FR, not "what's next on the lane." Flag priority-vs-architecture ties for the operator.
5. **Surface ripple, don't bury it.** A ticket the wave outdated is marked NEEDS RE-GROOM, never launched on a stale premise (Policy 8). Cite the `file:line` / bd id behind each reconciliation.
6. **One ticket at a time in Phase 4** (matches `/groom`); a NEEDS UPDATE/SPLIT loops to `/design-ticket`.
7. **Re-entrant / idempotent.** Re-derive the plan from `bd` every run; RECONSTRUCT `.notes/order.md` (don't append — no duplicate "To file" rows). Write a verdict with `bd update --notes` (replace) only when this routine owns the note; if a human-authored note is present, use `bd update --append-notes` instead (never clobber it). Before any Phase-4 split/create, check `bd` so a re-run never duplicates what `/design-ticket` already made (an already-split ticket grooms READY, not SPLIT). In the common case — state already reconciled — a re-run is effectively read-only.

## References
- `.claude/commands/handoff.md` — the wave-close record this consumes (run BEFORE /next-wave)
- `.claude/commands/review.md` — the post-wave code-quality pass (also before)
- `.claude/commands/groom.md` — Phase 4 dispatches it per selected ticket
- `.claude/commands/design-ticket.md` — where NEEDS UPDATE/SPLIT + new follow-ups route
- `.claude/commands/launch-team.md` — the next step once the wave is groomed
- `.claude/agents/project-manager.md` — the role that drives this (between-wave planning; syncs order.md)
- `docs/PRD.md` (FRs + status) · `docs/ARCHITECTURE.md` (build-state) · `docs/ARD.md` (ADRs) — the intent hierarchy
- `.notes/order.md` — the live wave plan this re-syncs
- root `CLAUDE.md` § Self-improvement loop — why doc/process edits are operator-gated proposals
