# `.notes/order.md` — wave board template

The canonical structure for `.notes/order.md`, the cross-epic **live forward plan**. Maintained by
`/next-wave` (Phase 5) and the **project-manager** agent. `.notes/order.md` itself is gitignored scratch —
this committed template is its single source of truth for shape.

## Principle — a board, NOT a changelog
order.md shows only what is **in flight or queued**. A wave **drops off the board** only once it is
bd-**closed** AND **pushed** AND any owed **dogfood** is done — verify each (`bd show` · `git status`),
never assume "done" just because the code landed (its record then lives only in
`.notes/waves/<date>/<slug>/` + beads). Never let it accrete history; never let the Backlog become a
graveyard (prune stale items). History → git · `bd show` · the wave folders.

## Sections (in this order)
1. **Base state** — HEAD/branch · ahead-of-origin · what's owed (push, dogfood) · ADR count. 1–3 lines.
2. **Wave board** — the table (below). The centerpiece.
3. **DO NEXT** — a numbered, ordered action queue for the operator.
4. **Backlog (unscheduled — prune stale; NOT a graveyard)** — compact lists: later tickets · singletons · "To file" · operator-only.
5. **Invariants (settled — cite, don't re-debate)** — the stable reference (ADRs · gates · conventions).

## The Wave board table

```
| Status | Wave | Summary & why grouped | Notes |
|--------|------|----------------------|-------|
```

- **Status — DERIVE each from bd + git; NEVER guess** (`bd show <tickets>` · `bd ready` · `bd blocked` · `git status` ahead-count). Sort rows in this order:
  - `✅ closing` — code committed/done BUT the wave is **NOT fully closed**: it still owes at least one of { `bd close` · `git push` · the white-hacker **dogfood** }. **Stays on the board until ALL are done**, then drops off. ("closing" ≠ "closed" — a wave is not done just because the code landed; confirm `bd show` = closed AND `git` = pushed.)
  - `▶ next` — ready to launch: tickets `open`, no open blocker (appears in `bd ready`).
  - `◐ in progress` — actively being implemented (claimed / `in_progress`, code not yet committed).
  - `⏸ blocked` — has an open bd dependency (appears in `bd blocked`).
  - `⬚ later` — queued; not yet ready (behind another ticket on the same file, or not started).
  - **No hallucinated state** (Policy 8) — if a status isn't obvious, run the check; never assert "closed/done" from memory.
- **Wave** — the wave's **slug** = its sorted ticket ids = its folder name `.notes/waves/<date>/<slug>/`
  (1 ticket verbatim · 2–3 joined with `+` · 4+ `<lead>+<N>more`). A `→` chain (e.g. `wh-a → wh-b`) means a
  **sequence of separate waves** on the same file, NOT one wave.
- **Summary & why grouped** — 1–2 plain-English sentences: what the wave does, AND why those tickets are
  together — exactly one of:
  - **grouped (parallel)** — they change *different* files, so they run at the same time (name the files/areas).
  - **solo** — a single ticket (its own wave).
  - **sequenced** — separate waves that all change the *same* file, so they take turns one-at-a-time (name the file).
  - Avoid jargon. Do NOT write "lane / swimlane / WIP / ∥ / co-wave / serialize". Say "different files →
    can run together" / "same file → take turns".
- **Notes** — priority (P0–P4) · blocked-by · open decisions · short status detail.

## The grouping rule (the one thing the board encodes)
Tickets run **together in one wave only when they change different files** (so they can't collide).
Tickets that change the **same file** are **separate waves, run one-at-a-time**. A single ticket is its own
(solo) wave. The "why grouped" half of each Summary states which of the three this row is.

## Worked example
```
| Status | Wave | Summary & why grouped | Notes |
|--------|------|----------------------|-------|
| ✅ closing | `wh-0c2+wh-hxt.18` | Three unrelated floor improvements — Gradle dep-parser · KB staleness · Betterleaks. **Grouped** because each touches a different file → ran in parallel. | `bd close` pending dogfood |
| ▶ next | `wh-5ox.10` | The schema spine: att_ck/atlas + disputed fields + matcher. **Solo** — one ticket on the busy `supply_chain.py`. | P2; ⚠ .2-vs-.10 |
| ▶ next | `wh-sml` | Spike: do plugin hooks fire for subagents? **Solo**, but **can run with `wh-5ox.10`** (different files). | P2 |
| ⏸ blocked | `wh-5ox.19` | ATT&CK/ATLAS coverage report. Solo; **waits on `wh-5ox.10`** (needs its att_ck field). | P3 |
| ⬚ later | `wh-5ox.2 → .5 → .8` | Three S6 detectors. **Separate waves, one-at-a-time** — all edit the same `supply_chain.py`. | after `.10` |
```

## References
- `.claude/commands/next-wave.md` (Phase 5 rewrites order.md to this template) · `.claude/agents/project-manager.md` (owns the sync)
- `docs/beads_templates/beads-epic-template.md` — the per-epic Execution-Waves table (the in-epic sibling of this cross-epic board)
- `.claude/CLAUDE.md` § QA flow — the `.notes/waves/<date>/<slug>/` per-wave folder convention + the slug rule
