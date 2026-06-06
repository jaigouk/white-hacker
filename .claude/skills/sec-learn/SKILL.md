---
name: sec-learn
description: Reflective learning pass. Mine recent review sessions for false-positives, missed findings, and user corrections; propose dated diffs to the KB/checklists/skills as a reviewable PR behind the eval keep-or-revert gate. Use periodically or after a notable review.
---

# sec-learn

> **STATUS: STUB** — frontmatter + contract only. Full body lands in Phase 6+
> (see `docs/plan/`). Until then the white-hacker agent performs this stage inline.

## Purpose
The outer-loop reflection (ADR-001/004); every change is a gated, reviewable diff — never auto-applied.

## Inputs / Outputs
- **Reads:** session traces, eval corpus
- **Writes:** proposed diffs / PR branch

## Where it sits in the loop
See `docs/ARCHITECTURE.md` and `.claude/agents/white-hacker.md` (the review loop).

## Verification criteria (definition of done for this skill)
- [ ] Frontmatter `description`+`when_to_use` ≤ 1,536 chars (ADR-005); `lint_skill` passes.
- [ ] Produces its output artifact with the documented schema; validated by a test fixture.
- [ ] Any `scripts/` ship with `pytest` tests (TDD; >1 test, edge cases).
- [ ] Degrades gracefully when an external tool is absent (ADR-003).
- [ ] No secret values ever written to output.

## TODO (Phase 6+)
- [ ] Implement methodology body (port from `docs/plan/` + `docs/research/`).
- [ ] Add `scripts/` + tests where executable logic is needed.
- [ ] Add `reference/` detail loaded on demand.
