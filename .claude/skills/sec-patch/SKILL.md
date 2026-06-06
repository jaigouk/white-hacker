---
name: sec-patch
description: Generate candidate fixes (opt-in). Patch ladder: build -> original PoC stops -> tests pass -> re-attack with a fresh agent. Root-cause fix, variant hunt, minimal diff. Writes ONLY to ./PATCHES/. Use only when explicitly asked to propose patches.
---

# sec-patch

> **STATUS: STUB** — frontmatter + contract only. Full body lands in Phase 5
> (see `docs/plan/`). Until then the white-hacker agent performs this stage inline.

## Purpose
Remediation with verification; capability-removed writes (ADR-010) — proposes, never pushes.

## Inputs / Outputs
- **Reads:** TRIAGE.json
- **Writes:** PATCHES/, PATCH-STATE.json

## Where it sits in the loop
See `docs/ARCHITECTURE.md` and `.claude/agents/white-hacker.md` (the review loop).

## Verification criteria (definition of done for this skill)
- [ ] Frontmatter `description`+`when_to_use` ≤ 1,536 chars (ADR-005); `lint_skill` passes.
- [ ] Produces its output artifact with the documented schema; validated by a test fixture.
- [ ] Any `scripts/` ship with `pytest` tests (TDD; >1 test, edge cases).
- [ ] Degrades gracefully when an external tool is absent (ADR-003).
- [ ] No secret values ever written to output.

## TODO (Phase 5)
- [ ] Implement methodology body (port from `docs/plan/` + `docs/research/`).
- [ ] Add `scripts/` + tests where executable logic is needed.
- [ ] Add `reference/` detail loaded on demand.
