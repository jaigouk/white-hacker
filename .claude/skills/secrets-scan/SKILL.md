---
name: secrets-scan
description: Scan for committed secrets — fast pattern pass (gitleaks) plus verified pass (trufflehog --results=verified). Use during discovery on any repo.
---

# secrets-scan

> **STATUS: STUB** — frontmatter + contract only. Full body lands in Phase 3
> (see `docs/plan/`). Until then the white-hacker agent performs this stage inline.

## Purpose
Catch hardcoded credentials/tokens with low noise; verification collapses to confirmed-active secrets.

## Inputs / Outputs
- **Reads:** repo (+ git history)
- **Writes:** SECRETS.json

## Where it sits in the loop
See `docs/ARCHITECTURE.md` and `.claude/agents/white-hacker.md` (the review loop).

## Verification criteria (definition of done for this skill)
- [ ] Frontmatter `description`+`when_to_use` ≤ 1,536 chars (ADR-005); `lint_skill` passes.
- [ ] Produces its output artifact with the documented schema; validated by a test fixture.
- [ ] Any `scripts/` ship with `pytest` tests (TDD; >1 test, edge cases).
- [ ] Degrades gracefully when an external tool is absent (ADR-003).
- [ ] No secret values ever written to output.

## TODO (Phase 3)
- [ ] Implement methodology body (port from `docs/plan/` + `docs/research/`).
- [ ] Add `scripts/` + tests where executable logic is needed.
- [ ] Add `reference/` detail loaded on demand.
