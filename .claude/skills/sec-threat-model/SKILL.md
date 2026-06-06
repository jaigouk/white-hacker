---
name: sec-threat-model
description: Synthesize or ingest THREAT_MODEL.md (assets, entry points, trust boundaries, in-scope vuln classes, scoring standard) from docs + git history + past fixes. Use at the start of a security review to scope and calibrate severity.
---

# sec-threat-model

> **STATUS: STUB** — frontmatter + contract only. Full body lands in Phase 2
> (see `docs/plan/`). Until then the white-hacker agent performs this stage inline.

## Purpose
Establish threat-model fidelity — the top precision lever (~90% exploitable findings when well-defined).

## Inputs / Outputs
- **Reads:** repo source, docs/, git log
- **Writes:** THREAT_MODEL.md

## Where it sits in the loop
See `docs/ARCHITECTURE.md` and `.claude/agents/white-hacker.md` (the review loop).

## Verification criteria (definition of done for this skill)
- [ ] Frontmatter `description`+`when_to_use` ≤ 1,536 chars (ADR-005); `lint_skill` passes.
- [ ] Produces its output artifact with the documented schema; validated by a test fixture.
- [ ] Any `scripts/` ship with `pytest` tests (TDD; >1 test, edge cases).
- [ ] Degrades gracefully when an external tool is absent (ADR-003).
- [ ] No secret values ever written to output.

## TODO (Phase 2)
- [ ] Implement methodology body (port from `docs/plan/` + `docs/research/`).
- [ ] Add `scripts/` + tests where executable logic is needed.
- [ ] Add `reference/` detail loaded on demand.
