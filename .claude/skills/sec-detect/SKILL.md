---
name: sec-detect
description: Auto-detect languages/frameworks from manifest files, map needed capabilities (SAST/SCA/secrets/IaC/AI-redteam) to whatever tools are installed, and emit SCAN-PLAN.json with graceful degradation to the Read/Grep/Glob floor. Use right after threat-model to plan the scan.
---

# sec-detect

> **STATUS: STUB** — frontmatter + contract only. Full body lands in Phase 2
> (see `docs/plan/`). Until then the white-hacker agent performs this stage inline.

## Purpose
Make the agent language-agnostic; pick the right tools and degrade gracefully (ADR-003). Seeded by docs/research/poc-tool-detection/.

## Inputs / Outputs
- **Reads:** repo root manifests
- **Writes:** SCAN-PLAN.json

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
