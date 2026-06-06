---
name: sec-kb-refresh
description: Poll authoritative AI-threat feeds (OWASP GenAI, MITRE ATLAS, OSV/GHSA, trackers), extract NEW attack techniques AND newly-useful security tools, and propose dated entries (KB + tool-registry) with source provenance for human approval. Use on a schedule (routine) or manually to keep both current.
---

# sec-kb-refresh

> **STATUS: STUB** — frontmatter + contract only. Full body lands in Phase 6+
> (see `docs/plan/`). Until then the white-hacker agent performs this stage inline.

## Purpose
The outer-loop input arm — ingests 'new ways to hack AI products' (docs/research/si-07-threat-feeds.md).

## Inputs / Outputs
- **Reads:** feeds (see si-07), existing KB
- **Writes:** proposed ai-attack-kb entries / PR

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
