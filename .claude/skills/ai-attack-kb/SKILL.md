---
name: ai-attack-kb
description: Living knowledge base of AI/LLM/agent/MCP attack techniques with detection patterns, dated provenance, and active/archived status. Loaded on demand during ai-llm-review; refreshed by sec-kb-refresh. Use to look up current AI-attack techniques.
---

# ai-attack-kb

> **STATUS: STUB** — frontmatter + contract only. Full body lands in Phase 4
> (see `docs/plan/`). Until then the white-hacker agent performs this stage inline.

## Purpose
Progressive-disclosure KB that keeps AI-attack knowledge current (ADR-012).

## Inputs / Outputs
- **Reads:** feeds (via sec-kb-refresh), reviews (via sec-learn)
- **Writes:** reference/*.md entries

## Where it sits in the loop
See `docs/ARCHITECTURE.md` and `.claude/agents/white-hacker.md` (the review loop).

## Verification criteria (definition of done for this skill)
- [ ] Frontmatter `description`+`when_to_use` ≤ 1,536 chars (ADR-005); `lint_skill` passes.
- [ ] Produces its output artifact with the documented schema; validated by a test fixture.
- [ ] Any `scripts/` ship with `pytest` tests (TDD; >1 test, edge cases).
- [ ] Degrades gracefully when an external tool is absent (ADR-003).
- [ ] No secret values ever written to output.

## TODO (Phase 4)
- [ ] Implement methodology body (port from `docs/plan/` + `docs/research/`).
- [ ] Add `scripts/` + tests where executable logic is needed.
- [ ] Add `reference/` detail loaded on demand.
