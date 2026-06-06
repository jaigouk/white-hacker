---
name: ai-llm-review
description: AI/LLM/MCP/Agentic security review: improper output handling (LLM05), lethal trifecta, prompt-injection architecture, MCP token-passthrough/tool poisoning, RAG/vector poisoning, excessive agency, unbounded consumption. Use when the repo contains LLM/agent/MCP code.
---

# ai-llm-review

> **STATUS: STUB** — frontmatter + contract only. Full body lands in Phase 4
> (see `docs/plan/`). Until then the white-hacker agent performs this stage inline.

## Purpose
Cover OWASP LLM 2025 / MCP / Agentic(ASI) 2026, grounded in the living ai-attack-kb.

## Inputs / Outputs
- **Reads:** repo, SCAN-PLAN.json, ai-attack-kb/reference/
- **Writes:** merged into VULN-FINDINGS.json

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
