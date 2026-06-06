# Spike S-03 — What are the real Claude Code skill limits? (size-cap guardrail)

- **Status:** ✅ RESOLVED
- **Date:** 2026-06-06
- **Confidence:** High (official docs)

## Question / assumption

Two sources disagreed on the skill `description` cap: the Self-Improving Agent
reference said **≤ 1,024 chars**; the self-improvement research said **1,536**.
The size-cap guardrails for the self-improving KB depend on the real number.

## Evidence (verified — [skills docs](https://code.claude.com/docs/en/skills))

> "the combined `description` and `when_to_use` text is **truncated at 1,536
> characters** in the skill listing to reduce context usage."

- `when_to_use` is **appended to `description`** and **counts toward the same
  1,536-char cap**.
- Body: `SKILL.md` loads only when the skill is used; `reference/` files load on
  demand → keep the always-loaded surface (frontmatter) tiny, push depth into refs.
- The `1,024` figure is the **agentskills.io** cross-tool standard for the
  `description` field in the abstract spec — a *different* number from Claude
  Code's combined-listing truncation. Not a contradiction; different scopes.

## Decision (guardrails to enforce)

- **Cap A (listing):** each skill's `description` + `when_to_use` **≤ 1,536 chars**
  (operative Claude Code limit). The KB-write/lint check enforces this.
- **Cap B (portability):** to stay portable to other Agent-Skills runtimes, also
  keep `description` alone **≤ 1,024** and `name` **≤ 64** chars.
- **Body:** `SKILL.md` **< 500 lines**; `reference/` **one level deep** with a
  table of contents in long files; avoid time-sensitive phrasing (use a
  `## Deprecated` `<details>` block so stale techniques don't pollute guidance).
- These become the numeric inputs to the self-improving ratchet's **size-cap gate**
  and the `lint_skill` script (which ships with tests).

→ Feeds **ADR-005** (skill size-cap guardrails) and the KB-design doc.
