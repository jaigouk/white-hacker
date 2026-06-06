# Phase 4 — AI/LLM + API coverage (seed the living KB + the AI-redteam capability)

> **Theme:** add the AI/LLM/MCP/Agentic review pass and the API appendix, grounded in the **living
> knowledge base**. This is where the two loops first touch: `ai-llm-review` (inner loop) **consumes**
> the `ai-attack-kb` (outer-loop-maintained). Phase 4 stands up the KB with a **stable seed** + its
> entry schema; the *autonomous* refresh/learn machinery lands in Phases 8–9.
> **Maps to:** PLAN §8.1 P4, §5.3 (AI/LLM), §5.4 (API); ADR-012 (living KB), ADR-015 (AI-redteam cap);
> si-08 §2 (KB tiers/schema) folded onto the on-disk `ai-attack-kb/reference/` path (README reconcile).
>
> **Loop position:** INNER pass that **consumes** the KB; seeds the Context surface the OUTER loop edits.
> **Exit condition:** on an AI/MCP repo, `ai-llm-review` flags LLM05 improper-output-handling and a
> lethal-trifecta path, citing `kb_refs` to dated, source-linked KB entries; the API appendix drives
> BOLA/BFLA checks on a REST repo.

> **Layout note (README reconcile):** the on-disk KB uses `ai-attack-kb/reference/` (singular, one level
> deep) per ADR-012. The si-08 two-tier *idea* is honored by cadence, not by path: stable web/CWE
> checklists stay in `_shared/reference/` (yearly); the fast AI-threat tier is `ai-attack-kb/reference/`
> (monthly; the refresh routine in Phase 8 is scoped here only).

---

### T-4.1 · Define the KB entry schema + seed `ai-attack-kb/SKILL.md` as a pure TOC
- **Goal:** `ai-attack-kb/SKILL.md` becomes a < 500-line progressive-disclosure TOC over
  `reference/<technique-class>.md`; an entry schema (si-08 §2.2 fused Sigma+Semgrep front-matter:
  `id` typed/never-reused, `title`, `technique_class` from a controlled vocab, `severity`, `confidence`,
  `status ∈ {active,archived,deprecated}`, `date`, `modified`, `review_by`, `metadata.{source,url,
  retrieved}` **mandatory**, `supersedes`, `detections`, `xref`) is documented and accompanied by a
  validator (full implementation in T-8.1).
- **Artifact:** `.claude/skills/ai-attack-kb/SKILL.md`, `.claude/skills/ai-attack-kb/kb-entry-schema.json`
- **Depends on:** —
- **Verification criteria:**
  - [ ] `SKILL.md` is a TOC, < 500 lines, de-stubbed — `awk 'END{exit !(NR<500)}' .claude/skills/ai-attack-kb/SKILL.md && ! grep -q 'STATUS: STUB' .claude/skills/ai-attack-kb/SKILL.md`
  - [ ] Entry schema requires `metadata.source` + `url` + `retrieved` and a controlled `technique_class` enum — a fixture entry missing `source` fails validation — `uv run pytest .claude/skills/ai-attack-kb/scripts/tests/test_kb_entry_schema.py` (stub test ok here; expanded in T-8.1)
  - [ ] `status` enum is exactly `{active, archived, deprecated}` and `id` matches a typed pattern — asserted in the test
- **Status:** todo

### T-4.2 · Fill the seed KB reference entries (dated, sourced, active)
- **Goal:** the five on-disk `reference/*.md` files (`prompt-injection`, `tool-poisoning`,
  `rag-poisoning`, `excessive-agency`, `data-exfil`) carry real seed entries conforming to T-4.1 with
  dated provenance (ATLAS `AML.T*` / OWASP `ASIxx`/`LLMxx` / CVE), mapping technique → detection pattern
  → checklist item (ADR-012). Anchored to OWASP LLM Top 10 **2025** + Agentic 2026 + ATLAS 2026.05.
- **Artifact:** `.claude/skills/ai-attack-kb/reference/{prompt-injection,tool-poisoning,rag-poisoning,
  excessive-agency,data-exfil}.md`
- **Depends on:** T-4.1
- **Verification criteria:**
  - [ ] Every entry validates against the T-4.1 schema (source+url+retrieved present) — `uv run python .claude/skills/ai-attack-kb/scripts/validate_kb.py .claude/skills/ai-attack-kb/reference/` (exit 0)
  - [ ] Each file has ≥ 1 `active` entry with a real `AML.T\d+|ASI\d+|LLM\d+|CVE-\d{4}-\d+` source — `grep -REq 'AML\.T[0-9]+|ASI[0-9]+|LLM[0-9]+|CVE-[0-9]{4}-[0-9]+' .claude/skills/ai-attack-kb/reference/`
  - [ ] No `STATUS: STUB` banner remains — `! grep -rq 'STATUS: STUB' .claude/skills/ai-attack-kb/reference/`
  - [ ] Each entry summary ≤ 120 words; file ≤ 400 lines — checked by `validate_kb.py` (size caps)
- **Status:** todo

### T-4.3 · Fill `_shared/reference/ai-llm.md` (the inner-loop AI checklist)
- **Goal:** replace the stub with PLAN §5.3 content mapped to OWASP LLM Top 10 (2025) / MCP Top 10 /
  Agentic ASI 2026: LLM01 prompt injection (architectural-only, no code fix), **LLM05 improper output
  handling (highest yield)**, lethal trifecta / Agents Rule of Two, MCP token-passthrough / tool-
  poisoning / confused-deputy, RAG/vector poisoning + cross-tenant leakage, unbounded consumption,
  excessive agency — each cross-linking the `ai-attack-kb` technique class.
- **Artifact:** `.claude/skills/_shared/reference/ai-llm.md`
- **Depends on:** T-4.2
- **Verification criteria:**
  - [ ] Covers all seven areas with OWASP IDs — `for k in 'LLM01\|prompt injection' 'LLM05\|improper output' 'lethal trifecta\|rule of two' 'MCP' 'RAG\|vector' 'unbounded\|consumption' 'excessive agency'; do grep -qiE "$k" .claude/skills/_shared/reference/ai-llm.md || echo MISSING:"$k"; done` prints nothing
  - [ ] LLM05 flagged as the highest-yield code check — `grep -qi 'highest.yield\|highest yield' .claude/skills/_shared/reference/ai-llm.md`
  - [ ] Cross-links the KB — `grep -q 'ai-attack-kb' .claude/skills/_shared/reference/ai-llm.md`; de-stubbed; ≤ 400 lines
- **Status:** todo

### T-4.4 · Fill `_shared/reference/api.md` (OWASP API Top 10 2023)
- **Goal:** replace the stub with PLAN §5.4 content: BOLA(#1)/BFLA/BOPLA, broken auth, unrestricted
  consumption, SSRF, unsafe third-party consumption — with the explicit "no 2025/2026 API edition
  exists; distrust 'API Top 10 2026' claims" caveat and the highest-value generic check (re-verify
  authenticated principal server-side per object/function, default-deny).
- **Artifact:** `.claude/skills/_shared/reference/api.md`
- **Depends on:** —
- **Verification criteria:**
  - [ ] Covers BOLA/BFLA/BOPLA + the four others with `APIx:2023` IDs — `grep -qi 'bola' .claude/skills/_shared/reference/api.md && grep -qi 'bfla' .claude/skills/_shared/reference/api.md && grep -qE 'API[0-9]+:2023' .claude/skills/_shared/reference/api.md`
  - [ ] States the "no 2025/26 API edition" caveat — `grep -qi '2023' .claude/skills/_shared/reference/api.md && grep -qi 'no 20(25|26)\|distrust' .claude/skills/_shared/reference/api.md`
  - [ ] De-stubbed; ≤ 400 lines — `! grep -q 'STATUS: STUB' .claude/skills/_shared/reference/api.md`
- **Status:** todo

### T-4.5 · Implement `ai-llm-review` body (consumes KB; AI-redteam capability)
- **Goal:** `ai-llm-review/SKILL.md` documents the AI pass triggered by `SCAN-PLAN.json` `ai_pass:true`:
  partition the agent/LLM/MCP surface, check the `ai-llm.md` classes, **load `ai-attack-kb` entries on
  demand**, attach `kb_refs` to findings, and optionally use an AI-redteam capability (illustrative:
  promptfoo/Inspect) with floor degradation — merging into `VULN-FINDINGS.json`.
- **Artifact:** `.claude/skills/ai-llm-review/SKILL.md`
- **Depends on:** T-4.2, T-4.3, T-1.1, T-2.2
- **Verification criteria:**
  - [ ] Triggered by `SCAN-PLAN.json` `ai_pass` and loads KB entries (progressive disclosure) — `grep -qi 'ai_pass\|SCAN-PLAN' .claude/skills/ai-llm-review/SKILL.md && grep -q 'ai-attack-kb' .claude/skills/ai-llm-review/SKILL.md`
  - [ ] Findings carry `kb_refs` to KB entry ids — documented in the SKILL; demonstrated on an AI fixture (logged)
  - [ ] AI-redteam capability is optional with floor degradation (ADR-015/003) — `grep -qi 'degrad\|floor\|optional' .claude/skills/ai-llm-review/SKILL.md`
  - [ ] De-stubbed; output validates against T-1.1 — `! grep -q 'STATUS: STUB' .claude/skills/ai-llm-review/SKILL.md`
- **Status:** todo

### T-4.6 · AI/MCP fixture + end-to-end AI-pass demonstration
- **Goal:** a small AI/MCP fixture (an LLM05 improper-output-handling sink + a lethal-trifecta path +
  one MCP token-passthrough) so `sec-detect` triggers the AI pass and `ai-llm-review` flags them with
  KB-cited findings; plus a clean look-alike that must not fire.
- **Artifact:** `docs/research/poc-ai-review/` (fixtures + `README.md` with expected `file:line` + KB ids)
- **Depends on:** T-4.5
- **Verification criteria:**
  - [ ] `sec-detect` sets `ai_pass:true` on the fixture (it imports langchain/openai/anthropic/MCP) — `uv run python .claude/skills/sec-detect/scripts/detect_tools.py docs/research/poc-ai-review/<ai-vuln> | grep -q '"ai_pass": true'` (or schema field)
  - [ ] The AI pass flags the LLM05 sink + lethal-trifecta path with non-empty `kb_refs`, and does NOT flag the clean look-alike — before/after logged in README
  - [ ] Resulting findings validate against T-1.1 and each `kb_refs` id exists in `ai-attack-kb/reference/` — `uv run python .claude/skills/_shared/scripts/validate_findings.py <output> --check-kb-refs .claude/skills/ai-attack-kb/reference/`
- **Status:** todo
