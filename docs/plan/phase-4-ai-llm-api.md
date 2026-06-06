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

## Grooming (refined 2026-06-06, after Phase 3)

**Readiness:** ✅ READY *after the currency spike* (see DoR). Phases 0–3 are `done (verified)`.

**Definition of Ready — reconciled against what Phases 2–3 actually built:**
- **`ai_pass` already gates this phase.** `sec-detect` flips `ai_pass:true` on langchain/openai/
  anthropic/transformers/torch and adds `ai-llm.md` to `reference_appendices` + the `ai-redteam`
  capability to `category_tool`. `ai-llm-review` is *triggered by that flag* — the wiring exists.
- **Degradation pattern is set (Phase 3).** `ai-redteam` follows the same capability+floor contract as
  SCA/SAST/IaC; `_shared/scripts/degradation.py` stamps `tool_assisted`/`tools_unavailable`. Reuse it.
- **Finding contract + validator exist.** Findings merge into `VULN-FINDINGS.json` (T-1.1 schema, which
  already has a `kb_refs[]` field) and validate with `validate_findings.py`.
- **The exclusion list already covers LLM01.** `exclusion-rules.md` lists "prompt-injection-into-LLM
  (architectural, not code-bug)". So `ai-llm-review` must treat **LLM01 prompt injection as an
  architectural design note, NOT a HIGH finding**, while **LLM05 improper output handling is the
  reportable, highest-yield code bug**. This precision split is load-bearing — bake it into T-4.3/T-4.5.
- **The KB is five ad-hoc stub files** (`- status:`/`- sources:` bullets), not the si-08 schema, and
  there is **no `ai-attack-kb/scripts/`** yet → T-4.1 defines the real format + builds the validator.

**KB entry format decision (resolves a T-4.1/T-4.2 ambiguity): one entry per file, YAML front-matter.**
Each `reference/<technique-class>.md` = **one** KB entry (Sigma-style; consistent with this repo's
front-matter convention), front-matter = the schema fields, body = technique→detection→checklist
(≤120-word summary first). `technique_class` controlled vocab = the five file stems
(`prompt-injection`, `tool-poisoning`, `rag-poisoning`, `excessive-agency`, `data-exfil`). Multiple
entries per class later split to `reference/<class>-<n>.md` (still one level deep, ADR-012). Shape:
```yaml
---
id: AISEC-PROMPT-INJECTION-001     # typed, never reused
title: ...
technique_class: prompt-injection  # enum = the five stems
severity: high                     # high|medium|low
confidence: 0.8                    # 0..1
status: active                     # active|archived|deprecated
date: 2026-06-06
modified: 2026-06-06
review_by: 2026-09-06
metadata: { source: "...", url: "https://...", retrieved: 2026-06-06 }   # all three MANDATORY
supersedes: null
detections: ["grep/semgrep pattern or behavioral check"]
xref: ["LLM01:2025", "AML.T0051"]
---
```

**Host capability reality (probed Phase 3):** no AI-redteam tool installed (promptfoo/garak absent) →
the AI pass runs the **static floor** (KB patterns over the code), `tool_assisted:false`; the
AI-redteam-tool path is proven by the injected-`which` degradation pattern, not a live redteam run.
Don't fake a behavioral redteam.

**Reconciliation sub-tasks (gaps Phase-2/3 left for Phase 4 — own them explicitly):**
1. **MCP detection:** `detect_tools.AI_FRAMEWORK_SIGNALS` has no `mcp` → an MCP-only repo would NOT
   flip `ai_pass`, yet T-4.6's fixture assumes it does. **Add `mcp`/`modelcontextprotocol`/
   `@modelcontextprotocol/sdk` to the AI signals + a `sec-detect` test** (do this in T-4.6 prep, or
   first — it's independent and small).
2. **`--check-kb-refs`:** `validate_findings.py` lacks it (T-4.6 VC uses it). **Add a
   `--check-kb-refs <kb-reference-dir>` option** that asserts every finding's `kb_refs` id exists as a
   KB entry `id`, + a test in the `_shared` suite.
3. **Functional `validate_kb.py` in *this* phase.** T-4.1's text says "full implementation in T-8.1",
   but T-4.2 runs `validate_kb.py` exit-0. Build the **basic** validator now (parse YAML front-matter,
   validate against `kb-entry-schema.json`, enforce size caps + unique ids); T-8.1 adds only the
   refresh/`review_by` gating. Needs a YAML parser (`uv run --with pyyaml`).

**Task sizing & sequencing (reconciled):**
| Step | Size | Type | Order | Notes |
|------|------|------|-------|-------|
| **spike-05** AI threat currency | S | research | **first (DoR for T-4.2/4.3)** | verify OWASP LLM-2025 IDs, ATLAS `AML.T*`, OWASP ASI/Agentic naming, MCP refs |
| T-4.1 KB schema + TOC + functional `validate_kb.py` | M | code+docs+tests | after spike | YAML front-matter; build the validator now |
| T-4.4 `api.md` (API Top 10 2023) | S | docs | parallel (independent) | stable; just confirm no 2025/26 edition |
| T-4.2 seed five KB entries | M | docs+data | after spike + T-4.1 | one entry/file; real dated sources |
| T-4.3 `ai-llm.md` inner checklist | M | docs | after T-4.2 | LLM05>LLM01 precision split; cross-link KB |
| T-4.5 `ai-llm-review` body | M | docs | after T-4.2/4.3 | trigger on `ai_pass`; AI-redteam optional+floor |
| T-4.6 AI/MCP fixture + e2e (+MCP detect +`--check-kb-refs`) | L | code+fixtures+tests | last | the two reconciliation sub-tasks land here |

Order: **spike-05 → T-4.1 → (T-4.2 ∥ T-4.4) → T-4.3 → T-4.5 → T-4.6.**

**Risks / open questions:**
- *Currency (top risk, mirrors Phase-2 CVEs):* the AI threat taxonomy moves fast and is the project's
  whole premise. **spike-05 must re-verify against 2026 sources BEFORE T-4.2/T-4.3**: the OWASP LLM
  Top-10 **2025** list + IDs (esp. LLM01/LLM05), MITRE **ATLAS** technique ids (`AML.T….`) for each of
  the five classes, whether an **OWASP Agentic/ASI** ranking exists and its real naming/numbering
  (distrust invented `ASIxx`), and a citable **MCP** source (token-passthrough / RFC 8707 audience
  binding / tool-description poisoning). Any id that can't be confirmed → write the *pattern* and tag
  the id `unverified` (don't block). API Top 10 is **2023** (no 2025/26 edition) — confirm that too.
- *LLM01 vs LLM05 precision:* LLM01 is exclusion-listed (architectural) — emitting it as a HIGH finding
  would be a false positive by our own rules. Keep it a design note; make LLM05 the reportable sink.
- *VC-grep portability (known gotcha):* T-4.3's original `grep -qiE "$k"` with `\|` would hit the BSD
  `-E` literal-pipe bug — rewritten below to BRE `grep -qi`. (See `vc-grep-gotchas` memory.)
- *No live AI-redteam tool here:* the AI pass runs the static floor; don't claim a behavioral redteam.

**Definition of Done (phase):** all six tasks `done (verified)` + spike-05 resolved; `validate_kb.py`
green on the five seed entries; `ai-llm.md`/`api.md` de-stubbed and covering their areas; `ai-llm-review`
triggers on `ai_pass` and cites `kb_refs`; the AI/MCP fixture flips `ai_pass`, the pass flags the LLM05
sink + lethal-trifecta path (KB-cited) and spares the clean look-alike, findings validate + every
`kb_ref` resolves to a KB entry; `detect_tools` gains MCP detection and `validate_findings.py` gains
`--check-kb-refs` (both tested); living docs + statuses updated. Then **re-groom Phase 5** (rolling-wave).

---

### T-4.1 · Define the KB entry schema + seed `ai-attack-kb/SKILL.md` as a pure TOC
- **Goal:** `ai-attack-kb/SKILL.md` becomes a < 500-line progressive-disclosure TOC over
  `reference/<technique-class>.md`; an entry schema (si-08 §2.2 fused Sigma+Semgrep front-matter:
  `id` typed/never-reused, `title`, `technique_class` from a controlled vocab, `severity`, `confidence`,
  `status ∈ {active,archived,deprecated}`, `date`, `modified`, `review_by`, `metadata.{source,url,
  retrieved}` **mandatory**, `supersedes`, `detections`, `xref`) is documented and accompanied by a
  **functional** validator.
- **Approach:** (1) write `kb-entry-schema.json` (draft 2020-12, `additionalProperties:false`,
  `metadata.{source,url,retrieved}` required, `technique_class` enum = the five stems, `status` enum,
  `id` pattern); (2) build `scripts/validate_kb.py` that parses each entry's YAML front-matter
  (`uv run --with pyyaml`), validates it, and enforces size caps (≤120-word summary, ≤400-line file) +
  unique ids across the dir; (3) rewrite `SKILL.md` as a TOC (what each class covers, how progressive
  disclosure loads them, the entry-format contract). T-8.1 later adds `review_by`/refresh gating only.
- **Artifact:** `.claude/skills/ai-attack-kb/SKILL.md`, `.claude/skills/ai-attack-kb/kb-entry-schema.json`,
  `.claude/skills/ai-attack-kb/scripts/` (`validate_kb.py`, `pyproject.toml`, `conftest.py`, `tests/`)
- **Depends on:** spike-05 (for the controlled vocab + xref conventions)
- **Edge cases / test notes:** entry missing `metadata.source`/`url`/`retrieved` → fails; bad
  `technique_class` / `status` → fails; duplicate `id` across files → fails; oversize file/summary → fails.
- **Verification criteria:**
  - [x] `SKILL.md` is a TOC, < 500 lines, de-stubbed — `awk 'END{exit !(NR<500)}' .claude/skills/ai-attack-kb/SKILL.md && ! grep -q 'STATUS: STUB' .claude/skills/ai-attack-kb/SKILL.md` *(96 lines, no stub banner ✓)*
  - [x] Schema requires `metadata.source`+`url`+`retrieved` and a controlled `technique_class` enum; a fixture entry missing `source` fails — `uv run --with jsonschema --with pyyaml --with pytest pytest .claude/skills/ai-attack-kb/scripts/tests/` *(18 tests pass)*
  - [x] `status` enum is exactly `{active, archived, deprecated}` and `id` matches a typed pattern — asserted in the test *(test_status_enum_is_exactly_…, test_id_pattern_is_typed)*
- **Status:** done

### T-4.2 · Fill the seed KB reference entries (dated, sourced, active)
- **Goal:** the five on-disk `reference/*.md` files (`prompt-injection`, `tool-poisoning`,
  `rag-poisoning`, `excessive-agency`, `data-exfil`) carry real seed entries conforming to T-4.1 with
  dated provenance (ATLAS `AML.T*` / OWASP `ASIxx`/`LLMxx` / CVE), mapping technique → detection pattern
  → checklist item (ADR-012). Anchored to OWASP LLM Top 10 **2025** + Agentic 2026 + ATLAS, **with every
  id confirmed by spike-05** (unconfirmed ids tagged `unverified`, pattern still written).
- **Approach:** one entry per file (YAML front-matter per the format decision); body = technique →
  detection pattern (a grep/semgrep hint or behavioral check) → the checklist item it maps to in
  `ai-llm.md`. Use only spike-05-confirmed `xref` ids.
- **Artifact:** `.claude/skills/ai-attack-kb/reference/{prompt-injection,tool-poisoning,rag-poisoning,
  excessive-agency,data-exfil}.md`
- **Depends on:** spike-05, T-4.1
- **Edge cases / test notes:** keep each ≤120-word summary / ≤400-line file; `status:active`; no secret
  or live-exploit payloads in entries (KB is a detection reference, not an exploit kit).
- **Verification criteria:**
  - [x] Every entry validates against the T-4.1 schema — `uv run --with jsonschema --with pyyaml python .claude/skills/ai-attack-kb/scripts/validate_kb.py .claude/skills/ai-attack-kb/reference/` (exit 0) *(OK, exit 0)*
  - [x] Each file has ≥1 `active` entry with a real `AML.T\d+|ASI…|LLM\d+|CVE-\d{4}-\d+` xref — `grep -REq 'AML\.T[0-9]+|ASI[0-9]+|LLM[0-9]+|CVE-[0-9]{4}-[0-9]+' .claude/skills/ai-attack-kb/reference/`
  - [x] No `STATUS: STUB` banner remains — `! grep -rq 'STATUS: STUB' .claude/skills/ai-attack-kb/reference/`
  - [x] Size caps enforced by `validate_kb.py` (≤120-word summary, ≤400-line file) *(validator enforces; all 5 pass)*
- **Status:** done *(xref ids confirmed by spike-05; AML.T0110 tagged medium-confidence inline)*

### T-4.3 · Fill `_shared/reference/ai-llm.md` (the inner-loop AI checklist)
- **Goal:** replace the stub with PLAN §5.3 content mapped to OWASP LLM Top 10 (2025) / MCP / Agentic
  ASI 2026: LLM01 prompt injection (**architectural-only, exclusion-listed — design note, not a HIGH**),
  **LLM05 improper output handling (highest yield — the reportable code sink)**, lethal trifecta /
  Agents Rule of Two, MCP token-passthrough / tool-poisoning / confused-deputy, RAG/vector poisoning +
  cross-tenant leakage, unbounded consumption, excessive agency — each cross-linking the `ai-attack-kb`
  technique class.
- **Approach:** pattern-first dangerous→safe pairs for LLM05 (model/tool/RAG output flowing into
  eval/exec/SQL/HTML/path/URL/template/deserializer), the lethal-trifecta architectural test, and the
  MCP checks; explicitly mark LLM01 as architectural (point at the exclusion rule). Cross-link each
  section to its KB class. ≤400 lines.
- **Artifact:** `.claude/skills/_shared/reference/ai-llm.md`
- **Depends on:** spike-05, T-4.2
- **Edge cases / test notes:** avoid time-sensitive phrasing in the body (ADR-005); keep exploit detail
  to detection patterns, not working payloads.
- **Verification criteria:**
  - [x] Covers all seven areas — *(BRE `grep -qi`, not `-qiE`: `\|` is a literal pipe under macOS `grep -E`)* `for k in 'LLM01\|prompt injection' 'LLM05\|improper output' 'lethal trifecta\|rule of two' 'MCP' 'RAG\|vector' 'unbounded\|consumption' 'excessive agency'; do grep -qi "$k" .claude/skills/_shared/reference/ai-llm.md || echo MISSING:"$k"; done` prints nothing *(no MISSING)*
  - [x] LLM05 flagged as the highest-yield code check; LLM01 marked architectural/exclusion — `grep -qi 'highest.yield\|highest yield' .claude/skills/_shared/reference/ai-llm.md && grep -qi 'architectural\|exclusion' .claude/skills/_shared/reference/ai-llm.md`
  - [x] Cross-links the KB — `grep -q 'ai-attack-kb' .claude/skills/_shared/reference/ai-llm.md`; de-stubbed; ≤400 lines *(121 lines)*
- **Status:** done

### T-4.4 · Fill `_shared/reference/api.md` (OWASP API Top 10 2023)
- **Goal:** replace the stub with PLAN §5.4 content: BOLA(#1)/BFLA/BOPLA, broken auth, unrestricted
  consumption, SSRF, unsafe third-party consumption — with the explicit "no 2025/2026 API edition
  exists; distrust 'API Top 10 2026' claims" caveat and the highest-value generic check (re-verify
  authenticated principal server-side per object/function, default-deny).
- **Approach:** pattern-first per class (BOLA = object-id not re-scoped to caller; BFLA = function/role
  not checked; BOPLA = mass-assignment in + over-exposure out); the generic default-deny re-verification
  rule; the edition caveat. ≤400 lines.
- **Artifact:** `.claude/skills/_shared/reference/api.md`
- **Depends on:** — (spike-05 confirms "no 2025/26 edition" in passing)
- **Edge cases / test notes:** distinguish authN (broken auth) from authZ (BOLA/BFLA); note SSRF cross-
  links the core SSRF category (don't duplicate).
- **Verification criteria:**
  - [x] Covers BOLA/BFLA/BOPLA + the four others with `APIx:2023` IDs — `grep -qi 'bola' .claude/skills/_shared/reference/api.md && grep -qi 'bfla' .claude/skills/_shared/reference/api.md && grep -qE 'API[0-9]+:2023' .claude/skills/_shared/reference/api.md` *(API1–API10:2023 all present)*
  - [x] States the "no 2025/26 API edition" caveat — `grep -qi 'distrust' .claude/skills/_shared/reference/api.md && grep -qi '2023' .claude/skills/_shared/reference/api.md`
  - [x] De-stubbed; ≤400 lines — `! grep -q 'STATUS: STUB' .claude/skills/_shared/reference/api.md` *(111 lines)*
- **Status:** done

### T-4.5 · Implement `ai-llm-review` body (consumes KB; AI-redteam capability)
- **Goal:** `ai-llm-review/SKILL.md` documents the AI pass triggered by `SCAN-PLAN.json` `ai_pass:true`:
  partition the agent/LLM/MCP surface, check the `ai-llm.md` classes, **load `ai-attack-kb` entries on
  demand**, attach `kb_refs` to findings, and optionally use an AI-redteam capability (illustrative:
  promptfoo/garak/Inspect) with floor degradation — merging into `VULN-FINDINGS.json`.
- **Approach:** document the partition (system prompt / tool defs / RAG ingestion / output sinks / MCP
  surface), the LLM05-first stance (highest yield; LLM01 → architectural note per exclusion), the
  KB-load-on-demand + `kb_refs` attachment, and the AI-redteam-or-floor selection via `category_tool
  ["ai-redteam"]` + `degradation.py`. Treat all model/tool/RAG output as untrusted (Agents Rule of Two).
- **Artifact:** `.claude/skills/ai-llm-review/SKILL.md`
- **Depends on:** T-4.2, T-4.3, T-1.1, T-2.2
- **Edge cases / test notes:** `ai_pass:false` → the pass is skipped entirely (no AI noise on non-AI repos).
- **Verification criteria:**
  - [x] Triggered by `SCAN-PLAN.json` `ai_pass` and loads KB entries (progressive disclosure) — `grep -qi 'ai_pass\|SCAN-PLAN' .claude/skills/ai-llm-review/SKILL.md && grep -q 'ai-attack-kb' .claude/skills/ai-llm-review/SKILL.md`
  - [x] Findings carry `kb_refs` to KB entry ids; LLM05-first / LLM01-architectural stance documented — `grep -qi 'kb_refs' … && grep -qi 'llm05' … && grep -qi 'architectural\|exclusion' .claude/skills/ai-llm-review/SKILL.md`
  - [x] AI-redteam capability optional with floor degradation (ADR-015/003) — `grep -qi 'degrad\|floor\|optional' .claude/skills/ai-llm-review/SKILL.md`
  - [x] Stub banner removed (de-stubbed); output validates against T-1.1 *(76 lines; `kb_refs` is in the schema; `--check-kb-refs` enforcement is exercised in T-4.6)*
- **Status:** done

### T-4.6 · AI/MCP fixture + end-to-end AI-pass demonstration
- **Goal:** a small AI/MCP fixture (an LLM05 improper-output-handling sink + a lethal-trifecta path +
  one MCP token-passthrough) so `sec-detect` triggers the AI pass and `ai-llm-review` flags them with
  KB-cited findings; plus a clean look-alike that must not fire. **Closes the two reconciliation
  sub-tasks:** MCP detection in `detect_tools`, and `--check-kb-refs` in `validate_findings.py`.
- **Approach:** (1) **add `mcp`/`modelcontextprotocol`/`@modelcontextprotocol/sdk` to
  `detect_tools.AI_FRAMEWORK_SIGNALS`** + a `sec-detect` test (so an MCP repo flips `ai_pass`); (2) **add
  `--check-kb-refs <kb-dir>` to `validate_findings.py`** (every finding `kb_ref` id resolves to a KB
  entry `id`) + a `_shared` test; (3) build the fixture (a vulnerable AI/MCP file + a clean look-alike)
  with a `requirements.txt`/`package.json` importing an AI/MCP dep; (4) run detect → AI pass → log the
  KB-cited findings + the spared look-alike.
- **Artifact:** `docs/research/poc-ai-review/` (fixtures + `README.md` with expected `file:line` + KB ids),
  edits to `detect_tools.py` (+ test) and `validate_findings.py` (+ test)
- **Depends on:** T-4.5 (and uses T-4.1/4.2 KB ids)
- **Edge cases / test notes:** the clean look-alike (schema-validated structured output before the sink)
  must NOT fire; an MCP-only repo (no langchain/openai) must still flip `ai_pass` after sub-task 1.
- **Verification criteria:**
  - [x] `detect_tools` flips `ai_pass:true` on the fixture (AI/MCP dep) incl. an MCP-only manifest — `uv run --with jsonschema python .claude/skills/sec-detect/scripts/detect_tools.py docs/research/poc-ai-review/ai-vuln | python3 -c 'import json,sys;assert json.load(sys.stdin)["ai_pass"]'` + a `sec-detect` MCP test *(ai-vuln + ai-vuln-mcp-only both True; +4 MCP tests, incl. no-overmatch)*
  - [x] The AI pass flags the LLM05 sink + lethal-trifecta path with non-empty `kb_refs`, and does NOT flag the clean look-alike — before/after logged in README *(F-001 LLM05@28, F-002 trifecta@40, F-003/F-004 MCP; look-alike spared — see `poc-ai-review/README.md`)*
  - [x] Findings validate against T-1.1 and every `kb_ref` resolves — `uv run --with jsonschema python .claude/skills/_shared/scripts/validate_findings.py docs/research/poc-ai-review/EXPECTED-FINDINGS.json --check-kb-refs .claude/skills/ai-attack-kb/reference/` + the new `_shared` test *(OK; +6 `--check-kb-refs` tests)*
- **Status:** done *(fixture findings file named `EXPECTED-FINDINGS.json` — the live-chain name `VULN-FINDINGS.json` is gitignored)*
