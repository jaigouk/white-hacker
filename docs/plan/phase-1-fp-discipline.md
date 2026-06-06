# Phase 1 — FP discipline + structure (where the real quality lives)

> **Theme:** turn the inline triage into the precision engine: `sec-triage` adversarial N-of-N voting,
> the exclusion list, precondition-counted severity, **the strict JSON finding schema**, and dedup-by-
> root-cause. Plus a separate `sec-vuln-scan` (recall) stage so discovery and triage are distinct.
> **Maps to:** PLAN §8.1 P1, §6, §2.3; ADR-008 (recall/precision split), ADR-009 (artifact chaining).
>
> **Loop position:** INNER. This is the highest-leverage element (PLAN §6.2: adversarial verification
> roughly halved non-exploitable findings in Anthropic's data).
> **Exit condition:** `VULN-FINDINGS.json → sec-triage → TRIAGE.json` validates against the schema,
> deduped, with severity derived in triage; the decision-maker sees only `{file,line,category,diff}`.

The schema (T-1.1) is the keystone — every later JSON artifact and every eval gate validates against it.

---

### T-1.1 · Replace the finding-schema stub with the real JSON Schema
- **Goal:** `_shared/reference/finding-schema.json` becomes a real JSON Schema (draft 2020-12) matching
  the agent output contract (`.claude/agents/white-hacker.md` §Output contract): `summary{scanned_langs,
  tools_used, tools_unavailable, scoring_standard, counts{high,medium,low}}` + `findings[]{id,
  canonical_of, file, line, severity(enum), category, owasp[], preconditions[], access_required,
  verified(enum), confidence, exploit_scenario, recommendation, first_link, tool_assisted, kb_refs[]}`.
- **Artifact:** `.claude/skills/_shared/reference/finding-schema.json` + `_shared/scripts/` validator
  package (`validate_findings.py`, `pyproject.toml`, `tests/`)
- **Depends on:** —
- **Verification criteria:**
  - [ ] Schema is valid draft 2020-12 and the agent's contract sample validates against it — `uv run pytest .claude/skills/_shared/scripts/tests/test_validate_findings.py`
  - [ ] `verified` enum is exactly `{ladder_passed, ladder_failed, static_review_only}` and `severity` enum is `{HIGH, MEDIUM, LOW}` — asserted by a test case
  - [ ] A malformed finding (missing required field, bad enum, `confidence > 1`) is **rejected** — negative test in the suite (TDD; >1 test, edge cases per ADR-013)
  - [x] `_comment: STUB` removed — `! grep -q 'STUB' .claude/skills/_shared/reference/finding-schema.json`
- **Status:** done (verified 2026-06-06; 15 tests pass, schema meta-validates as draft 2020-12)

### T-1.2 · Implement `sec-vuln-scan` (discovery, RECALL-optimized)
- **Goal:** `sec-vuln-scan/SKILL.md` body documents partition-the-attack-surface-then-fan-out, simple
  non-prescriptive prompts, "do not self-censor / record unproven candidates flagged", and emits
  `VULN-FINDINGS.json` (schema-shaped, `verified: static_review_only`, candidate confidences allowed
  below the report gate). Floor-only at this phase (tools land Phase 3).
- **Artifact:** `.claude/skills/sec-vuln-scan/SKILL.md` (+ `reference/` if needed)
- **Depends on:** T-1.1
- **Verification criteria:**
  - [ ] SKILL body documents partition → fan-out → system-level pass and the no-self-censor rule — `grep -qi 'partition' .claude/skills/sec-vuln-scan/SKILL.md && grep -qi 'self-censor' .claude/skills/sec-vuln-scan/SKILL.md`
  - [ ] Output is declared as `VULN-FINDINGS.json` conforming to T-1.1 — `grep -q 'VULN-FINDINGS.json' .claude/skills/sec-vuln-scan/SKILL.md`
  - [ ] `STATUS: STUB` banner gone; `SKILL.md` < 500 lines — `! grep -q 'STATUS: STUB' .claude/skills/sec-vuln-scan/SKILL.md && awk 'END{exit !(NR<500)}' .claude/skills/sec-vuln-scan/SKILL.md`
  - [x] A discovery run on the Phase-0 fixture emits schema-valid JSON — `uv run python .claude/skills/_shared/scripts/validate_findings.py <run-output>`
- **Status:** done (verified 2026-06-06; discovery.json over-reports 6, schema-valid)

### T-1.3 · Implement `sec-triage` body (adversarial N-of-N, exclusion, precondition severity)
- **Goal:** `sec-triage/SKILL.md` body documents: fresh context with no shared history; per-finding
  "assume FP, refute it" (trace reachability backward, hunt protections); adversarial N-of-N voting
  (default 3) with the fixed `VERDICT/CONFIDENCE/REFUTE_REASON/EXCLUSION_RULE/FIRST_LINK/RATIONALE`
  block; context starvation (`{file,line,category,diff}` only); apply exclusion list + confidence gate;
  derive precondition-counted severity; emit `TRIAGE.json`.
- **Artifact:** `.claude/skills/sec-triage/SKILL.md`
- **Depends on:** T-0.2, T-0.3, T-1.1
- **Verification criteria:**
  - [ ] Body documents all five: fresh-context, assume-FP, N-of-N voting, context starvation, precondition severity — `for k in 'fresh' 'false positive' 'N-of-N\|N of N\|voting' 'file, *line, *category, *diff\|context starvation' 'precondition'; do grep -qiE "$k" .claude/skills/sec-triage/SKILL.md || echo MISSING:"$k"; done` prints nothing
  - [ ] Declares the fixed voter output block fields — `grep -q 'VERDICT' .claude/skills/sec-triage/SKILL.md && grep -q 'REFUTE_REASON' .claude/skills/sec-triage/SKILL.md`
  - [ ] References `severity-rubric.md` + `exclusion-rules.md` (no copy-paste drift) — `grep -q 'severity-rubric' .claude/skills/sec-triage/SKILL.md && grep -q 'exclusion-rules' .claude/skills/sec-triage/SKILL.md`
  - [x] `STATUS: STUB` gone; `lint_skill` passes once it exists (T-8.1) — `! grep -q 'STATUS: STUB' .claude/skills/sec-triage/SKILL.md`
- **Status:** done (verified 2026-06-06; all method keywords + voter block + refs present)

### T-1.4 · Dedup-by-root-cause (two-pass) + canonical-id rule
- **Goal:** the dedup rule ("two findings are duplicates if fixing one fixes the other") is implemented:
  cheap deterministic pass (same file + same category + lines within 10) shippable as a tested script;
  the LLM semantic cross-file pass is documented in `sec-triage`. Every finding appears once; duplicates
  carry `canonical_of`.
- **Artifact:** `.claude/skills/sec-triage/scripts/dedup_findings.py` (+ `pyproject.toml`, `tests/`)
- **Depends on:** T-1.1
- **Verification criteria:**
  - [ ] Deterministic pass collapses same-file/same-category/within-10-lines pairs and sets `canonical_of` — `uv run pytest .claude/skills/sec-triage/scripts/tests/test_dedup_findings.py`
  - [ ] Idempotent: re-running dedup on its own output is a no-op — assertion test
  - [ ] Non-duplicates (different category, or > 10 lines apart) are NOT collapsed — negative test (TDD, >1 test)
  - [x] Output still validates against T-1.1 schema — test asserts schema-valid result
- **Status:** done (verified 2026-06-06; 9 dedup tests pass incl. idempotency + schema-valid)

### T-1.5 · End-to-end recall→precision smoke on the Phase-0 fixture
- **Goal:** prove the split pipeline: `sec-vuln-scan` over-reports candidates (recall) → `sec-triage`
  refutes the look-alikes and keeps the planted vulns (precision), with deterministic dedup applied.
- **Artifact:** `docs/research/poc-floor-review/README.md` (pipeline-run notes + before/after counts)
- **Depends on:** T-1.2, T-1.3, T-1.4
- **Verification criteria:**
  - [ ] Discovery flags ≥ the planted count (recall) and triage's `counts` drop the clean look-alikes (precision) — before/after table logged in README
  - [ ] Final `TRIAGE.json` validates against the schema — `uv run python .claude/skills/_shared/scripts/validate_findings.py TRIAGE.json`
  - [ ] Severity on each kept finding was derived in triage from listed `preconditions` (not the finder's score) — manual spot-check logged, `access_required` present on every finding
  - [x] No duplicate `id`s; duplicates reference a canonical id — `uv run python .claude/skills/_shared/scripts/validate_findings.py TRIAGE.json --no-dup-ids`
- **Status:** done (verified 2026-06-06; 6→3 recall→precision, TP=3 FP=0 FN=0, both artifacts schema-valid)
