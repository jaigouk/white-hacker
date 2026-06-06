# Phase 2 — Threat model + detect (aim before you shoot)

> **Theme:** add the two stages that scope and calibrate a review: `sec-threat-model` (synthesize/ingest
> `THREAT_MODEL.md`, pick the scoring standard) and `sec-detect` (auto-detect languages/frameworks,
> select scanners **by capability**, emit `SCAN-PLAN.json`). Fill the per-language reference appendices
> loaded on demand.
> **Maps to:** PLAN §8.1 P2, §3 (detection), §5.2 (per-language); ADR-009, ADR-015 (capabilities).
>
> **Loop position:** INNER. Threat-model fidelity is the top precision lever (~90% exploitable findings
> when well-defined, PLAN §G4/§6).
> **Exit condition:** a real repo yields a `THREAT_MODEL.md` (assets/entry-points/trust-boundaries/
> in-scope classes/scoring standard) and a `SCAN-PLAN.json` naming detected langs, frameworks, the
> AI-pass trigger, and a **capability → chosen-tool-or-degraded** map; `sec-vuln-scan` consumes both.

---

## Grooming (refined 2026-06-06)

**Readiness:** ✅ READY. Prerequisites met — Phase 0 (6/6) and Phase 1 (5/5) are `done (verified)`;
the floor loop, the finding schema, and the two reference files this phase extends all exist.

**Definition of Ready (all satisfied):**
- The `detect_tools` PoC exists and is green (`docs/research/poc-tool-detection/`, 12 tests) → T-2.2 is a
  *promotion*, not a green-field build.
- The finding-schema + validator pattern (T-1.1) is the template for the new `SCAN-PLAN.json` schema (T-2.3).
- PLAN §3 (detection tables) and §5.2 (per-language sinks) are the content source for T-2.2 / T-2.4.
- Reference-file size cap (≤400 lines) and the stub-marker convention are established (ADR-005).

**Task sizing & sequencing:**
| Task | Size | Type | Can start | Parallelizable with |
|------|------|------|-----------|---------------------|
| T-2.1 `sec-threat-model` body | M | docs | now | T-2.2, T-2.4 |
| T-2.2 promote `detect_tools` → `sec-detect` | M | code+tests | now | T-2.1, T-2.4 |
| T-2.3 `SCAN-PLAN.json` schema + validator | S | code+tests | after T-2.2 | — |
| T-2.4 per-language refs (go/py/ts/java) | L | docs | now | T-2.1, T-2.2 |
| T-2.5 chain + prove on a real repo | M | integration | after T-2.1/2.2/2.3 | — |

Recommended order: **(T-2.1 ∥ T-2.2 ∥ T-2.4) → T-2.3 → T-2.5.** T-2.4 is the largest (four language
appendices) and fully independent — a good candidate to fan out one writer per language.

**Risks / open questions:**
- *CVE currency:* the TS/Java appendices cite 2025/2026 CVEs (Next.js CVE-2025-29927, React2Shell,
  Spring-Security gate). Re-verify each CVE id against a 2026 source before writing (verify-rule); if a
  citation can't be confirmed, write the *pattern* and mark the id `unverified`. → spike if needed.
- *Real-repo target for T-2.5:* pick a small polyglot repo the user already has locally; do not fetch
  remote code (posture: authorized targets only). Candidate: one of the user's side projects, with
  consent. If none handy, extend the fixture into a multi-file mini-repo.
- *Interactivity:* `sec-threat-model` may want `AskUserQuestion`; the `--auto`/`--fresh` fallbacks must
  make it non-interactive for CI/headless runs.
- *Schema drift:* `SCAN-PLAN.json` (T-2.3) and the `detect_tools` output (T-2.2) must agree — write the
  schema from the actual emitter output, and add the schema test to T-2.2's suite to keep them locked.

**Definition of Done (phase):** all five tasks `done (verified)`; `uv run pytest` green across
`sec-detect/scripts`; a real (or mini) repo produces a schema-valid `THREAT_MODEL.md` + `SCAN-PLAN.json`
that `sec-vuln-scan` consumes; statuses + this file + the run log updated (living-docs rule).

> **✅ PHASE COMPLETE (2026-06-06).** All five tasks `done (verified)`: 35 tests green across
> `sec-detect/scripts` (26 detect + 9 schema); the floor-review mini-repo produces a schema-valid
> `THREAT_MODEL.md` + `SCAN-PLAN.json`; discovery partitions by the named entry points; the
> `/security-review` command runs threat-model→detect→discovery→triage→report. CVE currency resolved
> via `docs/research/spike-04-phase2-cve-currency.md`. One VC-regex portability fix applied (BSD-grep
> `\|`). Next wave (Phase 3 — tools/capabilities) to be **re-groomed** before starting (rolling-wave).

---

### T-2.1 · Implement `sec-threat-model` body (ingest/synthesize + scoring standard)
- **Goal:** `sec-threat-model/SKILL.md` documents: ingest an existing `THREAT_MODEL.md` if present, else
  synthesize from docs + `git log` + past fixes; capture assets, entry points, trust boundaries, in-scope
  vuln classes, and **ask which scoring standard** (CVSS 3.1/4.0/OWASP/org bug-bar) with `--auto`/`--fresh`
  fallbacks; state assumptions when derived. Read-only Bash (`git log`) only.
- **Approach:** (1) define the `THREAT_MODEL.md` output template (the 5 sections + chosen scoring
  standard + an "assumptions/derived" note); (2) document the bootstrap inputs (architecture docs, README,
  `git log --stat`, past security fixes) and Shostack's 4 questions for the interview path; (3) specify the
  scoring-standard prompt via `AskUserQuestion`, with `--auto` (infer/default to CVSS 4.0) and `--fresh`
  (ignore any existing file) flags for headless runs; (4) emphasize read-only git, no network.
- **Artifact:** `.claude/skills/sec-threat-model/SKILL.md`
- **Depends on:** —
- **Edge cases / test notes:** no docs and no git history (greenfield) → synthesize from code structure
  and label everything "assumed"; an existing `THREAT_MODEL.md` that's stale → ingest + flag drift, don't
  silently overwrite.
- **Verification criteria:**
  - [x] Body covers ingest-or-synthesize, the five THREAT_MODEL sections, and the scoring-standard question — `for k in 'asset' 'entry[ -]point' 'trust boundar' 'in.scope' 'scoring standard'; do grep -qiE "$k" .claude/skills/sec-threat-model/SKILL.md || echo MISSING:"$k"; done` prints nothing *(regex made BSD-grep portable: `\|` is a literal pipe under macOS `grep -E`, so alternation is written as `[ -]` / `.`)*
  - [x] Declares output `THREAT_MODEL.md` and read-only git usage — `grep -q 'THREAT_MODEL.md' .claude/skills/sec-threat-model/SKILL.md && grep -qi 'git log' .claude/skills/sec-threat-model/SKILL.md`
  - [x] Documents `--auto`/`--fresh` non-interactive fallbacks (PLAN §8.1 P2) — `grep -qE '\-\-auto|\-\-fresh' .claude/skills/sec-threat-model/SKILL.md`
  - [x] stub banner removed — `! grep -q 'STATUS: STUB' .claude/skills/sec-threat-model/SKILL.md`
- **Status:** done (verified 2026-06-06; five sections + scoring-standard question + --auto/--fresh + read-only git documented)

### T-2.2 · Promote tool/lang detection PoC into `sec-detect` scripts
- **Goal:** move `docs/research/poc-tool-detection/detect_tools.py` (manifest→lang, framework
  fingerprint, capability→scanner preference, graceful-degradation `ScanPlan`) into the skill as the
  emitter of `SCAN-PLAN.json`, keeping the injectable `which` seam for tests and the `degraded`/
  `tools_unavailable` fields (ADR-003, ADR-015).
- **Approach:** (1) copy `detect_tools.py` + its 12 tests into `sec-detect/scripts/` (+ `pyproject.toml`,
  `conftest.py` for import path — mirror the `_shared/scripts` pattern); (2) **extend** it with the
  framework-fingerprint layer from PLAN §3.2 (detect `next`/`react`/`express` (TS), `django`/`flask`/
  `fastapi` + `langchain`/`openai`/`anthropic`/`transformers`/`torch` (Py), `gin`/`chi` (Go),
  `spring-boot`/`jackson` (Java)) and an `ai_pass: bool` set when AI deps are present; (3) make the CLI
  emit a `SCAN-PLAN.json`-shaped object (langs, infra, frameworks, capability→tool map, degraded list,
  `ai_pass`, applicable reference appendices); (4) keep `which` injectable so tests stay hermetic.
- **Artifact:** `.claude/skills/sec-detect/scripts/detect_tools.py` (+ `pyproject.toml`, `tests/`),
  `.claude/skills/sec-detect/SKILL.md`
- **Depends on:** —
- **Edge cases / test notes:** monorepo with multiple languages (emit all); language present but no
  tool for its capability (degrade, list in `tools_unavailable`); AI deps present → `ai_pass:true` even
  for a non-Python stack (e.g. a TS LangChain app). Keep the PoC's existing edge-case tests; add ≥3 new
  ones for the framework/ai_pass layer.
- **Verification criteria:**
  - [x] Ported tests pass (≥ the PoC's 12) — `uv run --with jsonschema --with pytest pytest .claude/skills/sec-detect/scripts/` (26 detect tests, ≥12 ported)
  - [x] Detection is capability-keyed (`sast/sca/secrets/iac/ai-redteam` → ordered tool prefs, brands swappable) and degrades when a category has no tool — `test_plan_degrades_when_category_tool_missing`, `test_ai_redteam_degrades_to_floor_when_no_tool`
  - [x] CLI emits valid `SCAN-PLAN.json` — `uv run --with jsonschema python .claude/skills/sec-detect/scripts/detect_tools.py . | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "category_tool" in d and "degraded" in d'`
  - [x] Framework fingerprint sets `ai_pass` when AI deps present — `test_ai_pass_true_for_python_langchain`, `test_ai_pass_true_for_typescript_stack`
  - [x] `SKILL.md` documents the framework-fingerprint → AI-pass trigger and stub banner removed — `grep -qi 'ai-llm-review\|ai pass\|ai_pass' .claude/skills/sec-detect/SKILL.md && ! grep -q 'STATUS: STUB' .claude/skills/sec-detect/SKILL.md`
- **Status:** done (verified 2026-06-06; 26 detect tests pass, framework+ai_pass+ai-redteam layer added, SCAN-PLAN emitter validated)

### T-2.3 · Define the `SCAN-PLAN.json` schema + validator
- **Goal:** a JSON Schema for `SCAN-PLAN.json` (languages, infra, frameworks, capability→tool map,
  degraded categories, `ai_pass: bool`, applicable reference appendices) so downstream stages and CI can
  validate it, mirroring T-1.1 for findings.
- **Approach:** write the schema **from the actual T-2.2 emitter output** (generate a sample, derive the
  schema, then constrain). Reuse `_shared/scripts/validate_findings.py`'s structure for a tiny
  `validate_scan_plan` (or generalize the existing validator to take a schema path). Add its test to
  T-2.2's suite so emitter and schema can't drift.
- **Artifact:** `.claude/skills/sec-detect/scan-plan-schema.json` (+ a test in T-2.2's suite)
- **Depends on:** T-2.2
- **Edge cases / test notes:** empty repo (no langs) still valid; `additionalProperties:false` to catch
  typos; unknown capability key rejected; `degraded` required.
- **Verification criteria:**
  - [x] PoC/emitter output validates against the schema — `uv run --with jsonschema --with pytest pytest .claude/skills/sec-detect/scripts/tests/test_scan_plan_schema.py` (9 tests)
  - [x] A plan missing `degraded` or with an unknown capability key is rejected — `test_missing_degraded_is_rejected`, `test_unknown_capability_key_is_rejected`, `test_unknown_degraded_capability_is_rejected`, `test_additional_root_property_is_rejected`, `test_wrong_type_ai_pass_is_rejected`
  - [x] Schema is valid draft 2020-12 (meta-validate) and referenced by `sec-detect/SKILL.md` — `test_schema_is_valid_draft_2020_12` + `grep -q 'scan-plan-schema.json' .claude/skills/sec-detect/SKILL.md`
- **Status:** done (verified 2026-06-06; schema derived from emitter, locked by test_scan_plan_schema.py, 9 tests incl. 5 negatives)

### T-2.4 · Fill per-language reference appendices (`lang-{go,python,typescript,java}.md`)
- **Goal:** replace the four stubs with the PLAN §5.2 content (Go `os.Root`/govulncheck/gosec;
  Python SSTI/pickle/yaml.load/torch.load/eval; TS Next.js CVE-2025-29927 + React2Shell + prototype
  pollution + `eval`/`vm2`; Java Spring-Security version-gate + Jackson default-typing + XXE + SpEL),
  each loaded on demand by `sec-vuln-scan`/`sec-triage`.
- **Approach:** one writer per language (parallelizable). Each appendix: dangerous→safe snippet pairs,
  the framework-specific sinks, the native tool to run (from the registry, as examples), and a short
  "what to grep for" list. **Re-verify each cited CVE id** against a 2026 source first; write the pattern
  regardless and tag any unconfirmed id `unverified`. Keep ≤400 lines; one level deep.
- **Artifact:** `.claude/skills/_shared/reference/lang-go.md`, `lang-python.md`, `lang-typescript.md`,
  `lang-java.md`
- **Depends on:** —
- **Edge cases / test notes:** avoid time-sensitive phrasing in the body (ADR-005); put any deprecated
  technique under a `## Deprecated <details>` block so it doesn't pollute current guidance.
- **Verification criteria:**
  - [x] Each file > 30 lines and free of the stub banner — `for f in go python typescript java; do { awk 'END{exit !(NR>30)}' .claude/skills/_shared/reference/lang-$f.md && ! grep -q 'STATUS: STUB' .claude/skills/_shared/reference/lang-$f.md; } || echo FAIL:$f; done` prints nothing (go 66, java 72, python 74, ts 72 lines)
  - [x] Signature sinks present per language — `grep -qi 'os.Root\|govulncheck' lang-go.md && grep -qi 'pickle\|yaml.load' lang-python.md && grep -qiE '29927|react2shell|prototype pollution' lang-typescript.md && grep -qiE 'jackson|spel|ObjectInputStream' lang-java.md`
  - [x] Each ≤ 400 lines (reference cap) — all four well under (max 74)
  - [x] CVE ids re-verified against 2026 sources before writing — `docs/research/spike-04-phase2-cve-currency.md` (none needed the `unverified` tag)
- **Status:** done (verified 2026-06-06; four appendices, pattern-first, CVE ids confirmed via spike-04)

### T-2.5 · Chain threat-model + detect into the command and prove on a real repo
- **Goal:** `/security-review` and the agent loop now run threat-model → detect before discovery; a real
  polyglot repo (or the extended fixture) produces both upstream artifacts and `sec-vuln-scan` reads them.
- **Approach:** update `commands/security-review.md` (and note in the agent loop) so the order is
  threat-model → detect → discovery → triage → report. Run on a chosen repo; capture `THREAT_MODEL.md` +
  `SCAN-PLAN.json` under `docs/research/poc-floor-review/run/`; show `sec-vuln-scan` partitions by the
  entry points the threat model named.
- **Artifact:** `docs/research/poc-floor-review/README.md` (threat-model + detect run notes), updated
  `commands/security-review.md`
- **Depends on:** T-2.1, T-2.2, T-2.3, T-0.4
- **Edge cases / test notes:** headless run must use `--auto` (no AskUserQuestion); confirm a degraded
  capability still produces a usable plan.
- **Verification criteria:**
  - [x] A run on a real/mini repo emits a `THREAT_MODEL.md` with all five sections + chosen scoring standard (logged) — `run/THREAT_MODEL.md` (synthesized, CVSS 4.0, 3 entry points)
  - [x] The same run emits a `SCAN-PLAN.json` that validates against T-2.3 and lists detected langs + capability map + `ai_pass` — `run/SCAN-PLAN.json` validates; langs `go,python,typescript`, frameworks `express,flask`, `ai_pass:false`, `degraded:[sast,secrets]`
  - [x] `sec-vuln-scan` partitions according to the entry points named in `THREAT_MODEL.md` (manual spot-check logged) — all 3 entry points map to discovery candidates at exact `file:line` (README Phase-2 table)
- **Status:** done (verified 2026-06-06; chain run end-to-end on the floor-review mini-repo; command order updated to threat-model→detect→discovery→triage→report)
