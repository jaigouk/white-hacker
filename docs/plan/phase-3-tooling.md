# Phase 3 — Tooling as a swappable capability layer (+ degradation)

> **Theme:** wire the enhancer capabilities on top of the floor — **secrets**, **SCA**, **SAST**,
> **IaC** — each as a *capability with degradation*, never a hard tool dependency (ADR-015). Ship
> `secrets-scan` and `deps-scan`, and make discovery prefer installed tools while always degrading to
> the Read/Grep/Glob floor. The tool registry is itself part of the self-improving loop.
> **Maps to:** PLAN §8.1 P3, §4 (tool strategy), §3.3 (scanner selection); ADR-002, ADR-003, ADR-006,
> ADR-011, **ADR-015**.
>
> **Loop position:** INNER. Enhancers raise recall/precision but the value floor stands without them.
> **Exit condition:** on a host with a given capability present, the matching skill uses it and emits
> schema-valid findings; on a host without it, the same skill degrades, marks `tool_assisted:false`,
> caps confidence, and lists the capability under `tools_unavailable` — **no skill ever blocks**.

Every task here reads as **"wire capability X + degradation"**, not "install tool Y". Named tools
(Opengrep, OSV-Scanner, Trivy, gitleaks, trufflehog, govulncheck/pip-audit/npm audit) are illustrative
defaults the registry lists; an equivalent tool plugs in behind the same capability.

---

## Grooming (refined 2026-06-06, after Phase 2)

**Readiness:** ✅ READY. Phase 0 (6/6), Phase 1 (5/5), Phase 2 (5/5) are `done (verified)`.

**Definition of Ready — reconciled against what Phase 2 actually built:**
- `detect_tools.py::SCANNER_PREFERENCE` (in `sec-detect/scripts/`) is now the **executable**
  capability→tool map (sast/sca/secrets/iac/ai-redteam, ordered prefs, injectable `which`,
  `category_tool`/`degraded`/`available_tools`). `tool-registry.md` is its **human-facing twin** —
  T-3.1 becomes *verify + cross-link the two so they can't drift*, not a greenfield write.
- `tool-registry.md` was **already seeded in Phase 0** with all five capabilities, floor fallbacks,
  the "illustrative defaults" wording, the self-updating note, and the pinning rule → T-3.1's VCs are
  largely already met; the work is a lock test + Trivy-version specifics + the code cross-reference.
- `SCAN-PLAN.json` (Phase 2) carries `category_tool` + `degraded` + `available_tools`; the
  finding-schema `summary` carries `tools_used` + `tools_unavailable` and each finding carries
  `tool_assisted`. **These two artifacts are the seam degradation flows through** — a finding's
  `tool_assisted` and the summary's `tools_unavailable` are *derived from* the SCAN-PLAN, not invented.
- `docs/research/poc-trivy-sca/trivy-output.json` is a **real 13-vuln Trivy SCA capture**
  (`Results[].Vulnerabilities[]` with `VulnerabilityID/PkgName/InstalledVersion/FixedVersion/Severity/
  Title/PrimaryURL`, Target `requirements.txt`, Type `pip`) → the `deps-scan` normalizer fixture.
- `finding-schema.json` (T-1.1) + `validate_findings.py` are the output contract + validator every
  normalizer must satisfy.

**Host capability reality (probed 2026-06-06) — drives what is *demonstrated* vs *tested via injected `which`*:**
| Capability | This host | Phase-3 consequence |
|------------|-----------|---------------------|
| SCA | `trivy` 0.69.0 + `govulncheck` present | **real** Trivy SCA normalize (fixture) + Go native gate demonstrable |
| IaC | `trivy` present | **real** `trivy config` on a Dockerfile fixture demonstrable |
| SAST | opengrep/semgrep/gosec/bandit **all absent** | **cannot** run live SAST → verify *selection logic* via injected `which`; this host runs the **floor** (`tool_assisted:false`) — log that honestly, no fake "ran opengrep" claim |
| secrets | gitleaks/trufflehog **absent** | runs the **floor** entropy/pattern heuristic; the redaction helper is testable regardless |
This is a genuine **mixed-capability** host (SCA+IaC real, SAST+secrets floor) — exactly the
degradation story Phase 3 must prove.

**New shared sub-artifact (DRY glue, built first):** `_shared/scripts/degradation.py` —
pure functions mapping a `SCAN-PLAN.json` dict → the finding `summary` tool fields
(`tools_used`/`tools_unavailable`) and **stamping `tool_assisted`** on a finding by whether its
capability was `degraded`. It depends on the **artifact**, not on `sec-detect`'s module (avoids the
cross-package import problem), and is reused by `deps-scan` (T-3.3), `secrets-scan` (T-3.2), and the
integration test (T-3.6).

**Task sizing & sequencing (reconciled):**
| Task | Size | Type | Can start | Notes |
|------|------|------|-----------|-------|
| `degradation.py` helper | S | code+tests | now (first) | glue T-3.2/3.3/3.6 share |
| T-3.1 registry verify + cross-link + lock test | S (was M) | docs+test | now | mostly seeded already |
| T-3.2 `secrets-scan` body + redaction helper | S | docs+code+tests | now | floor on this host |
| T-3.3 `deps-scan` body + Trivy normalizer | M | docs+code+tests | now | real fixture; biggest code task |
| T-3.4 SAST section in `sec-vuln-scan` | S | docs | after T-3.1 | selection tested via injected `which` |
| T-3.5 IaC + `infra.md` + real `trivy config` demo | M | docs+demo | after T-3.1 | trivy present → real demo |
| T-3.6 degradation integration test | M | code+tests | after helper, T-3.2/3.3 | drives SCAN-PLAN + normalizers |

Recommended order: **`degradation.py` → (T-3.1 ∥ T-3.2 ∥ T-3.3) → (T-3.4 ∥ T-3.5) → T-3.6.**

**Risks / open questions:**
- *Cross-package imports (T-3.6):* `detect_tools.py` lives in `sec-detect/scripts`, the test home is
  `_shared/scripts/tests`. **Resolution:** the integration test drives the `SCAN-PLAN.json` *artifact*
  through `degradation.py` (+ the normalizers), never importing `sec-detect`'s module.
- *No live SAST here:* don't fake it. T-3.4's "tool present → `tool_assisted:true`" is proven by the
  injected-`which` degradation test; the floor path is what this host runs and what gets logged.
- *Registry ↔ code drift:* a lock test asserts every capability in `SCANNER_PREFERENCE` appears in
  `tool-registry.md` (and vice-versa for the five named capabilities).
- *Trivy supply-chain hygiene (ADR-006):* host binary is **0.69.0** — *not* in the malicious set
  (binary 0.69.4 / images 0.69.5–0.69.6) but the registry must still recommend pinning to **0.70.0+ /
  0.71.0**, `--skip-db-update` for offline, and **never auto-install unpinned**.
- *Secret leakage (T-3.2):* the redaction helper must guarantee no raw secret value ever reaches a
  finding/log; a test feeds a known secret and asserts it is masked.

**Definition of Done (phase):** all six tasks `done (verified)`; `uv run pytest` green across
`_shared/scripts`, `deps-scan/scripts`, `secrets-scan/scripts`; a **real** Trivy SCA normalize (13
findings, schema-valid) **and** a **real** `trivy config` IaC run are logged; the degradation
integration test proves floor-only completes with non-empty `tools_unavailable` and that an injected
tool flips `tool_assisted:true`; living docs + statuses updated. Then **re-groom Phase 4** before
starting (rolling-wave).

> **✅ PHASE COMPLETE (2026-06-06).** All six tasks `done (verified)`; **95 tests** green across
> `_shared`/`sec-detect`/`sec-triage`/`deps-scan`/`secrets-scan`. Real Trivy SCA normalize (13 findings,
> schema-valid) + real `trivy config` IaC run (3 misconfigs, offline) logged; degradation contract
> proven (floor-only completes, injected tool flips `tool_assisted`). Two VC-grep portability/self-trip
> fixes applied. Next: **re-groom Phase 4** (AI/LLM + API) before starting.

---

### T-3.1 · Verify + cross-link `_shared/reference/tool-registry.md` as the capability→tool map
- **Goal:** the registry documents each capability (SAST · SCA · secrets · IaC · AI-redteam) with its
  ordered illustrative tools, the floor fallback, the runtime-discovery rule, the pinning/hygiene rule
  (ADR-006), and an explicit note that `sec-learn`/`sec-kb-refresh` may add new tools (ADR-015). It is
  **cross-linked to `detect_tools.py::SCANNER_PREFERENCE`** (the executable twin) and a lock test
  keeps them consistent.
- **Approach:** (1) confirm the Phase-0 seed already satisfies the capability/floor/illustrative/
  self-updating VCs (it does); (2) add a short "executable twin" note pointing at
  `sec-detect/scripts/detect_tools.py::SCANNER_PREFERENCE` and the `ai-redteam` capability added in
  Phase 2; (3) add the Trivy-version hygiene specifics (safe ≥0.70.0/0.71.0; avoid 0.69.4/0.69.5/
  0.69.6; `--skip-db-update`; no unpinned auto-install); (4) add a tiny lock test in
  `_shared/scripts` asserting the five named capabilities in `SCANNER_PREFERENCE` each appear in the
  registry.
- **Artifact:** `.claude/skills/_shared/reference/tool-registry.md` + `_shared/scripts/tests/test_registry_lock.py`
- **Depends on:** T-2.2 (for `SCANNER_PREFERENCE`)
- **Edge cases / test notes:** a capability added to the code but not the doc (or vice-versa) must
  fail the lock test.
- **Verification criteria:**
  - [x] All five capabilities appear with ≥1 illustrative tool and a floor fallback each — `for c in sast sca secret iac redteam; do grep -qi "$c" .claude/skills/_shared/reference/tool-registry.md || echo MISSING:$c; done` prints nothing
  - [x] States "illustrative default, not a requirement" and the self-updating-registry rule — `grep -qi 'illustrative' … && grep -qi 'sec-learn\|sec-kb-refresh' …`
  - [x] States pinning/hygiene (ADR-006) incl. the safe Trivy version line — `grep -qi 'pin' … && grep -qiE '0\.70|0\.71' .claude/skills/_shared/reference/tool-registry.md`
  - [x] Lock test passes (registry ↔ `SCANNER_PREFERENCE`) — `uv run --with pytest pytest .claude/skills/_shared/scripts/tests/test_registry_lock.py`
- **Status:** done (verified 2026-06-06; registry meets VCs, executable-twin cross-link + Trivy hygiene added, 4 lock tests)

### T-3.2 · Implement `secrets-scan` (secrets capability + degradation)
- **Goal:** `secrets-scan/SKILL.md` documents a fast pattern pass + a verified pass behind the **secrets
  capability** (illustrative: gitleaks fast, trufflehog `--results=verified`), degrading to a Read/Grep
  entropy/pattern heuristic when no tool is present; emits findings merged into `VULN-FINDINGS.json`;
  **never writes secret values** anywhere.
- **Approach:** (1) write the body: fast→verified→floor ladder behind the capability, the floor
  entropy/known-key-pattern heuristic, and the hard "redact, never emit the secret value" rule;
  (2) ship `scripts/redact.py` — `redact(s)` masks all but a short prefix/suffix, plus a
  `to_finding(...)` that builds a schema-valid secrets finding whose `first_link`/`exploit_scenario`
  carry only `file:line` + the rule name, never the value; (3) use `degradation.py` to stamp
  `tool_assisted` + `tools_unavailable`.
- **Artifact:** `.claude/skills/secrets-scan/SKILL.md` + `.claude/skills/secrets-scan/scripts/` (`redact.py`, `pyproject.toml`, `conftest.py`, `tests/`)
- **Depends on:** T-1.1, T-3.1, `degradation.py`
- **Edge cases / test notes:** an empty string / very short secret must still redact without leaking;
  a finding built from a detected secret must contain **no substring** of the raw value (assert).
- **Verification criteria:**
  - [x] Body documents fast + verified passes behind a capability and the degradation fallback — `grep -qi 'verified' … && grep -qi 'degrad\|fallback\|floor' .claude/skills/secrets-scan/SKILL.md`
  - [x] Explicit "no secret value in output" rule — `grep -qi 'never.*secret value\|redact\|no secret' .claude/skills/secrets-scan/SKILL.md`
  - [x] Redaction helper tests pass; a known secret string is redacted **and** absent from the built finding — `uv run pytest .claude/skills/secrets-scan/scripts/tests/`
  - [x] `STATUS: STUB` gone — `! grep -q 'STATUS: STUB' .claude/skills/secrets-scan/SKILL.md`
- **Status:** done (verified 2026-06-06; secrets-scan body + redact.py — 8 tests prove no secret value leaks into a finding)

### T-3.3 · Implement `deps-scan` (SCA capability + native-gate-first + degradation)
- **Goal:** `deps-scan/SKILL.md` documents native low-FP gates first (govulncheck/pip-audit/npm audit
  by language), then a cross-language fallback (OSV-Scanner/Trivy), then floor (lockfile read + advisory
  match) — all behind the **SCA capability**; emits findings into `VULN-FINDINGS.json`. Validated against
  the Trivy SCA PoC fixture already on disk.
- **Approach:** (1) write the body: the native-gate-first → OSV/Trivy → floor ladder, keyed off
  `SCAN-PLAN.json`'s `category_tool["sca"]`; the "outdated-lib without a reachable sink is not HIGH"
  exclusion linkage (triage decides reachability); (2) ship `scripts/normalize_deps.py` mapping a Trivy
  `--format json` doc → schema-valid findings (one per CVE: `category:"supply-chain"`,
  `owasp:["A06:2021"]`, `access_required:"unknown"`, `verified:"static_review_only"`, provisional
  severity CRITICAL/HIGH→HIGH·MEDIUM→MEDIUM·else LOW, `recommendation:"upgrade <pkg> to <FixedVersion>"`,
  CVE id + URL in `kb_refs`, `tool_assisted` via `degradation.py`); dedup by `(pkg, CVE)`;
  (3) degraded path: empty `which` → floor result, `tool_assisted:false`, SCA in `tools_unavailable`.
- **Artifact:** `.claude/skills/deps-scan/SKILL.md` + `.claude/skills/deps-scan/scripts/` (`normalize_deps.py`, `pyproject.toml`, `conftest.py`, `tests/`)
- **Depends on:** T-1.1, T-2.2, T-3.1, `degradation.py`
- **Edge cases / test notes:** a Trivy `Result` with no `Vulnerabilities` (clean) → 0 findings; a
  vuln with no `FixedVersion` → recommendation says "no fixed version; mitigate/replace"; output must
  pass `validate_findings.py` with **no duplicate ids**.
- **Verification criteria:**
  - [x] Body documents the native-gate-first → fallback → floor ladder behind the SCA capability — `grep -qi 'govulncheck\|pip-audit\|npm audit' … && grep -qi 'osv\|trivy' … && grep -qi 'floor\|lockfile' .claude/skills/deps-scan/SKILL.md`
  - [x] The normalizer turns the on-disk Trivy output into schema-valid findings (13, no dup ids) — `uv run --with jsonschema --with pytest pytest .claude/skills/deps-scan/scripts/tests/` (fixture: `docs/research/poc-trivy-sca/trivy-output.json`)
  - [x] When no SCA tool is on PATH the skill still emits a (degraded, `tool_assisted:false`) result — test with injected empty `which`
  - [x] `STATUS: STUB` gone — `! grep -q 'STATUS: STUB' .claude/skills/deps-scan/SKILL.md`
- **Status:** done (verified 2026-06-06; deps-scan body + normalize_deps.py — 13 fixture findings schema-valid, dedup, degraded path; 10 tests)

### T-3.4 · Wire the SAST capability into `sec-vuln-scan` (+ degradation)
- **Goal:** `sec-vuln-scan` prefers an installed SAST engine (illustrative: Opengrep, Semgrep-compatible
  rules) and per-language linters when present, else runs the Read/Grep/Glob heuristic floor — selecting
  via `SCAN-PLAN.json`'s capability map; tool-derived findings carry `tool_assisted:true`.
- **Approach:** add a "SAST capability selection" section to `sec-vuln-scan/SKILL.md`: read
  `category_tool["sast"]` from `SCAN-PLAN.json`; if set, run it and stamp `tool_assisted:true`; if
  `null`/degraded, run the floor and stamp `tool_assisted:false` + list SAST in `tools_unavailable`.
  Include the PLAN §4.3 caveat that SCA/IaC tools have **no SAST**, so a clean SCA run ≠ source
  coverage — combine capabilities. **Honesty note for this host:** SAST is absent here, so the floor
  path is what runs; the *selection* logic is proven by the T-3.6 injected-`which` test.
- **Artifact:** `.claude/skills/sec-vuln-scan/SKILL.md` (SAST section)
- **Depends on:** T-1.2, T-2.2, T-3.1
- **Edge cases / test notes:** SAST present but serves a different language than detected → treat as
  degraded for that language (mirror `_serves`).
- **Verification criteria:**
  - [x] Section documents capability-based SAST selection from `SCAN-PLAN.json` + floor fallback — `grep -qi 'opengrep\|sast' … && grep -qi 'SCAN-PLAN.json' … && grep -qi 'floor\|degrad' .claude/skills/sec-vuln-scan/SKILL.md`
  - [x] Selection logic (present → `tool_assisted:true`; absent → `false` + in `tools_unavailable`) is proven by the T-3.6 degradation test with injected `which`; this host runs the floor (logged in `poc-floor-review/README.md`)
  - [x] "SCA/IaC tools have no SAST — combine capabilities for coverage" caveat present (PLAN §4.3) — `grep -qi 'no SAST\|combine' .claude/skills/sec-vuln-scan/SKILL.md`
- **Status:** done (verified 2026-06-06; SAST capability-selection section + 'no SAST/combine' caveat; selection proven by the T-3.6 injected-which test)

### T-3.5 · Wire the IaC capability + supply-chain hygiene (+ degradation)
- **Goal:** when `SCAN-PLAN.json` reports infra (Dockerfile / k8s / GitHub Actions / Terraform), discovery
  runs an IaC capability (illustrative: Trivy `config`/Checkov/hadolint/zizmor) else a floor heuristic;
  the `infra.md` appendix is filled (PLAN §5.5) and the tool-pinning hygiene (ADR-006) is enforced in how
  the skill invokes any tool.
- **Approach:** (1) fill `infra.md` (Dockerfile non-root/multi-stage/`--mount=type=secret`/.dockerignore;
  k8s/Helm PSS-Restricted + `helm template | trivy config -`; GitHub Actions least-priv `permissions`,
  OIDC, `pull_request_target` pwn-requests, no `${{ github.event.* }}` in `run:`; SLSA L2 + Sigstore
  keyless); (2) add the IaC section to `sec-vuln-scan` (run only when `infra` non-empty); (3) since
  **trivy is present**, run a **real `trivy config`** on a small Dockerfile fixture and log it; show the
  no-infra case skips cleanly.
- **Artifact:** `.claude/skills/_shared/reference/infra.md` + IaC section in `sec-vuln-scan/SKILL.md` + an infra fixture + run log under `docs/research/`
- **Depends on:** T-3.1, T-2.3
- **Edge cases / test notes:** avoid time-sensitive phrasing in `infra.md` body (ADR-005); a repo with
  no infra signals must not invoke any IaC tool.
- **Verification criteria:**
  - [x] `infra.md` covers Dockerfile, k8s/Helm, GitHub Actions, SLSA/Sigstore and is de-stubbed — `for k in 'Dockerfile' 'kubernetes\|helm' 'github\|actions' 'slsa\|sigstore'; do grep -qi "$k" .claude/skills/_shared/reference/infra.md || echo MISSING:"$k"; done` prints nothing; `! grep -q 'STATUS: STUB' .claude/skills/_shared/reference/infra.md` *(BRE `-qi`, not `-qiE`: `\|` is a literal pipe under macOS `grep -E`)*
  - [x] Real `trivy config` runs on a Dockerfile fixture (exit 0, **3 misconfigs**: DS-0002/DS-0001/DS-0026) and the no-infra case skips — both logged in `docs/research/poc-iac-scan/README.md`
  - [x] Tool invocations honor ADR-006 pinning (no unpinned auto-install) — `grep -qiE 'pin|--skip-db-update|digest|signature' .claude/skills/_shared/reference/infra.md` (note: `|` is correct under `-E`)
- **Status:** done (verified 2026-06-06; infra.md filled + IaC section; real `trivy config` found 3 misconfigs offline; no-infra skip confirmed)

### T-3.6 · Capability-degradation integration test
- **Goal:** a single test proves the whole degradation contract: with all capabilities absent the
  pipeline still completes, emits `tools_unavailable`, caps confidences, and never raises — and with a
  capability injected as present it switches to `tool_assisted:true`.
- **Approach:** build `_shared/scripts/degradation.py` first (ScanPlan/SCAN-PLAN dict → `tools_used`/
  `tools_unavailable`; `stamp_tool_assisted(finding, scan_plan)` by category-degraded). Then
  `test_degradation.py` drives it on (a) a fully-degraded SCAN-PLAN (empty `which` via `detect_tools`)
  → asserts the run completes, `tools_unavailable` non-empty, findings `tool_assisted:false`, no
  exception; (b) a SCAN-PLAN with a tool injected present → asserts `tool_assisted:true` and the
  capability is **absent** from `tools_unavailable`. Reuses the `deps-scan`/`secrets-scan` normalizers.
- **Artifact:** `.claude/skills/_shared/scripts/degradation.py` + `_shared/scripts/tests/test_degradation.py`
- **Depends on:** T-2.2, T-3.2, T-3.3, T-3.4
- **Edge cases / test notes:** a finding whose category isn't in the SCAN-PLAN at all (e.g. no infra)
  must not crash the stamping; idempotent re-stamping.
- **Verification criteria:**
  - [x] With `which` returning None for all tools, the run completes and `tools_unavailable` is non-empty — `uv run --with jsonschema --with pytest pytest .claude/skills/_shared/scripts/tests/test_degradation.py::test_floor_only`
  - [x] With a SAST/SCA/secrets tool injected present, findings flip to `tool_assisted:true` and the capability leaves `tools_unavailable` — `… ::test_tool_present`
  - [x] No exception path blocks on a missing tool (asserted; ADR-003) — `uv run --with jsonschema --with pytest pytest .claude/skills/_shared/scripts/tests/test_degradation.py` (all green)
- **Status:** done (verified 2026-06-06; degradation.py + integration tests — floor-only completes w/ tools_unavailable, injected tool flips tool_assisted; 33 _shared tests)
