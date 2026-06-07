---
name: deps-scan
description: >
  Software-composition analysis: native low-FP gates (govulncheck/pip-audit/npm
  audit) first, then OSV-Scanner/Trivy fallback. Use during discovery to find
  vulnerable dependencies.
---

# deps-scan — SCA capability (native-gate-first, degrade to the floor)

Find vulnerable dependencies behind the **SCA capability** — never a hard dependency on one tool
(ADR-015). SCA is *cheap*; the value is feeding triage honest candidates. A known CVE in a manifest
is **not** automatically a finding: reachability decides. So this stage emits candidates with
`access_required:"unknown"` and a modest confidence, and **triage** applies the "outdated-lib without
a reachable sink is not HIGH" exclusion.

> Reads `SCAN-PLAN.json` (`category_tool["sca"]`) to pick the tool; writes findings merged into
> `VULN-FINDINGS.json`. Offline by default (no network during scanning).

## The ladder (best signal first, then degrade)
1. **Native low-FP gate** for the detected language — the most precise signal:
   - Go → `govulncheck ./...` (reachability-aware: only flags vulns whose symbol is actually called)
   - Python → `pip-audit`
   - JS/TS → `npm audit` / `pnpm audit`
   - Rust → `cargo audit`
2. **Cross-language fallback** when no native gate is present: `osv-scanner` or `trivy fs --scanners vuln`.
3. **Floor** when no SCA tool is on PATH at all: read the lockfile/manifest, list pinned versions, and
   flag clearly-outdated packages as **low-confidence, `tool_assisted:false`** candidates (reachability
   unproven). The stage records `sca` under `summary.tools_unavailable` and **never blocks**.

Selection is keyed off `SCAN-PLAN.json`; the tool is swappable, the ladder is the contract.

## Normalizing to the finding schema
`scripts/normalize_deps.py` maps a Trivy `--format json` document into schema-valid findings
(one per `(package, CVE)`, deduped): `category:"supply-chain"`, `owasp:["A06:2021"]`, provisional
severity (CRITICAL/HIGH→HIGH, MEDIUM→MEDIUM, else LOW), `recommendation:"Upgrade <pkg> to
<FixedVersion>"` (or a "no fixed version" note), the CVE id + advisory URL in `kb_refs`.
`tool_assisted` and the summary's `tools_used`/`tools_unavailable` come from `_shared/scripts/
degradation.py` (derived from the SCAN-PLAN), so a degraded run is recorded rather than crashing.
The same module is where OSV-Scanner / native-gate output would be normalized behind the same shape.

```bash
# example: capture then normalize (offline)
trivy fs --scanners vuln --severity HIGH,CRITICAL --skip-db-update --quiet --format json <repo> > deps.json
uv run --with jsonschema python scripts/normalize_deps.py deps.json > DEPS.json
uv run --with jsonschema python ../_shared/scripts/validate_findings.py DEPS.json
```

## Supply-chain hygiene (ADR-006)
Pin tools; never auto-install from unpinned sources (see
[`_shared/reference/tool-registry.md`](../_shared/reference/tool-registry.md) for the safe Trivy
versions and the `--skip-db-update` offline mode). Also check lifecycle-script abuse (`npm ci
--ignore-scripts`), SHA-pinned Actions, and digest-pinned base images — see
[`infra.md`](../_shared/reference/infra.md).

## Verification criteria (definition of done)
- [x] Body documents the native-gate-first → OSV/Trivy fallback → floor ladder behind the SCA capability.
- [x] `normalize_deps.py` turns the on-disk Trivy output into 13 schema-valid findings, no dup ids
  (`tests/test_normalize_deps.py`).
- [x] No SCA tool on PATH → a degraded, schema-valid result with `sca` in `tools_unavailable` (never blocks).
- [x] Stub banner removed (de-stubbed); no secret values written.
