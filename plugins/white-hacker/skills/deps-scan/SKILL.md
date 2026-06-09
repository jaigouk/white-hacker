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

## Supply-chain-malware floor (S1–S8, offline, behind the SCA capability)
CVE-based SCA (`npm audit` / OSV-by-CVE) has a structural **blind spot**: novel *malicious*
packages (typosquats, slopsquats, install-script malware, self-propagating worms) have a valid
version, install without error, and are not in any CVE DB yet — so the native gate **approves**
them (spike-09 §F2). `scripts/supply_chain.py` is the floor that covers that gap. It is **offline**
(zero network), **static** (reads only on-disk `package.json` + lockfile + referenced install
scripts), emits **low/medium-confidence `tool_assisted:false`** candidates, and — like the rest of
this stage — **NEVER blocks** (SKILL.md:27–29). Triage + a human decide.

It is an **ecosystem-agnostic signal core + a per-ecosystem adapter** (spike-09 §F5): `parse_npm`
is the **lead** npm adapter (normalizes `package.json` + `package-lock.json`/`pnpm-lock.yaml`/
`yarn.lock` into `{deps:[{name,spec,source_type}], lifecycle_scripts, lockfile_present,
script_files}`); PyPI/RubyGems/Go/Cargo/Maven are **follow-on adapters behind the exact same
struct** (wh-w30) — the S1–S8 core + `score()` are reused UNCHANGED. `scan()` detects the
ecosystem by the first marker manifest present (`detect_ecosystem`, a `{marker → (adapter, lang,
manifest)}` dispatch table) and routes to the right adapter, setting `manifest_path` +
`summary.scanned_langs` per ecosystem. Each adapter NEVER raises on a missing/odd manifest —
it degrades to the empty-but-well-formed struct (stdlib only: `tomllib` for TOML, `xml.etree`
for `pom.xml`, targeted regex/line parsing for Gemfile/go.mod; no new runtime dep). Signals:

- **S1** install-lifecycle hook present (`pre/post/install`) — necessary-not-sufficient, LOW alone.
- **S2** non-registry source dep (git/http/tarball); `workspace:`/`file:` in-repo = benign.
- **S3** unpinned range AND no lockfile committed — LOW alone.
- **S4** typosquat: Damerau-Levenshtein distance 1–2 to the `reference/ai-sdk-allowlist.json`
  allowlist (distance 0 = exact = SAFE) — MEDIUM.
- **S5** homoglyph / separator-collision (ASCII-fold + separator-normalize collides with an
  allowlist entry while the raw string differs) — **HIGH**.
- **S6** dangerous-API strings in a *referenced* install script (`child_process`/`eval(`/
  `new Function(`/`require('net'|'http'|…)`/`fetch(`/`Buffer.from(…,'base64')`/`~/.ssh|.aws|.npmrc|
  .claude`) — **HIGH** when ≥2 hit. Reported once, **project-level** (keyed to the script).
- **S7** obfuscation (single line >50 KB, `_0x[0-9a-f]{4,}` density).
- **S8** known-bad vs an **OPTIONAL** offline OSSF/GHSA snapshot — a HOOK that **degrades**: no
  snapshot → record `malware-db` in `summary.tools_unavailable` and skip. To ACTIVATE, pass
  `malware_db=load_malware_db(<osv>)` to `scan()` (wh-0o7 loader). A snapshot is PINNED + verified
  active (wh-8qw: OSSF `174a862…`, real pkg `a-constructor.js`/MAL-2024-1708 → HIGH S8) — pin +
  fetch + operational caveats in `reference/MALWARE-DB.md`.

### Per-ecosystem adapters (npm lead + 5 follow-ons, same interface — wh-w30)
Every signal is a property of *a manifest + a lockfile + install/build hooks*, present in every
ecosystem; each adapter just normalizes those files. Source-type + hook handling per ecosystem:

| Ecosystem | Marker / manifest | Lockfile (→ `lockfile_present`) | Non-registry source (S2) | Install/build hook (S1 → `script_files`) |
|---|---|---|---|---|
| **npm** (lead) | `package.json` | package-lock / pnpm-lock / yarn.lock | git/http/tarball; `file:`/`workspace:` = in-repo benign | `pre/post/install` scripts |
| **PyPI** | `pyproject.toml` (`[project].dependencies` / `[tool.poetry.dependencies]`) or `requirements.txt` | `poetry.lock` / `uv.lock` | `git+…`/url = remote; `file://`/`{path=…}` = file | `setup.py` present = arbitrary build code |
| **RubyGems** | `Gemfile` (`gem '...'`) | `Gemfile.lock` | `git:`/`github:` = git; `path:` = file | `extconf.rb` / `ext/` = native ext build |
| **Go** | `go.mod` (`require` + `replace`) | `go.sum` | `replace`→fork = git; `replace`→local path = file | **none** (Go has no install hook → empty) |
| **Cargo** | `Cargo.toml` (`[dependencies]`) | `Cargo.lock` | `{git=…}` = git; `{path=…}` = file | `build.rs` = build script |
| **Maven** | `pom.xml` (`<dependency>` groupId:artifactId, via `xml.etree`) | **none standard** → always `False` | `system` scope (`systemPath` jar) = file | **none** standard |

The dep `name` is the ecosystem's canonical id (npm/PyPI/gem/crate name; Go module path; Maven
`groupId:artifactId`), so S4/S5 match against an ecosystem-appropriate `reference/` allowlist. The
`python` constraint in `[tool.poetry.dependencies]` is the interpreter, not a dep, and is dropped.
A `file:`/`workspace:`/local-`replace`/`system`-scope source is **in-repo benign** (the S2
exclusion) — it never fans out as a candidate, exactly like the npm `file:` rule.

**Scoring** (spike-09 §F2): emit on **any HIGH** (S5/S6/S8) **OR ≥2 corroborating** signals; a
lone S1/S3 is **informational only** (never a finding — the canonical FP guard is a benign native
build, `postinstall:"node-gyp rebuild"` + a pinned registry dep → no finding). Findings reuse the
`normalize_deps.py` shape (`category:"supply-chain"`, `owasp:["A06:2021"]`, `access_required:
"unknown"`, `verified:"static_review_only"`, confidence capped via `degradation.cap_floor_confidence`,
`kb_refs:["AISEC-SUPPLY-CHAIN-001"]`). The allowlist lives in `reference/` so `/sec-kb-refresh`
extends it (ADR-015). `scan()` **never raises** on a missing/odd manifest — it degrades to an
empty-but-valid result.

### F4 remediation ladder (spike-09 §F4) — the agent proposes, never executes
Each finding's `recommendation` maps to a rung: **0** do not build yet — `npm ci --ignore-scripts`
during triage · **1** confirm intended vs actual name char-by-char (S4/S5) · **2** check the offline
malware DB (S8) · **3** verify provenance/attestation (`npm audit signatures`, network, optional) ·
**4** pin + commit the lockfile, add `min-release-age`/`minimumReleaseAge` cooldown · **5** remove or
replace by exact name, reinstall `--ignore-scripts` · **6** rotate exposed credentials if the script
ran · **7** report upstream (OSSF `malicious-packages` / a GHSA malware advisory). The agent does
**not** auto-remove, auto-rotate, or push (capability removed — security posture).

```bash
# run the floor on a project (offline) and validate the candidates
cd plugins/white-hacker/skills/deps-scan/scripts
uv run --with jsonschema python -c "import sys; sys.path[:0]=['.','../../_shared/scripts']; \
  import json, supply_chain as sc, validate_findings as vf; \
  d=sc.scan('../../../../../docs/research/poc-supply-chain'); \
  print(vf.validate(d)); print(json.dumps(d['summary'], indent=2))"
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

### Supply-chain-malware floor (wh-07w)
- [x] `scripts/supply_chain.py` implements the npm adapter (`parse_npm`) + the ecosystem-agnostic
  S1–S8 signal core + `score()` + `scan()` (stdlib only, no new runtime dep, Rule 5 pure functions).
- [x] Typosquat → MEDIUM; homoglyph/separator scope → HIGH; ≥2-dangerous-API install script →
  HIGH; **benign native build (`node-gyp rebuild` + pinned registry dep) → NO finding**; lone
  missing-lockfile → informational only. (`tests/test_supply_chain.py`.)
- [x] Degraded (no `malware-db` snapshot) lists `malware-db` in `tools_unavailable` and never raises.
- [x] Every emitted document validates: `validate_findings.validate(doc) == []`.

### Per-ecosystem adapters (wh-w30)
- [x] `supply_chain.py` adds `parse_pypi` / `parse_gem` / `parse_go` / `parse_cargo` / `parse_maven`,
  each producing the SAME normalized struct; the S1–S8 core + `score()` are reused UNCHANGED
  (additive: `parse_npm` + `signal_s8` + every existing signature intact, so wh-0o7's
  `malware_db.py` still imports `signal_s8`). Stdlib only (`tomllib`, `xml.etree`); no new runtime dep.
- [x] `scan()` detects the ecosystem (`detect_ecosystem` dispatch table) and sets `manifest_path` +
  `scanned_langs` per ecosystem; the **npm path is identical** (package.json → `parse_npm` →
  `javascript`, demo still emits the same 2 HIGH candidates).
- [x] Each ecosystem fixture trips the right candidate (PyPI/Maven S5 HIGH, gem/Cargo native-hook
  S6 HIGH + S2 corroboration, Go S5 HIGH) AND a benign control per ecosystem emits NO finding;
  every emitted doc is schema-valid (`tests/test_adapters.py`, 25 tests).
- [x] The existing 40 tests (29 npm + 11 malware_db) still pass.

Gate commands (run via `--project` so uv selects the package's pinned ≥3.11 interpreter — `tomllib`
is 3.11+ stdlib; this matches `.github/workflows/ci.yml:44`):
```bash
uv run --project plugins/white-hacker/skills/deps-scan/scripts \
  --with jsonschema --with pytest pytest plugins/white-hacker/skills/deps-scan/scripts/tests -q
uv run python packaging/validate_manifest.py .
# demo: scan the neutralized POC and assert validate(...) == []
cd plugins/white-hacker/skills/deps-scan/scripts && uv run --with jsonschema python -c \
  "import sys; sys.path[:0]=['.','../../_shared/scripts']; import supply_chain as sc, \
   validate_findings as vf; assert vf.validate(sc.scan('../../../../../docs/research/poc-supply-chain'))==[]; print('OK')"
```
