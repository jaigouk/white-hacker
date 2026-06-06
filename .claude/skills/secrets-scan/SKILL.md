---
name: secrets-scan
description: Scan for committed secrets — fast pattern pass (gitleaks) plus verified pass (trufflehog --results=verified). Use during discovery on any repo.
---

# secrets-scan — secrets capability (fast → verified → floor)

Catch hardcoded credentials with low noise, behind the **secrets capability** (ADR-015). The hard
rule, non-negotiable: **a secret value is never written anywhere** — not in a finding, a log, a
ticket, or the KB (security posture; Agents Rule of Two — don't let the reviewer hold both the secret
and an egress path). Findings carry only `{file, line, rule}` plus a one-way fingerprint.

> Reads `SCAN-PLAN.json` (`category_tool["secrets"]`); writes findings merged into `VULN-FINDINGS.json`.

## The ladder (best signal first, then degrade)
1. **Fast pattern pass** — illustrative: `gitleaks` over the tree (and history) for known key shapes.
2. **Verified pass** — illustrative: `trufflehog --results=verified`, which live-checks candidates and
   collapses the set to **confirmed-active** secrets (the high-signal output).
3. **Floor** when no secrets tool is on PATH: a Read/Grep entropy + known-key-pattern heuristic
   (AWS `AKIA…`, GitHub `ghp_…`, private-key headers, high-entropy assignments). Mark candidates
   `tool_assisted:false`, cap confidence, record `secrets` in `summary.tools_unavailable`. Never blocks.

## No secret ever leaves the process
`scripts/redact.py` is the only sanctioned path from a detected secret to a finding:
- `fingerprint(s)` → a short SHA-256 prefix (one-way; correlates duplicates without disclosing).
- `redact(s)` → `"<redacted:sha256=…>"` — reveals **no** substring of the value (not even a prefix).
- `to_finding(file, line, rule, secret, scan_plan=…)` → a schema-valid `hardcoded-secret` finding
  whose fields contain only location + rule + fingerprint; `degradation.py` stamps `tool_assisted`.

A test (`tests/test_redact.py`) serializes the built finding and asserts the raw secret value (and
even a 6-char prefix) is **absent**, while the fingerprint is present for correlation.

## Triage handoff
Discovery flags candidates; **triage** confirms whether a secret is real/active and still in use, and
applies the exclusion list (e.g. on-disk test fixtures, obviously-fake placeholders). Severity is
provisional here (`HIGH` default for a live-looking credential) — triage tempers it.

## Verification criteria (definition of done)
- [x] Body documents fast + verified passes behind the capability and the floor fallback.
- [x] Explicit "never write a secret value; redact" rule, enforced by `redact.py` + tests.
- [x] Redaction helper tests pass; the raw secret is absent from the built finding (`tests/test_redact.py`).
- [x] Stub banner removed (de-stubbed); degrades gracefully (records `secrets` in `tools_unavailable`).
