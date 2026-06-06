# PoC — Trivy SCA on a vulnerable fixture (offline)

- **Status:** ✅ PASS
- **Date:** 2026-06-06
- **Verifies:** the `deps-scan` SCA pipeline works end-to-end via the Trivy CLI,
  **offline** against the locally cached vuln DB, and the local DB is current
  enough to catch 2026 CVEs.

## Files
- `fixture-vulnerable/requirements.txt` — deliberately old packages
  (flask 0.12.2, jinja2 2.10, pyyaml 5.1, requests 2.19.1, urllib3 1.24.1).
- `trivy-output.json` — captured scan output.

## Run
```bash
trivy fs --scanners vuln --severity HIGH,CRITICAL --skip-db-update --quiet \
  --format json docs/research/poc-trivy-sca/fixture-vulnerable
```

## Result (verified)
- **exit code 0**, **13 HIGH/CRITICAL** vulnerabilities reported.
- Distinct CVEs included historical *and* 2026 entries:
  `CVE-2018-1000656`, `CVE-2019-10906`, `CVE-2020-14343`, `CVE-2023-30861`,
  **`CVE-2025-66418`, `CVE-2025-66471`** — i.e. the cached DB (updated 2026-02-05)
  surfaces recent CVEs.
- `--skip-db-update` confirms it works with **no network** (matches the
  "remove network during scanning" sandbox guidance).

## Conclusion / decision
- Trivy **CLI** is a reliable SCA core with `--format json` for machine consumption
  and `--skip-db-update` for offline/air-gapped runs → confirms **ADR-002**
  (Trivy CLI-first, MCP optional).
- Local binary is **v0.69.0** — *not* in the malicious set (binary 0.69.4 /
  images 0.69.5–0.69.6) per [spike-01](spike-01-trivy-mcp.md), but the plan should
  still recommend pinning to **v0.71.0 / v0.70.0**. Follow-up: refresh DB
  (`trivy --download-db-only`) and consider pinning the binary.
- Seeds the `deps-scan` skill; the real skill will add per-language native gates
  (govulncheck/pip-audit) ahead of Trivy and ship with tests over recorded fixtures.
