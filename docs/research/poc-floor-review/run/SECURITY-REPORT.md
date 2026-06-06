# Security Review Report

> Logged evidence for `sec-report` (Phase 6 T-6.1): rendered from `run/triage.deduped.json`
> (the Phase-1 triaged fixture). Floor-only review (no external scanners installed).

## Summary
- **Scanned languages:** go, python, typescript
- **Scoring standard:** CVSS 4.0
- **Tools used:** none (Read/Grep/Glob floor)
- **Tools unavailable (degraded):** sast, sca, secrets, iac — findings are `tool_assisted:false`, confidence capped
- **Counts:** **HIGH 3** · MEDIUM 0 · LOW 0
- **CI gate:** ❌ FAIL — `counts.high (3) > 0`

| id | sev | category | OWASP | location | access | conf |
|----|-----|----------|-------|----------|--------|------|
| F-001 | HIGH | injection | A03:2025 (A03:2021) | go-vuln/main.go:13 | unauth-remote | 0.97 |
| F-002 | HIGH | injection | A03:2025 (A03:2021) | py-vuln/app.py:14 | unauth-remote | 0.97 |
| F-003 | HIGH | injection | A03:2025 (A03:2021) | ts-vuln/handler.ts:10 | unauth-remote | 0.96 |

---

### F-001 · HIGH · injection — `A03:2025`
- **Location:** [`docs/research/poc-floor-review/go-vuln/main.go:13`](../go-vuln/main.go) · access: unauth-remote · verified: static_review_only · tool_assisted: false · confidence: 0.97
- **Exploit scenario:** host query param concatenated into `sh -c` → OS command injection (unauthenticated).
- **Recommendation:** argv array `exec.Command("ping","-c","1",host)` + `net.ParseIP` validation.

### F-002 · HIGH · injection — `A03:2025`
- **Location:** [`docs/research/poc-floor-review/py-vuln/app.py:14`](../py-vuln/app.py) · access: unauth-remote · verified: static_review_only · tool_assisted: false · confidence: 0.97
- **Exploit scenario:** id query param interpolated into SQL via f-string → SQL injection (unauthenticated).
- **Recommendation:** parameterized query `execute("… WHERE id = ?", (uid,))`; cast id to int.

### F-003 · HIGH · injection — `A03:2025`
- **Location:** [`docs/research/poc-floor-review/ts-vuln/handler.ts:10`](../ts-vuln/handler.ts) · access: unauth-remote · verified: static_review_only · tool_assisted: false · confidence: 0.96
- **Exploit scenario:** name query param interpolated into `child_process.exec` shell string → OS command injection (unauthenticated).
- **Recommendation:** `execFile("echo",["Hello",name])` argv array, no shell; allowlist-validate name.

---

_Triaged-only output (no raw discovery candidates). Excluded items, if any, remain in the machine
JSON with `excluded_by` for the audit trail and are not promoted here._
