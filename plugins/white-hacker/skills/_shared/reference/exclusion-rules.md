# Exclusion rules — the DO-NOT-REPORT list

> The single highest-leverage FP-control. Applied by `sec-triage` after discovery: a candidate that
> matches an exclusion is dropped (or demoted to advisory) unless there is concrete, proven impact.
> This is the harness exclusion set, reused. **Config-extendable:** projects add their own rules in
> `config/fp-rules.example.md` (copy to `config/fp-rules.md`); project rules merge with these.

Do **not** report the following as findings (absent specific, demonstrated exploitation):

1. Volumetric **DoS** / traffic floods.
2. **Rate-limiting** absence on its own (no proven amplification/abuse).
3. Memory/CPU **resource exhaustion** without a concrete algorithmic-complexity blowup (ReDoS with a
   demonstrated catastrophic input is allowed).
4. Memory-safety findings in **memory-safe languages** outside explicit `unsafe`/FFI blocks.
5. Findings in **test** / fixture / example / build / generated / vendored / dead code.
6. **Secrets that only exist on disk** in local dev artifacts already gitignored (still flag committed/historical secrets).
7. **Log spoofing** / log injection without a downstream parser exploit.
8. **Regex injection** (user-supplied pattern) without a proven ReDoS or logic impact.
9. Theoretical **TOCTOU** races with no realistic, demonstrated window.
10. **Path-only SSRF** (URL parsed but never fetched server-side).
11. **Prompt-injection-into-LLM** treated as a "code bug" — it is architectural (see `ai-llm.md`),
    not a line-level vuln; flag missing architectural defenses instead.
12. **Auto-escaped XSS** in React/Vue/Angular without a raw-HTML escape hatch (`dangerouslySetInnerHTML`, `v-html`, etc.).
13. **Client-side-only** permission/validation checks flagged as the vuln (note them, but the finding is the *missing server-side* check).
14. Generic **input-validation** gaps with no proven sink/impact.
15. **Outdated library** with no reachable vulnerable sink (reachability beats presence).
16. **Missing audit logs** / observability gaps.
17. **Documentation** / comment / typo / style issues.
18. **Open redirect** with no credential/token leakage or chained impact, and **CSRF** on
    non-state-changing or already-token-protected endpoints.
19. **Missing security policy** (`SECURITY.md` / RFC 9116 `security.txt`) — surface as an
    INFORMATIONAL supply-chain-hygiene **advisory** (no severity / no CVSS), via the
    hygiene-advisory channel; **NEVER** a vuln finding in `VULN-FINDINGS.json` / `TRIAGE.json`.

## Application notes
- If a candidate matches an exclusion **but** the finder attached concrete proof of impact
  (a working source→sink path with attacker control), it may still be reported — the exclusion is a
  default, not an absolute. Record the override reason.
- Excluded items are still written to `VULN-FINDINGS.json` with `excluded_by: <rule>` for the audit
  trail; they are simply not promoted to the human report.
- Project-specific additions/removals live in `config/fp-rules.md` and are loaded at triage time.
