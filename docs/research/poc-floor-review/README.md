# PoC — Floor-only review smoke test (Phase 0, T-0.5 / T-0.6)

- **Status:** ✅ PASS
- **Date:** 2026-06-06
- **Verifies:** the generic agent runs the inner loop **on the Read/Grep/Glob floor alone**
  (zero external scanners), flags planted vulns across languages, spares safe look-alikes,
  degrades gracefully (`tools_unavailable`), and writes nothing (posture/ADR-010).

## Fixtures (paired vuln / clean look-alike per language)
| Sub-fixture | Planted vuln | Sink (file:line) | Category / OWASP |
|---|---|---|---|
| `go-vuln/main.go` | OS command injection | `exec.Command("sh","-c", "ping -c 1 "+host)` — **:13** | injection / A03:2025 |
| `py-vuln/app.py` | SQL injection | `con.execute(f"SELECT ... {uid}")` — **:14** | injection / A03:2025 |
| `ts-vuln/handler.ts` | OS command injection | `exec(\`echo Hello ${name}\`)` — **:10** | injection / A03:2025 |
| `go-clean/` `py-clean/` `ts-clean/` | none (safe look-alikes) | argv array + IP validation / bound param / `execFile` | must NOT be flagged |

## Grep checks (planted sink present in vuln, absent in clean) — verified
```bash
grep -nF 'exec.Command("sh", "-c"' go-vuln/main.go     # -> :13   ; go-clean -> 0
grep -nE 'execute\(f"' py-vuln/app.py                   # -> :14   ; py-clean -> 0
grep -nE 'exec\(`' ts-vuln/handler.ts                   # -> :10   ; ts-clean -> 0
```

## Live agent run (T-0.5 third VC) — verified
Spawned the real `white-hacker` agent (subagent) on this directory, floor-only:
- **Recall:** found all 3 planted candidates at the exact `file:line`.
- **Precision:** refuted all 3 clean look-alikes with the controlling reason (no-shell argv array +
  IP validation; bound parameter; `execFile`). **0 false positives.**
- **Output:** strict JSON contract — `counts {high:3, medium:0, low:0}`, every finding
  `severity:HIGH`, `access_required:unauth-remote`, `preconditions:[]`, `verified:static_review_only`,
  `tool_assisted:false`.
- **Degradation (ADR-003):** `tools_used` = builtin floor only; `tools_unavailable` listed 8
  scanners (Opengrep, OSV-Scanner, Trivy, gitleaks, trufflehog, govulncheck, pip-audit, npm audit).
- **Confusion matrix:** TP=3, FP=0, FN=0 on this corpus.

## Posture / degradation self-check (T-0.6) — verified + 1 follow-up
- ✅ **No working-tree write** during the run — agent returned JSON as its message only
  (10 read-only tool uses: Read/Grep/Glob/Bash-find). `grep -E '^tools:' .claude/agents/white-hacker.md`
  shows no `Write`/`Edit`.
- ✅ **No secret values** in the emitted output.
- ✅ Honored read-only posture; treated fixtures as untrusted; did not act on file contents.
- ⚠️ **Follow-up (capability-removal hardening):** when registered as an Agent-tool subagent the
  harness listed `Write, Edit` alongside the 6 frontmatter tools. The frontmatter is the contract
  and the run was read-only, but **frontmatter alone may not hard-remove write**. Per ADR-004 /
  spike-02, enforce no-write structurally with a **PreToolUse hook** that denies `Write`/`Edit`/
  `git apply` for the white-hacker agent. Tracked for Phase 6/8 (T-6.4 / T-8.4); a deny-write hook
  is the robust enforcement of ADR-010.

## Conclusion
The Phase-0 skeleton works end-to-end on the floor with zero external tools — it already beats a
single-pass language-specific reviewer. This corpus is the seed the Phase 7/9 eval harness absorbs
(it becomes labeled TP/FP/FN cases for the keep-or-revert gate).

---

## Phase 1 — recall → precision split (T-1.5), verified 2026-06-06
Demonstrates the two-stage pipeline (ADR-008) with **fresh-context** triage. Artifacts saved under
`run/`:

| Stage | Artifact | Findings | counts | Note |
|---|---|---|---|---|
| Discovery (recall) | `run/discovery.json` | **6** candidates | high 3, low 3 | over-reports — 3 vuln @0.9 + 3 clean look-alikes @0.4 |
| Triage (precision) | `run/triage.json` | **3** kept | high 3, low 0 | refuted all 3 clean look-alikes; **FP=0, FN=0** |
| Dedup | `run/triage.deduped.json` | 3 | — | deterministic pass = no-op (no duplicates), schema-valid |

- Both artifacts validate against `_shared/reference/finding-schema.json`
  (`validate_findings.py … --no-dup-ids` → OK, no duplicate ids).
- Triage ran **context-starved** (saw only `{id,file,line,category}`, not discovery's rationale) and
  in a **fresh agent context** — it independently re-derived each verdict.
- Severity on every kept finding was **derived in triage** from `preconditions` (0 preconditions +
  `unauth-remote` → HIGH), not copied from the finder's score.
- Confusion matrix vs the planted labels: **TP=3, FP=0, FN=0**.

This proves Phase 1: discovery maximizes recall (over-reports), triage delivers precision (refutes
the look-alikes), the strict schema gates both, and dedup is idempotent.
