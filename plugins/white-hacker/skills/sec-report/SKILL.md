---
name: sec-report
description: Render TRIAGE.json to a human SECURITY-REPORT.md plus machine JSON, mapping findings to OWASP IDs. Use as the final step of a review to present results and gate CI.
---

# sec-report — render the triaged result (human + machine)

The final inner-loop stage. It renders **`TRIAGE.json`** (canonical, triaged findings) into a
human **`SECURITY-REPORT.md`** and emits the **machine JSON** that CI gates on. This stage is
**pure reasoning** (`allowed_tools=[]`): it reads the triaged artifact and writes the report — no
scanning, no network, no build. It returns **only triaged findings, never raw discovery output**
(PLAN §7.3) — `sec-vuln-scan`'s recall-stage candidates never reach a human or a ticket unless they
survived `sec-triage`.

## Inputs / Outputs
- **Reads:** `TRIAGE.json` (validates against `_shared/reference/finding-schema.json`).
- **Writes:** `SECURITY-REPORT.md` (human) + the machine JSON (the validated findings doc) for CI.

## What the human `SECURITY-REPORT.md` contains
1. **Header / summary:** scanned languages, `scoring_standard` (default CVSS 4.0), `tools_used` +
   **`tools_unavailable`** (so a reader knows what was floor-only / degraded — ADR-003), and the
   `summary.counts` (high / medium / low).
2. **Per finding (canonical only; duplicates are folded under their canonical `id`):**
   - `id`, `severity`, `category`, and the **OWASP IDs** from `owasp[]` (e.g. `A03:2025`,
     `API1:2023`, `LLM05:2025`) — map every finding to its standard id(s) for the reader.
   - **location** via `first_link` (`file:line`), `access_required`, `preconditions`, `confidence`,
     `verified` (ladder class), and `tool_assisted`.
   - `exploit_scenario` (why it is reachable) and `recommendation` (the fix direction).
   - `kb_refs` when present (links AI findings to `ai-attack-kb` entry ids).
3. **Excluded items** are NOT promoted to the report; they remain in the machine JSON with
   `excluded_by` for the audit trail.

## CI gate
The machine JSON is the gate input. CI **fails on `summary.counts.high > 0`** (threshold
overridable) — implemented by `scripts/ci_gate.py` (T-6.2), which validates the JSON against the
finding-schema first, then checks the counts and returns a non-zero **exit code** to fail the PR.

## Posture
Triaged-only (never raw discovery); no secret values ever written to the report or JSON
(decision-makers see only `{file, line, category, diff}`). Pure reasoning — no tools at report time.

## Logged evidence
`docs/research/poc-floor-review/run/SECURITY-REPORT.md` is this skill applied to the Phase-1
`triage.deduped.json` fixture (3 HIGH injection findings → a non-empty, OWASP-mapped report).

## Verification criteria (definition of done for this skill)
- [ ] Documents the markdown + machine-JSON outputs and OWASP-ID mapping; de-stubbed.
- [ ] States the CI gate (`counts.high == 0`) and "triaged-only, never raw discovery".
- [ ] Renders the Phase-1 `TRIAGE.json` fixture to a non-empty report (logged under `poc-floor-review/run/`).
- [ ] No secret values ever written to output.
