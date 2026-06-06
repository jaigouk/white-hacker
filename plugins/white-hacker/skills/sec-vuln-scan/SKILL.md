---
name: sec-vuln-scan
description: Discovery stage — RECALL-optimized. Partition the attack surface, then sweep each partition with simple non-prescriptive prompts to find everything, including unlikely cases. Use as the main code-level find pass.
---

# sec-vuln-scan — discovery (optimize RECALL)

Discovery and verification are **separate stages** (ADR-008). This is discovery: your job is to
find **everything** — including unlikely cases — and hand candidates to `sec-triage`, which decides
what is real. **Do not self-censor.** Combining find + judge in one step drops true positives.

> Floor-only in Phase 0/1 (Read/Grep/Glob; external scanners arrive in Phase 3). When a scanner is
> absent, degrade and mark candidates `tool_assisted:false` (ADR-003). Reads `THREAT_MODEL.md` and
> `SCAN-PLAN.json` if present; writes `VULN-FINDINGS.json` (schema below).

## Method — partition, then fan out, then a system-level pass
Brute-force "more agents" converges on the same shallow bugs. Instead:

1. **Partition the attack surface first.** Split the target into independent areas — by entry point,
   endpoint, component, subsystem, or trust boundary. Record the partition list.
2. **Fan out per partition.** Sweep each partition independently against
   `_shared/reference/core-checklist.md` (load `lang-*.md` / `ai-llm.md` / `api.md` / `infra.md` as
   the `SCAN-PLAN.json` indicates). Use **simple, non-prescriptive prompts** — prescriptive
   checklists narrow creativity and miss novel issues. For each candidate, trace **source → sink**.
3. **System-level pass.** With the per-partition findings as context, do one final pass for
   **cross-component** vulnerabilities (a source in one area reaching a sink in another).

For every candidate, record `{file, line, category, source, sink, why-reachable}`. **Report unproven
candidates too**, flagged with a lower `confidence` — recall is the goal here; triage prunes.

## SAST capability selection (+ degradation)
Code-level discovery runs behind the **SAST capability** (ADR-015) — read
`SCAN-PLAN.json`'s `category_tool["sast"]`:
- **Tool bound** (illustrative: Opengrep with Semgrep-compatible rules, or a per-language linter such
  as gosec/bandit/eslint-plugin-security that *serves the detected language*): run it, fold its hits
  into the candidate set, and stamp them `tool_assisted:true` (via `_shared/scripts/degradation.py`).
- **Degraded** (`null`, or the only SAST tool doesn't serve this language): run the **Read/Grep/Glob
  heuristic floor** against `core-checklist.md` + the `lang-*.md` appendices, stamp `tool_assisted:false`,
  cap confidence, and list `sast` in `summary.tools_unavailable`. **Discovery never blocks** on a
  missing engine.

**Coverage caveat (PLAN §4.3):** SCA / IaC tools (e.g. Trivy) have **no SAST** — a clean dependency or
config scan is *not* source coverage. Always **combine** the SAST capability with SCA/secrets/IaC; one
green scan in one capability says nothing about the others. (On a host with no SAST engine installed,
this stage runs the floor — the selection logic is proven by the Phase-3 degradation test with an
injected `which`.)

## IaC capability selection (+ degradation)
Run the **IaC capability** **only when `SCAN-PLAN.json` reports infra** (`docker`/`github-actions`/
k8s/Terraform) — otherwise skip cleanly (no infra ⇒ no IaC tool invoked). When `category_tool["iac"]`
is bound (illustrative: `trivy config`, Checkov, hadolint, zizmor), run it against the rendered
manifests and load [`infra.md`](../_shared/reference/infra.md) for the patterns; else apply `infra.md`
over the files on the floor (`tool_assisted:false`). Honor ADR-006 pinning in any invocation
(pin/digest/signature; `--skip-db-update` for offline).

## Prompting stance
"Find security vulnerabilities in this code. Explain why each is exploitable and how an attacker
reaches it." Provide context and intent; delegate *how* to scan. Do not paste the exclusion list
here (that belongs in triage) — it would make you self-censor.

## Output — `VULN-FINDINGS.json`
Conforms to `_shared/reference/finding-schema.json` (validate with
`_shared/scripts/validate_findings.py`). At this stage every finding is `verified: static_review_only`;
candidate `confidence` **may be below** the report gate (triage applies the gate). `summary.counts`
may over-count (that is expected for a recall stage). Severity here is provisional — **triage
re-derives it** from preconditions; never treat the finder's score as final.

## Verification criteria (definition of done)
- [ ] Body documents partition → fan-out → system-level pass and the no-self-censor rule.
- [ ] Output declared as `VULN-FINDINGS.json` conforming to the T-1.1 schema; a run on the Phase-0
      fixture emits schema-valid JSON (`validate_findings.py`).
- [ ] stub banner removed; `SKILL.md` < 500 lines; `lint_skill` passes (once T-8.1 exists).
- [ ] No secret values written to output.
