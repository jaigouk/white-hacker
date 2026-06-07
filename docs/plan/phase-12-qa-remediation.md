# Phase 12 — QA remediation (resolve the issues the 2026-06-07 baseline surfaced)

> **Status:** groomed (todo). Date: 2026-06-07. Owner: ping@jaigouk.kim.
> Source: [`docs/qa/20260607/full-baseline-report.md`](../qa/20260607/full-baseline-report.md)
> (QA-8, J=0.835 over 103 cases). **Gate:** `evals/baseline.json` (J=0.835, FPR 0.049) — every fix
> is measured against it. **Plan-first:** proposals; nothing built until approved.

## What the baseline found (the issues to resolve)
| # | Issue | Evidence |
|---|-------|----------|
| I-1 | **AuthN/AuthZ recall is poor** | J=0.25 — 9 of 12 cases missed (FN) |
| I-2 | **SSRF false-positives** | 5 FP, all `py-ssrf*` benign look-alikes over-flagged |
| I-3 | **Singleton misses** | 1 FN each in crypto, improper-output-handling, tool-poisoning |
| I-4 | **Baseline is sonnet / single-shot** | DEFERRED in QA-8 — not yet production-opus + k-run |

## This is outer-loop work (the elegant part)
The fixes are **Context-surface edits** (reference appendices, checklists, the KB) — *not* code, *not*
retraining (ADR-001/004). Route them through `sec-learn` → propose dated diffs → the **keep-or-revert
gate** decides. The baseline this QA just produced **is** the gate. Loop closed.

## The measurement loop (every fix obeys this)
1. **Root-cause first** (DDD) — never patch a symptom. Distinguish three causes for each miss/FP:
   (a) a real **agent-recall/precision gap** (fixable via Context), (b) an **eval-harness artifact**
   (the blind per-file pair strips cross-function context a real `/security-review` would have — see
   I-1 caution), or (c) a **label/scope issue** (e.g. architectural classes on the DO-NOT-REPORT line).
2. **Edit the Context** (reference/checklist/KB) — minimal, surgical.
3. **Re-measure**: re-run the agent over the affected subset via the QA harness (neutralized
   filenames), `evals/score.py`, then `evals/keep_or_revert.py` vs `evals/baseline.json`.
4. **Gate:** KEEP only if the target class improves AND overall **J ≥ 0.835** AND **FPR not worse**.
   REVERT otherwise. Runs cost tokens (subscription, no key) — scope to the affected subset.

## Conventions
Inherit `docs/plan/README.md`. TDD for any executable change; reference/KB edits are size-capped
(ADR-005) and pass `validate_kb`/`lint_skill`. IDs typed, never renumbered.

---

### T-12.1 · Root-cause the AuthN/AuthZ misses (analysis-first; harness vs agent vs label)
- **Goal:** explain WHY 9/12 authz cases were missed and decide the cause class (a/b/c above) per case.
- **Artifact:** `docs/qa/20260607/authz-miss-analysis.md` — per FN case: the agent's actual verdict
  (from `full-run-mapping.json` + verdicts) vs the label; cause class; fix hypothesis.
- **Depends on:** — (consumes QA-8).
- **Verification criteria:**
  - [ ] all 9 authz FN cases listed with agent-verdict vs label and a cause class (a/b/c)
  - [ ] **harness-artifact check:** re-review ≥3 of them giving the agent the FULL case (route+handler+ownership, not the stripped single file); record whether recall improves — i.e. is J=0.25 partly a harness artifact, not a true agent gap?
  - [ ] a concrete, testable fix hypothesis per real-gap case (what Context edit would catch it)
- **Status:** todo

### T-12.2 · Lift AuthN/AuthZ recall via the outer loop (Context edit + re-measure)
- **Goal:** raise the AuthN/AuthZ subset J above 0.25 without regressing overall J or FPR.
- **Artifact:** `sec-learn`-proposed edits to `plugins/white-hacker/skills/_shared/reference/{api.md,core-checklist.md}` (BOLA/IDOR/BFLA reachability + ownership-check heuristics); re-measured run under `docs/qa/<date>/`.
- **Depends on:** T-12.1 (only for the cases T-12.1 classes as real agent gaps).
- **Verification criteria:**
  - [ ] AuthN/AuthZ subset J improves materially (target ≥ 0.50) on a re-run — `evals/score.py` per-category
  - [ ] overall **J ≥ 0.835** and **FPR ≤ 0.049** — `evals/keep_or_revert.py` returns KEEP vs `evals/baseline.json`
  - [ ] reference edits pass `lint_skill` size caps; diff is reviewable (PATCHES/sec-learn path, human-applied)
- **Status:** todo

### T-12.3 · Cut the SSRF false-positives (the 5 `py-ssrf*` benigns)
- **Goal:** stop flagging safe SSRF look-alikes (allow-list + DNS-pin + no server-side fetch) without missing real SSRF.
- **Artifact:** edits to `_shared/reference/` SSRF guidance + `exclusion-rules.md` ("mitigated SSRF" recognizer; path-only-SSRF already excluded); re-measured ssrf subset.
- **Depends on:** T-12.1 (FP root-cause of the 5).
- **Verification criteria:**
  - [ ] the 5 `py-ssrf*` benigns are NOT flagged on a re-run (subset FP → 0) — `score.py` ssrf `fp`
  - [ ] ssrf true-positives unchanged (tp = 16; no new FN) and overall J ≥ 0.835 — keep_or_revert KEEP
  - [ ] a regression case pins it: a benign mitigated-SSRF fixture stays clean AND a real SSRF stays flagged
- **Status:** todo

### T-12.4 · Resolve the singleton misses (crypto, improper-output-handling, tool-poisoning)
- **Goal:** root-cause + fix the 1 FN each; reconcile architectural classes with the exclusion rules.
- **Artifact:** per-case note in the authz/miss analysis doc; targeted reference/KB tweak where it's a real gap.
- **Depends on:** T-12.1.
- **Verification criteria:**
  - [ ] each of the 3 FN root-caused (real gap vs harness artifact vs label/scope nuance)
  - [ ] **tool-poisoning** explicitly reconciled: if it's architectural (like prompt-injection on the DO-NOT-REPORT line), record it as a label/scope decision, NOT an agent defect — update the corpus label note or the exclusion rationale rather than forcing a finding
  - [ ] any Context fix re-measured: overall J ≥ 0.835, no FPR regression — keep_or_revert KEEP
- **Status:** todo

### T-12.5 · Production re-baseline (opus + k-run bootstrap) — the DEFERRED QA-8 item
- **Goal:** replace the sonnet single-shot baseline with a production-opus, k-run paired-bootstrap baseline so the gate is production-grade.
- **Artifact:** refreshed `evals/baseline.json` (model=opus, k≥3 aggregated), `evals/runs/`, a new `docs/qa/<YYYYMMDD>/` cycle.
- **Depends on:** T-12.2/12.3/12.4 (re-baseline AFTER the fixes land, so the gate reflects the improved agent). Token-budget gated; subscription, no key.
- **Verification criteria:**
  - [ ] baseline.json `model` = opus, k≥3 runs aggregated; drift-guard (`test_baseline_tracks_corpus`) green
  - [ ] refresh documented in `docs/release-checklist.md`; cost recorded
- **Status:** todo

### T-12.6 · Close the remaining QA tiers (from `qa-flows.md`)
- **Goal:** finish the live/adversarial tiers still open after the 2026-06-07 cycle.
- **Artifact:** updates under `docs/qa/<date>/`.
- **Depends on:** —.
- **Verification criteria:**
  - [ ] QA-3 live: `claude plugin validate` (and/or `--plugin-dir`) loads the plugin; skills namespaced; hooks register
  - [ ] QA-6 live: the first GitHub Actions run (post-push) observed green; fix any runner-specific issue
  - [ ] QA-5 live: a real team-mode handoff (white-hacker → tech-lead via SendMessage, WAIT-exit) exercised
  - [ ] QA-7: untrusted-input sweep across the remaining ingestion points (reviewed code, KB text, feed content)
- **Status:** todo

---

## Priority / ordering
**I-1/I-2 first** (highest-impact agent-quality issues), starting with **T-12.1 root-cause** — it may
show part of I-1 is a *harness artifact* (per-file context-stripping), which would change the fix from
"edit the checklist" to "give the eval more context / document the limitation." Then T-12.2/12.3 in
parallel (different reference sections), T-12.4, then T-12.5 re-baseline once the agent improves, with
T-12.6 (remaining tiers) opportunistic. Each quality fix is a small `sec-learn` diff measured against
the gate — the outer loop doing exactly what it was built for.

## Team execution — grouped waves (TL / Devs / QA / white-hacker)
**Roles.** **TL** — sequence the waves, own each keep-or-revert gate decision, the re-baseline, and
integration. **Devs** — the Context edits + per-case analysis. **QA** — run the measurement loop
(re-run the agent over the affected subset → `score.py` → `keep_or_revert.py`) + the drift-guard.
**white-hacker/security** — review any edit touching untrusted-input/confinement; owns QA-7 adversarial.

**Parallelism rule.** Devs edit **different reference files** (authz: `api.md`/`core-checklist.md` ·
ssrf: ssrf reference + `exclusion-rules.md` · singletons: `crypto`/`ai-llm` reference) → no file
collision. QA measures each fix **in isolation on its subset**, then one **combined full 103-run**
before merge. The gate (overall **J ≥ 0.835**, **FPR ≤ 0.049**) is checked per-fix and on the combined run.

| Wave | Run together | Owners | Gate |
|------|--------------|--------|------|
| **A — analysis** (no gate) | **T-12.1** authz root-cause (incl. harness-vs-agent re-review) · **T-12.3 step 1** ssrf-FP root-cause · **T-12.6 partial** (QA-3 plugin smoke, QA-6 observe CI) | Dev-1+QA · Dev-2 · QA | — |
| **B — fixes** (parallel, after A) | **T-12.2** authz recall · **T-12.3 step 2** ssrf FP fix · **T-12.4** singletons | Dev-1 · Dev-2 · Dev-3; white-hacker reviews ssrf/exclusion + untrusted-input edits; QA measures each | per-fix + combined: KEEP vs `baseline.json` |
| **C — after fixes land** | **T-12.5** opus + k-run re-baseline · **T-12.6 remainder** (QA-5 team-mode, QA-7 input sweep) | TL+QA · Dev+white-hacker | drift-guard green |

**Dependency DAG:** `T-12.1 → {T-12.2, T-12.4}` · `T-12.3` independent (own analysis) ·
`{T-12.2, T-12.3, T-12.4} → T-12.5` · `T-12.6` opportunistic. Wave A and the cheap T-12.6 items can
start immediately; Wave B fans out 3 Devs once T-12.1 classifies the misses (agent-gap vs harness vs label).
