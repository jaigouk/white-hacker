# Phase 9 — Eval guardrails (frozen corpus; keep-or-revert gate; passive-drift)

> **Theme:** harden the Phase-7 baseline into the **frozen, agent-read-only** corpus + the asymmetric
> **keep-or-revert gate** that every outer-loop self-write must pass before merge. This is the ratchet
> that lets the OUTER loop edit the KB without drifting: a candidate KB version is kept **only** if it
> strictly improves (or holds) without regressing any locked case.
> **Maps to:** si-08 §6 (corpus/scoring/thresholds), §3.4 (loop guardrails), §5.2 (pre-commit checklist),
> §6.5 (CI layers + passive-drift); ADR-004 (gate before autonomy), ADR-001 (outer-loop gate).
>
> **Loop position:** OUTER (the gate). **Gating dependency:** no `sec-learn`/`sec-kb-refresh` change
> merges until this phase exists (README ordering note; si-08 §7 "nothing graduates to autonomy until the
> corpus exists"). Build Phase 8 (proposers) and Phase 9 (gate) up to the merge boundary, then the gate
> closes.
> **Exit condition:** the gate script, given a candidate KB diff, runs the frozen corpus, computes the
> asymmetric verdict, and **blocks** any change that regresses recall/precision/severity or breaks a
> locked case — wired as a CI check **and** a `PreToolUse`/`Stop` hook on KB edits.

---

## Grooming (re-groomed 2026-06-06, after Phase 8 — final phase)

**Readiness:** ✅ READY. Phases 0–8 done. The corpus (32), scorer, and confinement hooks exist.

**Reconciliations (own these):**
1. **The corpus-freeze write-block already exists.** `confine_self_writes` (T-8.4) already denies
   agent writes to `evals/corpus/**` and `keep_or_revert.py`/`baseline.json`/`score.py`
   (`FROZEN_BASENAMES`), with tests. So T-9.1 VC3 and T-9.2 VC4 **reuse** `test_confine_self_writes`
   (`-k corpus` / `-k keep_or_revert`); no new hook needed.
2. **Grow 32 → ≥100 via the generator.** Extend `generate.py` (programmatic per-language variants of
   the existing patterns, OWASP-Benchmark-style) + **3 named CVE-anchor cases** (CVE-2026-22807,
   CVE-2026-22778 vLLM; CVE-2025-68664 LangChain). Add `evals/corpus/LOCKED` enumerating case ids +
   a freeze note in the README. `test_labels.py` already validates every label.
3. **`keep_or_revert.py` is deterministic.** It takes baseline + candidate score dicts (+ per-locked-
   case results, + k≥3 run arrays) and computes the asymmetric verdict — **no RNG** (the k runs are
   inputs, so the verdict is reproducible). Read-only to the agent (already in `FROZEN_BASENAMES`).
4. **Hook registration stays human-auth-batched.** `gate_kb_edit` (T-9.3) hook logic + tests are the
   done-gate; its committed `settings.json` registration joins the one operator-auth approval. The
   **CI step** edits `ci/security-review.action.yml` (a workflow file — editable, not startup config).
5. **Docs that schedule are document-only** (T-9.5 drift re-score / red-team): describe cadence + how
   the operator schedules it; create **no live schedule** (operator's no-scheduler preference).
6. **Identity preservation is non-negotiable** (T-9.4): edits to the agent role / `.claude/rules/**` /
   `CLAUDE.md` are ALWAYS blocked, regardless of any gate verdict.

**Order:** T-9.1 → T-9.2 → T-9.4 → T-9.3 → T-9.5 → T-9.6. Phase 9 closes the outer-loop gate.

---

### T-9.1 · Freeze the corpus (read-only to the agent, signed, ≥ 100 paired cases)
- **Goal:** grow the Phase-7 corpus to ≥ 100 paired cases (vulnerable + benign look-alike; AI/LLM sinks
  covered separately; CVE regression anchors from si-08 §6.1 incl. vLLM CVE-2026-22807 / CVE-2026-22778,
  LangChain CVE-2025-68664), mark it **frozen** (signed commit), and enforce agent-write-block via the
  Phase-8 confinement hook (T-8.4). Add a `evals/corpus/LOCKED` marker listing the locked case ids.
- **Artifact:** `evals/corpus/` (grown), `evals/corpus/LOCKED`, `evals/corpus/README.md` (provenance +
  freeze note)
- **Depends on:** T-7.1, T-8.4
- **Verification criteria:**
  - [x] ≥ 100 case dirs, each with all four files + valid `label.json` — **103** cases (generator: variants + CVE anchors); `test_labels.py` validates all
  - [x] CVE regression anchors present — CVE-2026-22807 / CVE-2026-22778 (vLLM) / CVE-2025-68664 (LangChain) all present
  - [x] The confinement hook denies an agent write under `evals/corpus/**` — `pytest test_confine_self_writes.py -k corpus` (reuses T-8.4)
  - [x] `evals/corpus/LOCKED` enumerates the locked case ids — 103 ids written
- **Status:** done

### T-9.2 · `keep_or_revert.py` — asymmetric gate (agent cannot edit it)
- **Goal:** the gate (si-08 §6.4): given baseline vs candidate scores, **HARD REVERT** if `recall_loss >
  2pp` OR `FPR_gain > 1pp` OR any single locked case regresses; **KEEP only if** J non-inferior AND
  (J improves > 0.01 OR new sink coverage added); SECURITY GATE: severity-weighted recall ≥ baseline AND
  precision ≥ baseline − epsilon. 3-valued verdict (Pass/Fail/Inconclusive) from a paired bootstrap,
  k=3–5 runs/case (runs are non-deterministic). Regression = recall drop · precision drop · severity
  inversion · fix-target-break-other. The script itself is **read-only to the agent** (hook-blocked).
- **Artifact:** `evals/keep_or_revert.py` (+ `evals/tests/test_keep_or_revert.py`)
- **Depends on:** T-7.2, T-9.1
- **Verification criteria:**
  - [x] Each threshold fires on crafted score pairs (recall −2.5pp / FPR +1.5pp / locked-regress → REVERT; J +0.02 → KEEP) — `pytest test_keep_or_revert.py` *(12 tests, one per branch)*
  - [x] 3-valued verdict; "fix target while breaking any other case" → REVERT — `test_fix_target_but_break_other_reverts`
  - [x] Paired-bootstrap k≥3 produces a stable verdict on deterministic input — `test_bootstrap_stable_keep` / `_unstable_is_inconclusive`
  - [x] The confinement hook denies an agent write to `evals/keep_or_revert.py` — `pytest test_confine_self_writes.py -k keep_or_revert`
- **Status:** done *(deterministic: k runs are inputs, no RNG)*

### T-9.3 · Wire the gate as a merge gate + PreToolUse/Stop hook on KB edits
- **Goal:** express the gate as DeepEval-style pytest assertions for clean CI diffing, run it in the CI
  Action on any PR that touches `ai-attack-kb/**` or `_shared/reference/**`, **and** wire it as a
  `PreToolUse`/`Stop` hook so an in-session KB edit is gated before it can be proposed. A failing gate
  blocks the merge; a passing gate plus a green pre-commit safety checklist (T-9.4) allows the draft PR.
- **Artifact:** `evals/tests/test_gate_ci.py` (DeepEval assertions), CI step in
  `ci/security-review.action.yml`, `.claude/hooks/gate_kb_edit.sh` (+ test)
- **Depends on:** T-9.2, T-6.3, T-8.4
- **Verification criteria:**
  - [x] CI gate (DeepEval assertions) fails the job on REVERT — `pytest evals/tests/test_gate_ci.py` *(3 tests)*; the `kb-keep-or-revert-gate` job in `ci/security-review.action.yml` references `keep_or_revert`
  - [x] The `PreToolUse` hook gates a KB-edit event (blocks on REVERT/no-verdict, allows on KEEP) — `pytest test_gate_kb_edit.py` *(7 tests; Write/Edit + Bash)*
  - [x] A regressing KB diff is blocked end-to-end — `evals/audit-log.md` records the REVERT demonstration
- **Status:** done *(gate_kb_edit now WIRED in the plugin `hooks/hooks.json` PreToolUse chain — registration gap closed in the 2026-06-07 outer-loop QA, +1 test. Verified: no-verdict→block, KEEP→allow, REVERT→block, non-KB→allow. Safe to ship plugin-wide: it only fires on edits to `ai-attack-kb/`/`_shared/reference/` paths, a no-op in a user's repo.)*

### T-9.4 · Pre-commit safety checklist enforcement (the 10 gates)
- **Goal:** enforce the si-08 §5.2 mandatory checklist as a single PreToolUse-blocked self-write gate:
  schema/spec caps · references one-level-deep · source-linking present · dedup passed · identity
  preservation (no edit to agent role/`.claude/rules/`/CLAUDE.md) · confinement · self-critique passed ·
  promotion eligibility (≥ 3 sessions) · regression gate green · it is a PR on a feature branch (not
  default, not autocommit). On any failure: do not write, log to `evals/rejected.md`.
- **Artifact:** `.claude/skills/ai-attack-kb/scripts/precommit_safety.py` (+ `tests/`), `evals/rejected.md`
  (seed), `evals/audit-log.md` (seed)
- **Depends on:** T-8.1, T-8.2, T-9.2
- **Verification criteria:**
  - [x] All 10 gates implemented; a self-write failing any one is blocked + logged — `pytest test_precommit_safety.py` *(13 tests, ≥1 per gate)*
  - [x] An edit touching agent role / `.claude/rules/` / CLAUDE.md is **always** blocked — `test_identity_preservation_always_blocks` (also reconciled in `confine_self_writes`)
  - [x] A clean sourced/deduped/gate-green PATCH on a feature branch passes all 10 — `test_clean_change_passes_all_10`
  - [x] Rejections append to `evals/rejected.md` — `test_enforce_appends_to_rejected`
- **Status:** done

### T-9.5 · Passive-drift re-score + nightly red-team + second ratchet
- **Goal:** a weekly scheduled full-corpus re-score against the same thresholds (catches silent
  regression when the underlying model/provider updates, not just on self-edits); a nightly red-team
  layer (AI-redteam capability — illustrative: promptfoo redteam + Inspect) added as a CI/scheduled
  check; and the **second ratchet** — newly-confirmed true findings (+ labels) promoted INTO the frozen
  corpus so the bar keeps rising (si-08 §3.4 / §6.5).
- **Artifact:** `docs/self-improvement/eval-ops.md` (drift re-score + red-team schedule + ratchet
  procedure) + `evals/scripts/promote_finding.py` (+ test)
- **Depends on:** T-9.2, T-8.7
- **Verification criteria:**
  - [x] Doc defines the weekly passive-drift re-score against `baseline.json` thresholds (shares `keep_or_revert` logic) — greps pass
  - [x] Red-team layer documented behind the AI-redteam **capability** (optional/degradable, not a hard dep) — greps pass
  - [x] `promote_finding.py` adds a confirmed finding as a new locked case + label, run by the human/CI identity (agent is write-blocked from `evals/corpus/**`) — `pytest test_promote_finding.py` *(4 tests; refuses to clobber)*
- **Status:** done *(scheduled parts document-only — no live schedule, per the no-scheduler preference)*

### T-9.6 · Graduated-autonomy policy (earn it per-step)
- **Goal:** document the graduation policy (si-08 §7 Phase 5): everything human-gated first; only after a
  clean track record (e.g. ≥ 20 PRs where human approval matched the gate verdict) may the **lowest-risk,
  highest-precision** class be loosened — auto-merge **feed-sourced PATCH-only** fast-tier entries that
  pass the gate green, add no new sink, carry valid source+url+retrieved. CREATE, checklist edits, and any
  rule/CLAUDE.md change **remain human-gated indefinitely** (identity preservation non-negotiable).
- **Artifact:** `docs/self-improvement/autonomy-policy.md`
- **Depends on:** T-9.3, T-9.4
- **Verification criteria:**
  - [x] Policy states the track-record threshold (≥20 matched PRs) + the exact auto-merge-eligible class (feed-sourced PATCH-only, fast-tier, gate-green, no new sink, sourced) — greps pass
  - [x] States CREATE / checklist / rule / CLAUDE.md edits stay human-gated indefinitely (identity preservation) — greps pass
  - [x] References the second ratchet keeps running as autonomy widens — grep passes
- **Status:** done
