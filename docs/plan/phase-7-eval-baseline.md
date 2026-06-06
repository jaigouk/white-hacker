# Phase 7 — Eval baseline (a labeled finding set; FP-rate tracking)

> **Theme:** stand up the *minimum* eval baseline the inner loop needs to validate releases: a labeled
> finding set (planted vulns + clean look-alikes), a deterministic scorer, and an FP-rate number tracked
> before each release. This is the **seed** that Phase 9 freezes into the keep-or-revert corpus the outer
> loop depends on.
> **Maps to:** PLAN §8.1 P7; si-08 §6 (corpus design — the *baseline* subset), §6.2 (Youden's J).
>
> **Loop position:** BRIDGE. Phase 7 = "does this release regress against a labeled set?"; Phase 9 hardens
> the same corpus into the frozen, agent-read-only gate. Build Phase 7 first; Phase 9 freezes it.
> **Exit condition:** `score.py` runs the pipeline over the labeled set and prints TPR/FPR + Youden's J;
> a release checklist records the FP rate; the corpus reuses the Phase-0/4/5 fixtures already on disk.

> **Relationship to Phase 9.** Phase 7 is the *working* eval (the agent may add cases as it builds
> fixtures). Phase 9 **freezes** it: marks it read-only to the agent (hook-enforced), adds the asymmetric
> keep-or-revert thresholds, and wires it as a merge gate for any `sec-learn`/`sec-kb-refresh` change.
> Do not let any outer-loop self-write merge until Phase 9 is done (README ordering note).

---

### T-7.1 · Assemble the labeled corpus (vulnerable + clean look-alike pairs)
- **Goal:** an `evals/corpus/` of ≥ 30 paired cases to start (target ≥ 100 by Phase 9), each with a
  `target`, a `vulnerable_variant`, a `benign_lookalike`, and a `label.json` (expected `file:line`,
  category, severity). Seed from the Phase-0 floor fixtures, the Phase-4 AI fixtures, the Phase-5 patch
  fixture, plus real CVE pre/post-fix anchors (si-08 §6.1).
- **Artifact:** `evals/corpus/cases/<id>/{target.*, vulnerable_variant.*, benign_lookalike.*, label.json}`
  + `evals/corpus/README.md` (ground-truth provenance)
- **Depends on:** T-0.5, T-4.6, T-5.4
- **Verification criteria:**
  - [ ] ≥ 30 case dirs, each with all four files — `test -d evals/corpus/cases && [ $(ls -d evals/corpus/cases/*/ | wc -l) -ge 30 ]`
  - [ ] Every `label.json` validates against a label schema (expected findings + clean flag) — `uv run pytest evals/tests/test_labels.py`
  - [ ] Each case pairs a vulnerable with a clean look-alike (the FP term) — asserted by the label test (every case has both variants)
  - [ ] AI/LLM sinks are represented (prompt-injection / LLM05 / excessive-agency) — `grep -rqiE 'prompt.injection|insecure.output|excessive.agency' evals/corpus/cases/*/label.json`
- **Status:** todo

### T-7.2 · Deterministic scorer (`score.py`, Youden's J)
- **Goal:** a scorer that runs the review pipeline over the corpus, compares against labels, and emits
  TPR, FPR, and **Youden's J (TPR − FPR)** (si-08 §6.2 — the OWASP Benchmark convention) as a single
  deterministic number per run, plus per-category breakdown.
- **Artifact:** `evals/score.py` (+ `evals/pyproject.toml`, `evals/tests/test_score.py`)
- **Depends on:** T-7.1, T-1.1
- **Verification criteria:**
  - [ ] On a synthetic labeled set with known TP/FP/FN counts, `score.py` returns the arithmetically correct TPR/FPR/J — `uv run pytest evals/tests/test_score.py` (>1 case incl. a perfect run J=1 and an all-FP run)
  - [ ] Output is machine-readable JSON (`{tpr, fpr, youden_j, by_category}`) — asserted in test
  - [ ] A finding matches a label by `file` + category + line-within-tolerance (no exact-line brittleness) — tolerance edge-case test
- **Status:** todo

### T-7.3 · Release FP-rate tracking + baseline record
- **Goal:** capture a baseline score and an FP rate as a checked-in number, and a release checklist that
  re-runs `score.py` and compares to the recorded baseline before each release (the inner-loop "did we
  regress?" gate, pre-freeze).
- **Artifact:** `evals/baseline.json` (recorded J/TPR/FPR) + `docs/release-checklist.md`
- **Depends on:** T-7.2
- **Verification criteria:**
  - [ ] `evals/baseline.json` exists, validates as `{tpr,fpr,youden_j,date,commit}` — `uv run python -c 'import json;d=json.load(open("evals/baseline.json"));assert {"tpr","fpr","youden_j"}<=d.keys()'`
  - [ ] `score.py` re-run reproduces the recorded baseline within the run-to-run tolerance (determinism check) — documented runnable command in the checklist
  - [ ] `docs/release-checklist.md` includes the "run score.py, compare to baseline.json, record FP rate" step — `grep -q 'score.py' docs/release-checklist.md && grep -qi 'baseline' docs/release-checklist.md`
- **Status:** todo
