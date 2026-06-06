# Release checklist — white-hacker

Run before tagging a release (the inner-loop "did we regress?" gate; Phase 9 hardens this into the
frozen keep-or-revert merge gate).

## 1. Tests green
```bash
uv run --with jsonschema --with pyyaml --with pytest pytest \
  .claude/skills/*/scripts/ .claude/hooks/tests/ evals/tests/
```

## 2. Eval: score the corpus and compare to the recorded baseline
```bash
# Score a findings run over the labeled corpus -> TPR / FPR / Youden's J.
uv run --with jsonschema python evals/score.py \
  --findings evals/runs/baseline-findings.json \
  --corpus   evals/corpus/cases
```
- Compare the printed `youden_j` / `fpr` against **`evals/baseline.json`** (recorded:
  J=0.875, TPR=0.906, FPR=0.031 over 32 cases as of 2026-06-06, commit 4a9a3ce).
- **Determinism:** re-running `score.py` on the same findings snapshot + corpus reproduces the
  recorded numbers exactly (no agent call in the scorer). Any change to `youden_j`/`fpr` is a real
  signal, not noise.
- **Record the FP rate** for the release. A drop in J or a rise in FPR vs. baseline blocks the
  release until explained or fixed.
- **Refresh the baseline** when the corpus changes or a real `/security-review` run over the corpus
  is captured: replace `evals/runs/baseline-findings.json` with the captured findings, re-score, and
  update `evals/baseline.json` (date + commit). The current snapshot is a documented SYNTHETIC
  representative run (not a measured agent run).

## 3. Pins current (ADR-006)
- CI action model id + `@anthropic-ai/claude-code` version + every `uses:` SHA still resolve and are
  current (`ci/security-review.action.yml`).

## 4. Living docs + statuses updated
- `README.md` status table, `docs/plan/*` task statuses, `docs/ARD.md` (append-only) reflect the release.
