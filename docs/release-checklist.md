# Release checklist — white-hacker

Run before tagging a release (the inner-loop "did we regress?" gate; Phase 9 hardens this into the
frozen keep-or-revert merge gate).

## 1. Tests green
Per package (this is exactly what `.github/workflows/ci.yml` runs in CI; each package resolves its
own declared deps via `--project`, so no `--with jsonschema/pyyaml` is needed):
```bash
for pp in $(find plugins/white-hacker evals packaging -name pyproject.toml -not -path '*/.venv/*' | sort); do
  pkg="${pp%/pyproject.toml}"; [ -d "$pkg/tests" ] || continue
  uv run --project "$pkg" --with pytest pytest "$pkg/tests" -q || echo "FAILED: $pkg"
done
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
- Every `uses:` SHA in `.github/workflows/ci.yml` and `ci/security-review.action.yml` still resolves
  and is current; the uv version pinned in `ci.yml` is current.
- The security-review action's model id + `@anthropic-ai/claude-code` version are current
  (`ci/security-review.action.yml`).

## 4. Plugin package valid (ADR-017/028)
white-hacker ships as a plugin-shaped payload installed manually for now (ADR-028 — the in-repo
catalog serves local registration only); the package must still validate as a plugin before
tagging (the future marketplace flip stays docs-only):
- **Bump the plugin version.** Increment `version` in
  `plugins/white-hacker/.claude-plugin/plugin.json` (semver; matches the release tag).
- **Validate the manifest + catalog.** Either tool passes:
```bash
# Stdlib floor validator (no Claude CLI required) — exit 0 on success.
# Rejects unknown top-level keys in plugin.json/marketplace.json (e.g. a stray `$schema`),
# matching `claude plugin validate` — so a bogus key fails CI without the Claude CLI installed.
uv run python packaging/validate_manifest.py .
# Optional, if the CLI is installed:
claude plugin validate
```
- **Full test suite green.** Re-run step 1 (all skill/hook/eval/packaging tests, incl.
  `packaging/tests/`).
- **Marketplace source path resolves.** `.claude-plugin/marketplace.json` lists `white-hacker`
  with `source` `./plugins/white-hacker`, and that directory exists with `.claude-plugin/plugin.json`
  inside it (the validator above asserts this).

## 5. Living docs + statuses updated
- `README.md` status table, `docs/plan/*` task statuses, `docs/ARD.md` (append-only) reflect the release.
