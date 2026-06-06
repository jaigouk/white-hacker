"""The asymmetric keep-or-revert gate (Phase 9 T-9.2; si-08 §6.4).

Given baseline vs candidate corpus scores, decide whether an outer-loop KB change may merge. The
gate is **asymmetric** — it is easy to REVERT, hard to KEEP — so the KB can only ratchet up:

  HARD REVERT if:  recall_loss > 2pp  OR  FPR_gain > 1pp  OR  any locked case regresses
                   OR severity-weighted recall < baseline  OR precision < baseline - epsilon.
  KEEP only if:    Youden's J non-inferior (>= baseline - epsilon)  AND
                   (J improves > 0.01  OR  new sink coverage added).
  else:            INCONCLUSIVE (needs a human).

3-valued verdict. With k>=3 paired-bootstrap runs (runs are non-deterministic), the runs are
INPUTS here so the verdict is reproducible: if any run trips a hard-revert -> REVERT; if the runs
disagree on keepability -> INCONCLUSIVE. This script is **read-only to the agent** (confinement
hook, T-8.4: it is in FROZEN_BASENAMES) — a learning pass cannot edit its own exam.

CLI:
    uv run python keep_or_revert.py --baseline b.json --candidate c.json [--locked-regressions N] [--new-coverage]
Exit 0 = KEEP, 1 = REVERT, 2 = INCONCLUSIVE / usage.
"""
from __future__ import annotations

import argparse
import json
import sys

RECALL_REVERT = 0.02   # > 2pp recall loss
FPR_REVERT = 0.01      # > 1pp FPR gain
J_KEEP = 0.01          # J must improve by > 1pp to KEEP (unless new coverage)
EPS = 0.005


def _recall(d: dict) -> float:
    return d.get("sev_weighted_recall", d.get("tpr", d.get("recall", 0.0)))


def _hard_revert(baseline: dict, cand: dict, locked_regressions: int) -> bool:
    if locked_regressions and locked_regressions > 0:
        return True
    if _recall(baseline) - _recall(cand) > RECALL_REVERT:
        return True
    if cand.get("fpr", 0.0) - baseline.get("fpr", 0.0) > FPR_REVERT:
        return True
    # security gate: severity-weighted recall must not drop; precision within epsilon
    if cand.get("sev_weighted_recall", _recall(cand)) < baseline.get("sev_weighted_recall", _recall(baseline)) - 1e-9:
        return True
    pb, pc = baseline.get("precision"), cand.get("precision")
    if pb is not None and pc is not None and pc < pb - EPS:
        return True
    return False


def verdict(baseline: dict, candidate: dict | None = None, *, locked_regressions: int = 0,
            new_coverage: bool = False, runs: list[dict] | None = None) -> str:
    if candidate is None and runs:
        keys = runs[0].keys()
        candidate = {k: sum(r[k] for r in runs) / len(runs) for k in keys}
    assert candidate is not None, "need candidate or runs"

    if _hard_revert(baseline, candidate, locked_regressions):
        return "REVERT"

    if runs:
        # each run must individually avoid a hard revert; the runs must agree on keepability.
        if any(_hard_revert(baseline, r, locked_regressions) for r in runs):
            return "REVERT"
        keepable = {(_keepable(baseline, r, new_coverage)) for r in runs}
        if len(keepable) > 1:
            return "INCONCLUSIVE"

    return "KEEP" if _keepable(baseline, candidate, new_coverage) else "INCONCLUSIVE"


def _keepable(baseline: dict, cand: dict, new_coverage: bool) -> bool:
    j_delta = cand.get("youden_j", 0.0) - baseline.get("youden_j", 0.0)
    return j_delta >= -EPS and (j_delta > J_KEEP or new_coverage)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="keep_or_revert.py")
    p.add_argument("--baseline", required=True)
    p.add_argument("--candidate", required=True)
    p.add_argument("--locked-regressions", type=int, default=0)
    p.add_argument("--new-coverage", action="store_true")
    try:
        ns = p.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit:
        return 2
    b = json.loads(open(ns.baseline).read())
    c = json.loads(open(ns.candidate).read())
    v = verdict(b, c, locked_regressions=ns.locked_regressions, new_coverage=ns.new_coverage)
    print(v)
    return {"KEEP": 0, "REVERT": 1, "INCONCLUSIVE": 2}[v]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
