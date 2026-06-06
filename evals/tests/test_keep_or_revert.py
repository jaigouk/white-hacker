"""Tests for the asymmetric keep-or-revert gate (T-9.2, TDD).

Run: uv run --with pytest pytest evals/tests/test_keep_or_revert.py

One test per branch: recall loss / FPR gain / locked-case regress / fix-target-break-other ->
REVERT; J improvement -> KEEP; non-inferior-but-not-better -> INCONCLUSIVE; bootstrap stability;
security gate (precision / severity-weighted recall).
"""
from __future__ import annotations

import keep_or_revert as kr

BASE = {"tpr": 0.90, "fpr": 0.03, "youden_j": 0.87, "precision": 0.95, "sev_weighted_recall": 0.90}


def _c(**kw):
    d = dict(BASE)
    d.update(kw)
    return d


def test_recall_loss_reverts():
    assert kr.verdict(BASE, _c(tpr=0.875, sev_weighted_recall=0.875, youden_j=0.845)) == "REVERT"


def test_fpr_gain_reverts():
    assert kr.verdict(BASE, _c(fpr=0.045, youden_j=0.855)) == "REVERT"


def test_locked_case_regress_reverts():
    assert kr.verdict(BASE, _c(youden_j=0.92), locked_regressions=1) == "REVERT"


def test_fix_target_but_break_other_reverts():
    # improves overall J but breaks one previously-passing locked case -> REVERT (si-08 6.3)
    assert kr.verdict(BASE, _c(youden_j=0.95, tpr=0.93), locked_regressions=1) == "REVERT"


def test_j_improvement_keeps():
    assert kr.verdict(BASE, _c(youden_j=0.89)) == "KEEP"  # +0.02 > 0.01, no regress


def test_new_coverage_keeps_even_without_j_jump():
    assert kr.verdict(BASE, _c(youden_j=0.872), new_coverage=True) == "KEEP"


def test_non_inferior_but_not_better_is_inconclusive():
    assert kr.verdict(BASE, _c(youden_j=0.873)) == "INCONCLUSIVE"  # +0.003, no new coverage


def test_security_gate_precision_drop_reverts():
    assert kr.verdict(BASE, _c(youden_j=0.90, precision=0.93)) == "REVERT"  # precision -2pp > eps


def test_security_gate_sev_recall_drop_reverts():
    assert kr.verdict(BASE, _c(youden_j=0.90, sev_weighted_recall=0.88)) == "REVERT"


def test_bootstrap_stable_keep():
    runs = [{"tpr": 0.90, "fpr": 0.03, "youden_j": 0.89, "precision": 0.95, "sev_weighted_recall": 0.90}] * 3
    assert kr.verdict(BASE, runs=runs) == "KEEP"


def test_bootstrap_unstable_is_inconclusive():
    runs = [
        {"tpr": 0.90, "fpr": 0.03, "youden_j": 0.89, "precision": 0.95, "sev_weighted_recall": 0.90},  # keepable
        {"tpr": 0.90, "fpr": 0.03, "youden_j": 0.872, "precision": 0.95, "sev_weighted_recall": 0.90},  # not
        {"tpr": 0.90, "fpr": 0.03, "youden_j": 0.89, "precision": 0.95, "sev_weighted_recall": 0.90},
    ]
    assert kr.verdict(BASE, runs=runs) == "INCONCLUSIVE"


def test_main_exit_codes(tmp_path):
    import json
    b = tmp_path / "b.json"; b.write_text(json.dumps(BASE))
    keep = tmp_path / "k.json"; keep.write_text(json.dumps(_c(youden_j=0.89)))
    rev = tmp_path / "r.json"; rev.write_text(json.dumps(_c(fpr=0.05)))
    assert kr.main(["--baseline", str(b), "--candidate", str(keep)]) == 0
    assert kr.main(["--baseline", str(b), "--candidate", str(rev)]) == 1
