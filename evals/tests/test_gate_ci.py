"""DeepEval-style CI assertions wrapping the keep-or-revert gate (T-9.3).

Run in CI on any PR that touches ai-attack-kb/** or _shared/reference/**: it fails the job on a
REVERT verdict. Here we assert the gate-as-assertion behaves on crafted score pairs.

Run: uv run --with pytest pytest evals/tests/test_gate_ci.py
"""
from __future__ import annotations

import pytest

import keep_or_revert as kr

BASE = {"tpr": 0.90, "fpr": 0.03, "youden_j": 0.87, "precision": 0.95, "sev_weighted_recall": 0.90}


def gate_assert(baseline: dict, candidate: dict, **kw) -> str:
    """The CI assertion: a REVERT verdict fails the job; KEEP/INCONCLUSIVE return for logging."""
    v = kr.verdict(baseline, candidate, **kw)
    assert v != "REVERT", f"keep-or-revert gate REVERTed the candidate: {candidate}"
    return v


def test_ci_passes_on_improving_candidate():
    assert gate_assert(BASE, {**BASE, "youden_j": 0.89}) == "KEEP"


def test_ci_fails_on_regressing_candidate():
    with pytest.raises(AssertionError):
        gate_assert(BASE, {**BASE, "fpr": 0.05})  # FPR +2pp -> REVERT -> CI job fails


def test_ci_fails_on_locked_case_regression():
    with pytest.raises(AssertionError):
        gate_assert(BASE, {**BASE, "youden_j": 0.95}, locked_regressions=1)
