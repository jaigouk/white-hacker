"""Drift-guard (QA-8 / FINDING-QA1): the eval baseline must track the frozen corpus.

This fails CI when the corpus grows (or shrinks) without a baseline refresh — the exact drift
that left `baseline.json` at the 32-case synthetic era while the corpus reached 103 cases.

Run: uv run --project evals --with pytest pytest evals/tests/test_baseline_tracks_corpus.py
"""
from __future__ import annotations

import json
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve()
REPO = next(c for c in (_HERE, *_HERE.parents) if (c / ".git").exists())
EVALS = REPO / "evals"
CORPUS = EVALS / "corpus" / "cases"
sys.path.insert(0, str(EVALS))

import score  # noqa: E402  (path inserted above)


def _baseline() -> dict:
    return json.loads((EVALS / "baseline.json").read_text())


def _corpus_n() -> int:
    return len(list(CORPUS.glob("*/label.json")))


def test_baseline_n_cases_tracks_corpus():
    b = _baseline()
    n = _corpus_n()
    assert b["n_cases"] == n, (
        f"baseline.json n_cases={b['n_cases']} but the corpus has {n} cases — "
        "refresh the baseline over the full corpus (QA-8)."
    )


def test_baseline_findings_reproduce_metrics():
    """The recorded snapshot, re-scored over the corpus, must reproduce baseline.json exactly
    (score.py is deterministic). Guards snapshot/baseline/corpus from silently diverging."""
    labels = score.load_labels(None, str(CORPUS))
    findings = json.loads((EVALS / "runs" / "baseline-findings.json").read_text())
    res = score.score(findings, labels)
    b = _baseline()
    for k in ("tp", "fn", "fp", "tn"):
        assert res[k] == b[k], f"{k}: snapshot re-score {res[k]} != baseline {b[k]}"
    assert round(res["youden_j"], 6) == round(b["youden_j"], 6)
