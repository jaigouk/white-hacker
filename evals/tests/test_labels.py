"""Validate the eval corpus labels (T-7.1, TDD).

Run: uv run --with jsonschema --with pytest pytest evals/tests/test_labels.py

Asserts: >=30 cases; every label.json validates against label-schema.json; every case pairs a
vulnerable variant with a benign look-alike (both files exist); the labeled line is within bounds.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

EVALS = Path(__file__).resolve().parents[1]
CASES = sorted((EVALS / "corpus" / "cases").glob("*/label.json"))
SCHEMA = json.loads((EVALS / "label-schema.json").read_text())


def test_at_least_30_cases():
    assert len(CASES) >= 30, f"only {len(CASES)} cases"


@pytest.mark.parametrize("label_path", CASES, ids=[p.parent.name for p in CASES])
def test_label_valid_and_paired(label_path: Path):
    label = json.loads(label_path.read_text())
    errors = sorted(Draft202012Validator(SCHEMA).iter_errors(label), key=lambda e: list(e.path))
    assert not errors, [f"{'/'.join(map(str, e.path))}: {e.message}" for e in errors]

    case = label_path.parent
    vfile = case / label["vulnerable"]["file"]
    bfile = case / label["benign_lookalike"]["file"]
    assert vfile.exists(), f"missing vulnerable variant {vfile}"
    assert bfile.exists(), f"missing benign look-alike {bfile}"
    assert (case / "target.md").exists(), "missing target.md"

    n_lines = len(vfile.read_text().splitlines())
    assert 1 <= label["vulnerable"]["line"] <= n_lines, "labeled line out of bounds"


def test_case_id_matches_dir():
    for p in CASES:
        assert json.loads(p.read_text())["case_id"] == p.parent.name
