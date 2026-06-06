"""Tests for the second-ratchet promotion (T-9.5, TDD).

Run: uv run --with jsonschema --with pytest pytest evals/tests/test_promote_finding.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import promote_finding as pf

SCHEMA = json.loads((Path(__file__).resolve().parents[1] / "label-schema.json").read_text())

SPEC = {
    "case_id": "py-confirmed-ssti-001", "ext": "py", "language": "python",
    "category": "injection", "severity": "HIGH", "owasp": ["A03:2025"],
    "vulnerable_code": 'from jinja2 import Template\ndef r(x):\n    return Template("Hi " + x).render()  # SINK ssti\n',
    "benign_code": 'from jinja2 import Template\ndef r(x):\n    return Template("Hi {{ n }}").render(n=x)\n',
    "vulnerable_line": 3, "note": "confirmed in review session s42",
}


def test_promote_creates_four_files_and_valid_label(tmp_path):
    corpus = tmp_path / "corpus"
    (corpus / "cases").mkdir(parents=True)
    (corpus / "LOCKED").write_text("# locked\nexisting-case\n")
    d = pf.promote(corpus, SPEC)
    for f in ("target.md", "label.json", "vulnerable_variant.py", "benign_lookalike.py"):
        assert (d / f).exists(), f
    label = json.loads((d / "label.json").read_text())
    assert not list(Draft202012Validator(SCHEMA).iter_errors(label))
    assert label["vulnerable"]["line"] == 3


def test_promote_appends_to_locked(tmp_path):
    corpus = tmp_path / "corpus"
    (corpus / "cases").mkdir(parents=True)
    (corpus / "LOCKED").write_text("# locked\nexisting-case\n")
    pf.promote(corpus, SPEC)
    assert "py-confirmed-ssti-001" in (corpus / "LOCKED").read_text()


def test_promote_refuses_to_clobber(tmp_path):
    corpus = tmp_path / "corpus"
    (corpus / "cases" / SPEC["case_id"]).mkdir(parents=True)
    with pytest.raises(FileExistsError):
        pf.promote(corpus, SPEC)  # never overwrite an existing locked case


def test_main_usage():
    assert pf.main([]) == 2
