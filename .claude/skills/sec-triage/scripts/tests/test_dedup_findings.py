"""Tests for the deterministic dedup pass (T-1.4). TDD per ADR-013.

Run: uv run --with jsonschema --with pytest pytest .claude/skills/sec-triage/scripts/
"""
from __future__ import annotations

import copy

import dedup_findings as dd
import validate_findings as vf


def mkf(fid, file="a.go", line=10, category="injection", severity="HIGH", canonical_of=None):
    return {
        "id": fid,
        "canonical_of": canonical_of,
        "file": file,
        "line": line,
        "severity": severity,
        "category": category,
        "owasp": ["A03:2025"],
        "preconditions": [],
        "access_required": "unauth-remote",
        "verified": "static_review_only",
        "confidence": 0.9,
        "exploit_scenario": "x",
        "recommendation": "y",
        "first_link": f"{file}:{line}",
        "tool_assisted": False,
        "kb_refs": [],
    }


def doc_with(*findings):
    return {
        "summary": {
            "scanned_langs": ["go"],
            "tools_used": ["floor"],
            "tools_unavailable": [],
            "scoring_standard": "CVSS4.0",
            "counts": {"high": 0, "medium": 0, "low": 0},
        },
        "findings": list(findings),
    }


def test_collapses_same_file_category_within_window():
    d = doc_with(mkf("F-001", line=10), mkf("F-002", line=15))  # 5 lines apart
    out = dd.dedup(d)
    assert out["findings"][0]["canonical_of"] is None
    assert out["findings"][1]["canonical_of"] == "F-001"


def test_different_category_not_collapsed():
    d = doc_with(mkf("F-001", line=10, category="injection"),
                 mkf("F-002", line=12, category="xss"))
    out = dd.dedup(d)
    assert out["findings"][1]["canonical_of"] is None  # distinct class → kept


def test_far_apart_not_collapsed():
    d = doc_with(mkf("F-001", line=10), mkf("F-002", line=30))  # 20 lines apart > window
    out = dd.dedup(d)
    assert out["findings"][1]["canonical_of"] is None


def test_different_file_not_collapsed():
    d = doc_with(mkf("F-001", file="a.go", line=10), mkf("F-002", file="b.go", line=10))
    out = dd.dedup(d)
    assert out["findings"][1]["canonical_of"] is None


def test_idempotent():
    d = doc_with(mkf("F-001", line=10), mkf("F-002", line=15), mkf("F-003", line=100))
    once = dd.dedup(d)
    twice = dd.dedup(once)
    assert once == twice


def test_counts_recomputed_over_canonicals():
    d = doc_with(mkf("F-001", line=10, severity="HIGH"),
                 mkf("F-002", line=12, severity="HIGH"),   # dup of F-001
                 mkf("F-003", file="b.go", line=1, severity="LOW"))
    out = dd.dedup(d)
    # only 2 canonical findings: one HIGH, one LOW
    assert out["summary"]["counts"] == {"high": 1, "medium": 0, "low": 1}


def test_output_validates_against_schema():
    d = doc_with(mkf("F-001", line=10), mkf("F-002", line=15))
    out = dd.dedup(d)
    assert vf.validate(out) == []


def test_no_dup_ids_after_dedup():
    d = doc_with(mkf("F-001", line=10), mkf("F-002", line=15))
    out = dd.dedup(d)
    assert vf.duplicate_ids(out) == []


def test_window_is_configurable():
    d = doc_with(mkf("F-001", line=10), mkf("F-002", line=30))
    assert dd.dedup(d, window=25)["findings"][1]["canonical_of"] == "F-001"
