"""Tests for the deterministic dedup pass (T-1.4). TDD per ADR-013.

Run: uv run --with jsonschema --with pytest pytest plugins/white-hacker/skills/sec-triage/scripts/
"""
from __future__ import annotations

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


# === wh-5ox.10: collapsing must PRESERVE the duplicate's MITRE attribution =====
def _attr(f, att_ck=None, atlas=None, disputed=None):
    f["att_ck"] = att_ck or []
    f["atlas"] = atlas or []
    if disputed is not None:
        f["disputed"] = disputed
    return f


def test_dedup_merges_duplicate_attribution_onto_canonical():
    # The duplicate (F-002) carries MITRE ids + a dispute the canonical (F-001) lacks.
    # Collapsing must NOT silently drop them — the canonical inherits the union.
    canon = _attr(mkf("F-001", line=10), att_ck=["T1195.002"], atlas=[])
    dup = _attr(mkf("F-002", line=12),
                att_ck=["T1195.002", "T1552.005"],          # one shared, one new
                atlas=["AML.T0010"],
                disputed={"claim": "c", "dispute_source": "s", "status": "unresolved"})
    out = dd.dedup(doc_with(canon, dup))
    merged = out["findings"][0]
    assert out["findings"][1]["canonical_of"] == "F-001"    # the collapse still happened
    assert merged["att_ck"] == ["T1195.002", "T1552.005"]   # == union, order-stable, deduped
    assert merged["atlas"] == ["AML.T0010"]                 # == the dup's atlas adopted
    assert merged["disputed"]["status"] == "unresolved"     # == the dup's dispute adopted


def test_dedup_does_not_overwrite_existing_canonical_dispute():
    # If the canonical ALREADY has a dispute, the duplicate's does NOT clobber it.
    canon = _attr(mkf("F-001", line=10),
                  disputed={"claim": "keep-me", "dispute_source": "a", "status": "confirmed"})
    dup = _attr(mkf("F-002", line=12),
                disputed={"claim": "drop-me", "dispute_source": "b", "status": "unresolved"})
    out = dd.dedup(doc_with(canon, dup))
    assert out["findings"][0]["disputed"]["claim"] == "keep-me"   # == canonical's kept
    assert out["findings"][0]["disputed"]["claim"] != "drop-me"   # != the dup's


def test_dedup_attribution_merge_is_idempotent():
    canon = _attr(mkf("F-001", line=10), att_ck=["T1195.002"])
    dup = _attr(mkf("F-002", line=12), att_ck=["T1552.005"], atlas=["AML.T0010"])
    once = dd.dedup(doc_with(canon, dup))
    twice = dd.dedup(once)
    assert once == twice                                    # re-running collapses nothing new
