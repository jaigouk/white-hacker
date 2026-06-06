"""Tests for the degradation glue (degradation.py).

Unit tests for the helper here; the cross-capability *integration* tests
(`test_floor_only`, `test_tool_present`) are added in T-3.6 once the normalizers exist.

Run: `uv run --with pytest pytest .claude/skills/_shared/scripts/tests/test_degradation.py`
"""
from __future__ import annotations

import degradation as dg
# Cross-capability integration (T-3.6): the _shared conftest puts the sibling skill scripts on path.
import detect_tools as dt
import normalize_deps as nd
import redact as rd
import validate_findings as vf


# Two SCAN-PLAN shapes: one fully degraded, one with sca/secrets tools present.
FLOOR_PLAN = {
    "category_tool": {"sast": None, "sca": None, "secrets": None},
    "degraded": ["sast", "sca", "secrets"],
}
TOOLED_PLAN = {
    "category_tool": {"sast": None, "sca": "trivy", "secrets": "gitleaks"},
    "degraded": ["sast"],
}


def _finding(**over):
    base = {"id": "F-001", "category": "supply-chain", "confidence": 0.95,
            "tool_assisted": False}
    base.update(over)
    return base


# --- summary_tools --------------------------------------------------------
def test_summary_tools_all_degraded():
    s = dg.summary_tools(FLOOR_PLAN)
    assert s["tools_used"] == []
    assert s["tools_unavailable"] == ["sast", "sca", "secrets"]


def test_summary_tools_with_tools_present():
    s = dg.summary_tools(TOOLED_PLAN)
    assert s["tools_used"] == ["gitleaks", "trivy"]   # sorted, deduped, non-null
    assert s["tools_unavailable"] == ["sast"]


def test_summary_tools_empty_plan_does_not_raise():
    assert dg.summary_tools({}) == {"tools_used": [], "tools_unavailable": []}


# --- stamp_tool_assisted --------------------------------------------------
def test_stamp_true_when_tool_bound():
    f = dg.stamp_tool_assisted(_finding(), TOOLED_PLAN, "sca")
    assert f["tool_assisted"] is True


def test_stamp_false_when_degraded():
    f = dg.stamp_tool_assisted(_finding(), TOOLED_PLAN, "sast")
    assert f["tool_assisted"] is False


def test_stamp_false_when_capability_absent_from_plan():
    # iac not in the plan at all (e.g. no infra) -> not tool-assisted, no crash
    f = dg.stamp_tool_assisted(_finding(), TOOLED_PLAN, "iac")
    assert f["tool_assisted"] is False


def test_stamp_is_idempotent_and_pure():
    original = _finding()
    f1 = dg.stamp_tool_assisted(original, TOOLED_PLAN, "sca")
    f2 = dg.stamp_tool_assisted(f1, TOOLED_PLAN, "sca")
    assert f1["tool_assisted"] == f2["tool_assisted"] is True
    assert original["tool_assisted"] is False  # input not mutated


# --- cap_floor_confidence -------------------------------------------------
def test_floor_finding_confidence_is_capped():
    f = dg.cap_floor_confidence(_finding(confidence=0.95, tool_assisted=False))
    assert f["confidence"] == dg.FLOOR_CONFIDENCE_CAP


def test_tool_assisted_finding_keeps_high_confidence():
    f = dg.cap_floor_confidence(_finding(confidence=0.95, tool_assisted=True))
    assert f["confidence"] == 0.95


def test_finalize_floor_path_caps_and_marks_false():
    f = dg.finalize(_finding(confidence=0.99), FLOOR_PLAN, "sca")
    assert f["tool_assisted"] is False
    assert f["confidence"] == dg.FLOOR_CONFIDENCE_CAP


def test_finalize_tool_path_marks_true_and_keeps_confidence():
    f = dg.finalize(_finding(confidence=0.6), TOOLED_PLAN, "sca")
    assert f["tool_assisted"] is True
    assert f["confidence"] == 0.6


# === T-3.6 — cross-capability integration: drive the REAL pipeline ========
def _which_none(_name):
    return None


def _which_only(*present):
    s = set(present)
    return lambda n: f"/usr/bin/{n}" if n in s else None


_TRIVY_VULN = {"VulnerabilityID": "CVE-2018-1000656", "PkgName": "flask",
               "InstalledVersion": "0.12.2", "FixedVersion": "0.12.3",
               "Severity": "HIGH", "Title": "DoS via JSON"}
_TRIVY_DOC = {"Results": [{"Target": "requirements.txt", "Type": "pip",
                           "Vulnerabilities": [_TRIVY_VULN]}]}


def test_floor_only(tmp_path):
    """All capabilities absent → the pipeline completes, records tools_unavailable, caps
    confidence, marks tool_assisted:false, and never raises (ADR-003)."""
    (tmp_path / "pyproject.toml").write_text("[project]\n")
    plan = dt.build_scan_plan(tmp_path, _which_none).to_dict()

    # SCA degrades to a structurally-valid empty result that records the gap (never blocks).
    deps = nd.degraded_result(plan, scanned_langs=["python"])
    assert vf.validate(deps) == []
    assert deps["summary"]["tools_unavailable"]            # non-empty
    assert "sca" in deps["summary"]["tools_unavailable"]

    # A secrets finding on the floor is tool_assisted:false with capped confidence.
    secret = rd.to_finding("config.py", 3, "aws-key", "AKIAEXAMPLE0000000000", scan_plan=plan)
    assert secret["tool_assisted"] is False
    assert secret["confidence"] <= dg.FLOOR_CONFIDENCE_CAP

    # And a tool finding stamped against the floor plan is also false (no tool backed it).
    f = dg.finalize({"category": "supply-chain", "confidence": 0.99, "tool_assisted": True},
                    plan, "sca")
    assert f["tool_assisted"] is False


def test_tool_present(tmp_path):
    """With SCA + secrets tools injected present, findings flip to tool_assisted:true and the
    capability leaves tools_unavailable."""
    (tmp_path / "requirements.txt").write_text("flask==0.12.2\n")
    plan = dt.build_scan_plan(tmp_path, _which_only("trivy", "gitleaks")).to_dict()

    deps = nd.normalize(_TRIVY_DOC, scan_plan=plan)
    assert vf.validate(deps) == []
    assert deps["findings"][0]["tool_assisted"] is True
    assert "sca" not in deps["summary"]["tools_unavailable"]
    assert "trivy" in deps["summary"]["tools_used"]

    secret = rd.to_finding("config.py", 3, "aws-key", "AKIAEXAMPLE0000000000", scan_plan=plan)
    assert secret["tool_assisted"] is True
    assert "secrets" not in dg.summary_tools(plan)["tools_unavailable"]


def test_pipeline_never_raises_on_missing_tools(tmp_path):
    """Smoke: a fully-degraded run of every normalizer path completes without exception."""
    (tmp_path / "go.mod").write_text("module x\n")
    plan = dt.build_scan_plan(tmp_path, _which_none).to_dict()
    nd.degraded_result(plan)
    nd.normalize(_TRIVY_DOC, scan_plan=plan)          # tool output but plan degraded → false stamps
    rd.to_finding("a.py", 1, "k", "s", scan_plan=plan)
    # reaching here == no exception path blocked on a missing tool
