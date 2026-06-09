"""T-3.3 — deps-scan Trivy normalizer tests.

Drives the real 13-vuln capture in docs/research/poc-trivy-sca/trivy-output.json through
normalize() and asserts the output is schema-valid; plus dedup, severity mapping, recommendations,
the clean case, and the degraded (no-SCA-tool) path.

Run: `uv run --with jsonschema --with pytest pytest .claude/skills/deps-scan/scripts/tests/`
"""
from __future__ import annotations

import json
import pathlib

import pytest

import detect_tools as dt
import normalize_deps as nd
import validate_findings as vf

def _repo_root(start: pathlib.Path) -> pathlib.Path:
    """Repo root = the dir containing .git. Location-independent so the fixture path
    survives the plugin migration (.claude/skills → plugins/white-hacker/skills) and any
    future move — replaces a brittle hardcoded parents[N] count."""
    for cand in (start.resolve(), *start.resolve().parents):
        if (cand / ".git").exists():
            return cand
    return start.resolve().parents[-1]


_FIXTURE = _repo_root(pathlib.Path(__file__)) / "docs" / "research" / "poc-trivy-sca" / "trivy-output.json"

# wh-8lx: this whole module drives a repo fixture (docs/research/poc-trivy-sca) found via a `.git`
# repo-root walk. In a minimal package checkout / the Docker sandbox the repo isn't present, so SKIP
# (not fail) when the fixture is absent — the suite stays portable. Present → runs as before.
pytestmark = pytest.mark.skipif(
    not _FIXTURE.exists(),
    reason=f"repo fixture absent ({_FIXTURE}) — e.g. the minimal deps-scan sandbox image",
)


def _trivy_doc() -> dict:
    return json.loads(_FIXTURE.read_text())


def _empty_which(_name):
    return None


# --- the headline: real fixture → schema-valid findings -------------------
def test_fixture_normalizes_to_13_schema_valid_findings():
    doc = nd.normalize(_trivy_doc())
    assert len(doc["findings"]) == 13
    assert vf.validate(doc) == []          # schema-valid
    assert vf.duplicate_ids(doc) == []     # unique ids


def test_counts_match_findings():
    doc = nd.normalize(_trivy_doc())
    c = doc["summary"]["counts"]
    assert c["high"] + c["medium"] + c["low"] == len(doc["findings"])
    assert doc["summary"]["scanned_langs"] == ["python"]  # Type pip


def test_all_findings_are_supply_chain_candidates():
    doc = nd.normalize(_trivy_doc())
    for f in doc["findings"]:
        assert f["category"] == "supply-chain"
        assert f["severity"] in {"HIGH", "MEDIUM", "LOW"}
        assert f["access_required"] == "unknown"       # triage derives reachability
        assert f["verified"] == "static_review_only"
        assert f["kb_refs"] and f["kb_refs"][0].startswith("CVE-")


def test_recommendation_includes_fixed_version_when_present():
    doc = nd.normalize(_trivy_doc())
    upgrades = [f for f in doc["findings"] if "Upgrade" in f["recommendation"]]
    assert upgrades, "fixture has fixable CVEs → at least one Upgrade recommendation"


# --- synthetic edge cases -------------------------------------------------
def _doc(*vulns, target="requirements.txt", typ="pip"):
    return {"Results": [{"Target": target, "Type": typ, "Vulnerabilities": list(vulns)}]}


def test_severity_critical_maps_to_high():
    doc = nd.normalize(_doc({"VulnerabilityID": "CVE-X", "PkgName": "p",
                             "InstalledVersion": "1", "Severity": "CRITICAL"}))
    assert doc["findings"][0]["severity"] == "HIGH"


def test_missing_fixed_version_recommendation():
    doc = nd.normalize(_doc({"VulnerabilityID": "CVE-Y", "PkgName": "p",
                             "InstalledVersion": "1", "Severity": "HIGH"}))  # no FixedVersion
    assert "No fixed version" in doc["findings"][0]["recommendation"]


def test_dedup_by_pkg_and_cve():
    v = {"VulnerabilityID": "CVE-DUP", "PkgName": "p", "InstalledVersion": "1", "Severity": "LOW"}
    doc = nd.normalize(_doc(v, dict(v)))  # same (pkg, cve) twice
    assert len(doc["findings"]) == 1


def test_clean_result_yields_zero_findings():
    doc = nd.normalize({"Results": [{"Target": "go.mod", "Type": "gomod", "Vulnerabilities": []}]})
    assert doc["findings"] == []
    assert vf.validate(doc) == []


# --- degradation: no SCA tool on PATH -------------------------------------
def test_tool_assisted_true_when_scan_plan_binds_sca(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n")
    plan = dt.build_scan_plan(tmp_path, lambda n: "/usr/bin/trivy" if n == "trivy" else None).to_dict()
    doc = nd.normalize(_doc({"VulnerabilityID": "CVE-Z", "PkgName": "p",
                             "InstalledVersion": "1", "Severity": "HIGH"}), scan_plan=plan)
    assert doc["findings"][0]["tool_assisted"] is True
    assert "sca" not in doc["summary"]["tools_unavailable"]


def test_degraded_result_when_no_sca_tool(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\n")
    plan = dt.build_scan_plan(tmp_path, _empty_which).to_dict()  # nothing installed
    doc = nd.degraded_result(plan, scanned_langs=["python"])
    assert vf.validate(doc) == []                       # never blocks; valid result
    assert "sca" in doc["summary"]["tools_unavailable"]
    assert doc["findings"] == []
