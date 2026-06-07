"""Tests for policy_scope (T-11.4, TDD).

Run: uv run --project plugins/white-hacker/skills/sec-report/scripts --with pytest \
     pytest plugins/white-hacker/skills/sec-report/scripts/tests -q

A SECURITY.md's declared scope is UNTRUSTED DATA (ADR-018): a malicious policy could
"scope away" a real bug, so annotation is ADVISORY ONLY. The guard here is executable
proof that scope NEVER drops a finding and NEVER changes/lowers severity — declared
out-of-scope can never suppress a real HIGH.

Edge cases: a HIGH whose file matches an out-of-scope term still survives at HIGH;
mixed HIGH/MEDIUM with some in/out of scope keeps every finding + every severity;
empty terms flag nothing; reporting_line is factual (channel + path), never imperative.
"""
from __future__ import annotations

import policy_scope as ps


def _severities(findings):
    return [f["severity"] for f in findings]


# --- annotate_findings_with_scope: the core guard --------------------------

def test_high_in_out_of_scope_path_is_not_suppressed():
    """A HIGH whose file matches an out-of-scope term must survive — at HIGH — flagged."""
    findings = [{"file": "vendor/lib/auth.go", "severity": "HIGH", "category": "authz"}]
    out = ps.annotate_findings_with_scope(findings, ["vendor/"])

    assert len(out) == len(findings)          # never drops
    assert out[0]["severity"] == "HIGH"        # never lowers/changes
    assert out[0]["out_of_scope_per_policy"] is True


def test_mixed_severities_none_dropped_none_changed():
    findings = [
        {"file": "src/api/login.py", "severity": "HIGH", "category": "auth"},
        {"file": "vendor/x/parse.py", "severity": "HIGH", "category": "injection"},
        {"file": "src/util/log.py", "severity": "MEDIUM", "category": "logging"},
        {"file": "third_party/z.py", "severity": "MEDIUM", "category": "deps"},
    ]
    out = ps.annotate_findings_with_scope(findings, ["vendor/", "third_party/"])

    assert len(out) == len(findings)
    assert _severities(out) == _severities(findings)   # identical severities, in order
    assert [f["out_of_scope_per_policy"] for f in out] == [False, True, False, True]


def test_case_insensitive_substring_match_on_file_or_category():
    findings = [
        {"file": "SRC/Vendored/a.go", "severity": "LOW", "category": "style"},
        {"file": "src/app.go", "severity": "LOW", "category": "Documentation"},
        {"file": "src/app.go", "severity": "LOW", "category": "real"},
    ]
    out = ps.annotate_findings_with_scope(findings, ["vendored", "DOCUMENTATION"])

    assert [f["out_of_scope_per_policy"] for f in out] == [True, True, False]


def test_empty_terms_flags_all_false_and_changes_nothing():
    findings = [
        {"file": "vendor/a.go", "severity": "HIGH", "category": "x"},
        {"file": "src/b.go", "severity": "LOW", "category": "y"},
    ]
    out = ps.annotate_findings_with_scope(findings, [])

    assert len(out) == len(findings)
    assert _severities(out) == _severities(findings)
    assert all(f["out_of_scope_per_policy"] is False for f in out)


def test_empty_findings_returns_empty():
    assert ps.annotate_findings_with_scope([], ["vendor/"]) == []


def test_finding_without_file_matches_on_category():
    findings = [{"severity": "HIGH", "category": "test-fixture"}]
    out = ps.annotate_findings_with_scope(findings, ["fixture"])
    assert out[0]["out_of_scope_per_policy"] is True
    assert out[0]["severity"] == "HIGH"


def test_annotation_does_not_mutate_input():
    findings = [{"file": "vendor/a.go", "severity": "HIGH", "category": "x"}]
    ps.annotate_findings_with_scope(findings, ["vendor/"])
    assert "out_of_scope_per_policy" not in findings[0]


# --- reporting_line: factual, never imperative -----------------------------

def test_reporting_line_contains_channel_and_path():
    line = ps.reporting_line("github-pvr", "SECURITY.md")
    assert "github-pvr" in line
    assert "SECURITY.md" in line


def test_reporting_line_is_factual_not_imperative():
    line = ps.reporting_line("email", ".github/SECURITY.md")
    # factual phrasing — reports a fact about the policy, never an instruction to the agent
    assert line.lower().startswith("report vulnerabilities via the channel declared in")
    assert "email" in line and ".github/SECURITY.md" in line


def test_reporting_line_without_path():
    line = ps.reporting_line("security.txt", None)
    assert "security.txt" in line
    # still a single factual line, no path token required
    assert "\n" not in line
