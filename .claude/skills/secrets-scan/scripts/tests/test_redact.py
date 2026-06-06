"""T-3.2 — secrets redaction tests.

The load-bearing guarantee: no secret value ever appears in a finding (the whole serialized
finding is searched for the raw value). Plus fingerprint stability, edge cases, schema validity.

Run: `uv run --with jsonschema --with pytest pytest .claude/skills/secrets-scan/scripts/tests/`
"""
from __future__ import annotations

import json

import detect_tools as dt
import redact as rd
import validate_findings as vf

SECRET = "AKIA1234567890ABCDEF"  # looks like an AWS key; never appears in output


# --- redact never leaks the value ----------------------------------------
def test_redact_does_not_contain_any_secret_substring():
    out = rd.redact(SECRET)
    assert SECRET not in out
    # not even a 4-char prefix of the secret leaks
    assert SECRET[:4] not in out
    assert out.startswith("<redacted:sha256=")


def test_redact_empty_and_short():
    assert rd.redact("") == "<redacted:empty>"
    assert "ab" not in rd.redact("ab")  # short secret still fully masked


def test_fingerprint_is_stable_and_one_way():
    assert rd.fingerprint(SECRET) == rd.fingerprint(SECRET)
    assert rd.fingerprint("other") != rd.fingerprint(SECRET)
    assert SECRET not in rd.fingerprint(SECRET)


# --- to_finding builds a clean, schema-valid finding ----------------------
def _doc(finding):
    return {
        "summary": {"scanned_langs": [], "tools_used": [], "tools_unavailable": ["secrets"],
                    "scoring_standard": "CVSS4.0",
                    "counts": {"high": 1 if finding["severity"] == "HIGH" else 0,
                               "medium": 0, "low": 0}},
        "findings": [finding],
    }


def test_built_finding_excludes_the_secret_value():
    f = rd.to_finding("config/app.py", 42, "aws-access-key", SECRET)
    blob = json.dumps(f)
    assert SECRET not in blob
    assert SECRET[:6] not in blob          # no prefix leak either
    assert rd.fingerprint(SECRET) in blob  # but it is correlatable


def test_built_finding_is_schema_valid():
    f = rd.to_finding("config/app.py", 42, "aws-access-key", SECRET)
    assert vf.validate(_doc(f)) == []


def test_finding_carries_only_location_and_rule():
    f = rd.to_finding("config/app.py", 42, "aws-access-key", SECRET)
    assert f["first_link"] == "config/app.py:42"
    assert f["kb_refs"] == ["aws-access-key"]
    assert f["category"] == "hardcoded-secret"


# --- degradation stamping -------------------------------------------------
def test_tool_assisted_false_on_floor(tmp_path):
    plan = dt.build_scan_plan(tmp_path, lambda _n: None).to_dict()  # no gitleaks/trufflehog
    f = rd.to_finding("a.py", 1, "generic-key", SECRET, scan_plan=plan)
    assert f["tool_assisted"] is False


def test_tool_assisted_true_when_secrets_tool_present(tmp_path):
    plan = dt.build_scan_plan(
        tmp_path, lambda n: "/usr/bin/gitleaks" if n == "gitleaks" else None).to_dict()
    f = rd.to_finding("a.py", 1, "generic-key", SECRET, scan_plan=plan)
    assert f["tool_assisted"] is True
