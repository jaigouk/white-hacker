"""Tests for sec-policy's hygiene advisory (T-11.5).

When a repo has NO security policy, the agent surfaces an INFORMATIONAL
supply-chain-hygiene ADVISORY — never a vuln finding (see exclusion-rules.md rule 19).
The advisory therefore carries NO `severity` / NO `cvss` / NO `owasp` keys, so it can
never be mistaken for a `VULN-FINDINGS.json` / `TRIAGE.json` entry, and its message is
FACTUAL (not imperative) to stay injection-safe.

Run: uv run --project plugins/white-hacker/skills/sec-policy/scripts --with pytest \
       pytest plugins/white-hacker/skills/sec-policy/scripts/tests -q
"""
from __future__ import annotations

import hygiene_advisory as ha

# Keys that would mark something as a scored VULN-FINDINGS / TRIAGE entry. A hygiene
# advisory must carry NONE of these.
_FINDING_KEYS = ("severity", "cvss", "owasp")


def _absent_gap() -> dict:
    """A gap report shaped like parse_policy's output when no SECURITY.md exists."""
    return {
        "present": False,
        "path": None,
        "sections": {},
        "missing_sections": [],
        "reporting_channel": "none",
        "scorecard": {"contact": False, "free_form_text": False, "specific": False, "score": 0},
        "security_txt": {"present": False, "expired": None},
        "injection_suspected": False,
    }


def _present_gap() -> dict:
    """A gap report where a SECURITY.md IS present."""
    return {
        "present": True,
        "path": "SECURITY.md",
        "sections": {"reporting": True},
        "missing_sections": [],
        "reporting_channel": "email",
        "scorecard": {"contact": True, "free_form_text": True, "specific": True, "score": 10},
        "security_txt": {"present": False, "expired": None},
        "injection_suspected": False,
    }


# --- absent policy → advisory -----------------------------------------------


def test_absent_policy_returns_advisory_dict():
    adv = ha.policy_hygiene_advisory(_absent_gap())
    assert adv is not None
    assert isinstance(adv, dict)


def test_advisory_has_hygiene_kind_and_category():
    adv = ha.policy_hygiene_advisory(_absent_gap())
    assert adv["kind"] == "hygiene-advisory"
    assert adv["category"] == "supply-chain-hygiene"


def test_advisory_id_is_set():
    adv = ha.policy_hygiene_advisory(_absent_gap())
    assert adv["id"] == "WH-HYGIENE-SECPOLICY"
    assert adv["id"]  # non-empty


def test_advisory_has_no_severity_key():
    adv = ha.policy_hygiene_advisory(_absent_gap())
    assert "severity" not in adv


def test_advisory_has_no_cvss_key():
    adv = ha.policy_hygiene_advisory(_absent_gap())
    assert "cvss" not in adv


def test_advisory_is_not_a_finding_no_scored_keys():
    """It must never be mistaken for a VULN-FINDINGS / TRIAGE entry."""
    adv = ha.policy_hygiene_advisory(_absent_gap())
    for key in _FINDING_KEYS:
        assert key not in adv, f"advisory must not carry finding key {key!r}"


def test_advisory_message_is_factual():
    adv = ha.policy_hygiene_advisory(_absent_gap())
    assert ha.is_factual(adv["message"]) is True


def test_advisory_message_mentions_security_md_and_patches():
    adv = ha.policy_hygiene_advisory(_absent_gap())
    msg = adv["message"]
    assert "SECURITY.md" in msg
    assert "PATCHES/" in msg


def test_advisory_has_references_list():
    adv = ha.policy_hygiene_advisory(_absent_gap())
    assert isinstance(adv["references"], list)
    assert adv["references"]  # at least one reference


# --- present policy → no advisory -------------------------------------------


def test_present_policy_returns_none():
    assert ha.policy_hygiene_advisory(_present_gap()) is None


def test_present_policy_with_minimal_gap_still_none():
    """Even a sparse present gap report (only present=True) yields no advisory."""
    assert ha.policy_hygiene_advisory({"present": True}) is None


# --- is_factual helper edges ------------------------------------------------


def test_is_factual_rejects_imperative():
    assert ha.is_factual("Always add a SECURITY.md.") is False
    assert ha.is_factual("Do not skip this.") is False


def test_is_factual_accepts_statement():
    assert ha.is_factual("The repo has no security policy.") is True


def test_is_factual_empty_is_vacuously_true():
    assert ha.is_factual("") is True
    assert ha.is_factual("   ") is True
