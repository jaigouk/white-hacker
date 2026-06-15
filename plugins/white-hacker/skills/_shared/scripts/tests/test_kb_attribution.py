"""Tests for KB-entry attribution helpers (wh-5ox.10, TDD).

`mitre_from_xref` splits a KB `xref` list into the MITRE subset (ATT&CK + ATLAS), dropping
every non-MITRE id and stripping the ` [primary-sourced: <url>]` tag. `apply_kb_attribution`
copies those onto a finding and (optionally) propagates a `disputed` claim, capping confidence
while the dispute is unresolved. Every invariant is pinned BOTH ways (Policy 9).

Run: uv run --project plugins/white-hacker/skills/_shared/scripts --with pytest \
       pytest plugins/white-hacker/skills/_shared/scripts/tests -q
"""
from __future__ import annotations

import kb_attribution as ka

# The verbatim xref from ai-attack-kb/reference/supply-chain-1.md:21 (the matched entry).
SUPPLY_CHAIN_XREF = [
    "LLM03:2025",
    "AML.T0010 [primary-sourced: https://atlas.mitre.org/techniques/AML.T0010]",
    "T1195.002 [primary-sourced: https://attack.mitre.org/techniques/T1195/002/]",
    "T1552.005 [primary-sourced: https://attack.mitre.org/techniques/T1552/005/]",
]


# --- mitre_from_xref: split MITRE subset, drop the rest, strip the tag --------
def test_mitre_from_xref_locked_ac():
    # The locked acceptance example from the contract.
    assert ka.mitre_from_xref([
        "LLM03:2025",
        "AML.T0010 [primary-sourced: https://atlas.mitre.org/techniques/AML.T0010]",
        "T1195.002 [primary-sourced: https://attack.mitre.org/techniques/T1195/002/]",
    ]) == {"att_ck": ["T1195.002"], "atlas": ["AML.T0010"]}


def test_mitre_from_xref_full_supply_chain_entry():
    assert ka.mitre_from_xref(SUPPLY_CHAIN_XREF) == {
        "att_ck": ["T1195.002", "T1552.005"],   # order-stable
        "atlas": ["AML.T0010"],
    }


def test_mitre_from_xref_drops_non_mitre_taxonomies():
    # LLM/MCP/ASI/CVE/AISEC ids are NOT MITRE -> dropped from both buckets.
    out = ka.mitre_from_xref([
        "LLM03:2025", "MCP01", "ASI04", "CVE-2025-1234", "AISEC-SUPPLY-CHAIN-001",
    ])
    assert out == {"att_ck": [], "atlas": []}      # == nothing survives
    assert "CVE-2025-1234" not in out["att_ck"]    # != a CVE leaking into att_ck


def test_mitre_from_xref_strips_primary_sourced_tag():
    # The bare id (no provenance tag) is what lands in the bucket.
    out = ka.mitre_from_xref(["T1195 [primary-sourced: https://x]"])
    assert out["att_ck"] == ["T1195"]              # == the bare id
    assert out["att_ck"] != ["T1195 [primary-sourced: https://x]"]  # != the tagged raw


def test_mitre_from_xref_bare_attck_subtechnique_forms():
    # Both T#### and T####.### are ATT&CK; AML.* is ATLAS.
    assert ka.mitre_from_xref(["T1195", "T1195.002", "AML.T0010"]) == {
        "att_ck": ["T1195", "T1195.002"], "atlas": ["AML.T0010"],
    }


def test_mitre_from_xref_empty_and_none():
    assert ka.mitre_from_xref([]) == {"att_ck": [], "atlas": []}
    assert ka.mitre_from_xref(None) == {"att_ck": [], "atlas": []}


# --- apply_kb_attribution: copy MITRE onto a finding; propagate dispute --------
def _finding(**kw):
    base = {"id": "F-001", "confidence": 0.7}
    base.update(kw)
    return base


def test_apply_attribution_sets_att_ck_and_atlas():
    out = ka.apply_kb_attribution(_finding(), xref=SUPPLY_CHAIN_XREF)
    assert out["att_ck"] == ["T1195.002", "T1552.005"]
    assert out["atlas"] == ["AML.T0010"]
    assert "disputed" not in out                   # no dispute given -> none attached


def test_apply_attribution_no_kb_match_is_empty():
    out = ka.apply_kb_attribution(_finding(), xref=[], disputed=None)
    assert out["att_ck"] == [] and out["atlas"] == []


def test_apply_attribution_does_not_mutate_input():
    f = _finding()
    ka.apply_kb_attribution(f, xref=SUPPLY_CHAIN_XREF)
    assert "att_ck" not in f                        # original untouched (returns a copy)


def test_apply_attribution_unresolved_dispute_caps_confidence():
    disp = {"claim": "X is exploitable", "dispute_source": "vendor", "status": "unresolved"}
    out = ka.apply_kb_attribution(_finding(confidence=0.9), xref=[], disputed=disp)
    assert out["confidence"] == 0.5                 # == capped at the unresolved cap
    assert out["confidence"] != 0.9                 # != the original (cap applied)
    assert out["disputed"] == disp


def test_apply_attribution_unresolved_does_not_raise_already_low_confidence():
    disp = {"claim": "c", "dispute_source": "s", "status": "unresolved"}
    out = ka.apply_kb_attribution(_finding(confidence=0.3), xref=[], disputed=disp)
    assert out["confidence"] == 0.3                 # min() never RAISES a low confidence


def test_apply_attribution_resolved_dispute_keeps_confidence():
    # confirmed / refuted are settled -> NO cap (only 'unresolved' caps).
    for status in ("confirmed", "refuted"):
        disp = {"claim": "c", "dispute_source": "s", "status": status}
        out = ka.apply_kb_attribution(_finding(confidence=0.9), xref=[], disputed=disp)
        assert out["confidence"] == 0.9            # unchanged
        assert out["disputed"]["status"] == status


def test_apply_attribution_idempotent():
    once = ka.apply_kb_attribution(_finding(), xref=SUPPLY_CHAIN_XREF)
    twice = ka.apply_kb_attribution(once, xref=SUPPLY_CHAIN_XREF)
    assert twice == once                           # re-attributing the same xref is a fixpoint
