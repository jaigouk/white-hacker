"""Tests for the CI gate (T-6.2, TDD).

Run: uv run --with jsonschema --with pytest pytest plugins/white-hacker/skills/sec-report/scripts/tests/

Edge cases: passes with no HIGH; fails with HIGH; medium-only passes by default; threshold
override (max-high / max-medium); malformed JSON and non-schema JSON rejected (exit 2); the
real Phase-1 deduped fixture (3 HIGH) fails the gate.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import ci_gate as cg

VALID = {
    "summary": {
        "scanned_langs": ["go"],
        "tools_used": [],
        "tools_unavailable": ["sast"],
        "scoring_standard": "CVSS4.0",
        "counts": {"high": 0, "medium": 0, "low": 0},
    },
    "findings": [],
}

def _repo_root(start: Path) -> Path:
    """Repo root = the dir containing .git. Location-independent so the fixture path
    survives the plugin migration (.claude/skills → plugins/white-hacker/skills) and any
    future move — replaces a brittle hardcoded parents[N] count."""
    for cand in (start.resolve(), *start.resolve().parents):
        if (cand / ".git").exists():
            return cand
    return start.resolve().parents[-1]


FIXTURE = _repo_root(Path(__file__)) / "docs" / "research" / "poc-floor-review" / "run" / "triage.deduped.json"


def _write(tmp_path, doc, name="d.json"):
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return str(p)


# --- gate() unit ----------------------------------------------------------

def test_gate_passes_when_no_high():
    assert cg.gate({"high": 0, "medium": 0, "low": 0}) == []


def test_gate_fails_when_high():
    assert cg.gate({"high": 3, "medium": 0, "low": 0}) != []


def test_gate_medium_only_passes_by_default():
    assert cg.gate({"high": 0, "medium": 5, "low": 9}) == []


def test_gate_max_high_override():
    assert cg.gate({"high": 2, "medium": 0, "low": 0}, max_high=2) == []
    assert cg.gate({"high": 3, "medium": 0, "low": 0}, max_high=2) != []


def test_gate_max_medium_override():
    assert cg.gate({"high": 0, "medium": 4, "low": 0}, max_medium=3) != []


# --- main() CLI -----------------------------------------------------------

def test_main_passes_clean(tmp_path):
    assert cg.main([_write(tmp_path, VALID)]) == 0


def test_main_fails_on_high(tmp_path):
    d = copy.deepcopy(VALID)
    d["summary"]["counts"]["high"] = 2
    assert cg.main([_write(tmp_path, d)]) == 1


def test_main_threshold_override(tmp_path):
    d = copy.deepcopy(VALID)
    d["summary"]["counts"]["high"] = 2
    f = _write(tmp_path, d)
    assert cg.main([f, "--max-high", "2"]) == 0
    assert cg.main([f, "--max-high", "1"]) == 1


def test_main_malformed_json_rejected(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    assert cg.main([str(p)]) == 2


def test_main_non_schema_json_rejected(tmp_path):
    # valid JSON but missing required summary -> schema fails -> exit 2 (not a silent pass)
    assert cg.main([_write(tmp_path, {"findings": []})]) == 2


def test_main_no_args_is_usage_error():
    assert cg.main([]) == 2


def test_real_deduped_fixture_fails_gate():
    # the Phase-1 fixture has 3 HIGH findings -> the gate must fail it. It lives under docs/research/
    # (dev/sandbox only) and is NOT vendored into a target project, where _repo_root resolves to the
    # target's own .git — so SKIP (not error) when absent, mirroring deps-scan test_supply_chain.py:378.
    # Keeps the vendored suite portable (wh-7gh).
    if not FIXTURE.exists():
        import pytest

        pytest.skip(f"dev/sandbox-only fixture absent ({FIXTURE}) — e.g. a vendored target copy")
    assert cg.main([str(FIXTURE)]) == 1
