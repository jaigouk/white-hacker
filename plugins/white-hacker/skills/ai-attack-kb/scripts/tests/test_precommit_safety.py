"""Tests for the 10-gate pre-commit safety checklist (T-9.4, TDD).

Run: uv run --with pytest pytest plugins/white-hacker/skills/ai-attack-kb/scripts/tests/test_precommit_safety.py

>= 1 test per gate; identity-preservation always blocks; a clean change passes all 10; rejections
append to rejected.md.
"""
from __future__ import annotations

import precommit_safety as ps


def _clean(tmp_path, **over):
    c = {
        "id": "AISEC-PROMPT-INJECTION-009",
        "cwd": str(tmp_path),
        "paths": [".claude/skills/ai-attack-kb/reference/prompt-injection.md"],
        "lint_passed": True, "validate_passed": True, "references_one_level": True,
        "sourced": True, "dedup_passed": True, "self_critique_passed": True,
        "seen_sessions": 3, "gate_verdict": "KEEP", "branch": "feature/kb-update", "autocommit": False,
    }
    c.update(over)
    return c


def _failed_gates(change):
    return {g for g, _ in ps.failures(change)}


def test_clean_change_passes_all_10(tmp_path):
    assert ps.passed(_clean(tmp_path))
    assert len(ps.check(_clean(tmp_path))) == 10


def test_schema_caps_gate(tmp_path):
    assert "schema_caps" in _failed_gates(_clean(tmp_path, lint_passed=False))


def test_source_linked_gate(tmp_path):
    assert "source_linked" in _failed_gates(_clean(tmp_path, sourced=False))


def test_dedup_gate(tmp_path):
    assert "dedup_passed" in _failed_gates(_clean(tmp_path, dedup_passed=False))


def test_identity_preservation_always_blocks(tmp_path):
    for p in ("CLAUDE.md", ".claude/rules/x.md", ".claude/agents/white-hacker.md"):
        f = _failed_gates(_clean(tmp_path, paths=[p]))
        assert "identity_preserved" in f


def test_confined_gate(tmp_path):
    assert "confined" in _failed_gates(_clean(tmp_path, paths=["src/app.py"]))
    assert "confined" in _failed_gates(_clean(tmp_path, paths=["evals/corpus/cases/c1/label.json"]))


def test_self_critique_gate(tmp_path):
    assert "self_critique" in _failed_gates(_clean(tmp_path, self_critique_passed=False))


def test_promotion_eligibility_gate(tmp_path):
    assert "promotion_eligible" in _failed_gates(_clean(tmp_path, seen_sessions=2))


def test_regression_gate(tmp_path):
    assert "regression_gate" in _failed_gates(_clean(tmp_path, gate_verdict="REVERT"))


def test_feature_branch_gate(tmp_path):
    assert "feature_branch" in _failed_gates(_clean(tmp_path, branch="main"))
    assert "feature_branch" in _failed_gates(_clean(tmp_path, autocommit=True))


def test_references_one_level_gate(tmp_path):
    assert "references_one_level" in _failed_gates(_clean(tmp_path, references_one_level=False))


def test_enforce_appends_to_rejected(tmp_path):
    rej = tmp_path / "rejected.md"
    rej.write_text("# rejected\n")
    assert ps.enforce(_clean(tmp_path, gate_verdict="REVERT"), rej) is False
    assert "BLOCKED" in rej.read_text() and "AISEC-PROMPT-INJECTION-009" in rej.read_text()


def test_enforce_clean_does_not_append(tmp_path):
    rej = tmp_path / "rejected.md"
    rej.write_text("# rejected\n")
    assert ps.enforce(_clean(tmp_path), rej) is True
    assert rej.read_text() == "# rejected\n"
