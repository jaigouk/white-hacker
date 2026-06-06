"""Tests for staleness_check (T-8.2, TDD).

Run: uv run --with pyyaml --with pytest pytest plugins/white-hacker/skills/ai-attack-kb/scripts/tests/test_staleness_check.py
"""
from __future__ import annotations

import staleness_check as sc
from _kb_entries import read_entries


def _entry(d, fname, eid, review_by):
    (d / fname).write_text(
        f"---\nid: {eid}\ntitle: t\ntechnique_class: prompt-injection\nstatus: active\n"
        f"review_by: {review_by}\nxref: ['LLM01:2025']\n---\nbody-content\n")


def test_past_review_by_is_stale(tmp_path):
    _entry(tmp_path, "old.md", "AISEC-PROMPT-INJECTION-001", "2020-01-01")
    assert len(sc.stale_entries(read_entries(tmp_path), "2026-06-06")) == 1
    assert sc.main([str(tmp_path), "--today", "2026-06-06"]) == 1


def test_future_review_by_not_stale(tmp_path):
    _entry(tmp_path, "fresh.md", "AISEC-PROMPT-INJECTION-001", "2099-01-01")
    assert sc.stale_entries(read_entries(tmp_path), "2026-06-06") == []
    assert sc.main([str(tmp_path), "--today", "2026-06-06"]) == 0


def test_archive_moves_file_preserving_content(tmp_path):
    ref = tmp_path / "reference"; ref.mkdir()
    _entry(ref, "old.md", "AISEC-PROMPT-INJECTION-001", "2020-01-01")
    original = (ref / "old.md").read_text()
    rc = sc.main([str(ref), "--today", "2026-06-06", "--archive"])
    assert rc == 1
    assert not (ref / "old.md").exists(), "stale file should be moved out of reference/"
    archived = tmp_path / "archive" / "old.md"
    assert archived.exists(), "stale file should be archived (never deleted)"
    assert archived.read_text() == original, "archived content must be preserved verbatim"


def test_main_usage_error():
    assert sc.main([]) == 2
