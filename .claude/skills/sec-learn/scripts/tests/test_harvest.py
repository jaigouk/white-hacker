"""Tests for the sec-learn trace harvester (T-8.5, TDD).

Run: uv run --with pytest pytest .claude/skills/sec-learn/scripts/tests/test_harvest.py
"""
from __future__ import annotations

import json

import harvest as h


def _write(d, name, rows):
    (d / name).write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def test_collates_corrections_and_failures(tmp_path):
    _write(tmp_path, "findings-2026-06.jsonl", [
        {"kind": "trace", "tool": "Bash", "session": "s1"},
        {"kind": "correction", "correction": "F-3 is a false positive", "session": "s1"},
        {"kind": "failed_exploit", "error": "blocked", "session": "s2"},
    ])
    out = h.harvest(tmp_path)
    assert out["total_rows"] == 3
    assert len(out["corrections"]) == 1 and "false positive" in out["corrections"][0]["correction"]
    assert len(out["failed_exploits"]) == 1
    assert out["by_session"] == {"s1": 2, "s2": 1}


def test_merges_multiple_months(tmp_path):
    _write(tmp_path, "findings-2026-05.jsonl", [{"kind": "correction", "session": "a"}])
    _write(tmp_path, "findings-2026-06.jsonl", [{"kind": "correction", "session": "b"}])
    out = h.harvest(tmp_path)
    assert len(out["corrections"]) == 2 and set(out["sessions"]) == {"a", "b"}


def test_skips_malformed_lines(tmp_path):
    (tmp_path / "findings-2026-06.jsonl").write_text('{"kind":"trace","session":"s"}\nnot json\n\n')
    assert h.harvest(tmp_path)["total_rows"] == 1


def test_empty_dir(tmp_path):
    assert h.harvest(tmp_path)["total_rows"] == 0


def test_main_usage(capsys):
    assert h.main([]) == 2
