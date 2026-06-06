"""Tests for the team-mode review gate (T-6.5, TDD).

Run: uv run --with pytest pytest plugins/white-hacker/hooks/tests/test_gate_review.py

The gate blocks until TRIAGE.json exists, then surfaces ONLY summary counts + the report path.
"""
from __future__ import annotations

import io
import json

import gate_review as gr

TRIAGE = {
    "summary": {
        "scanned_langs": ["python"], "tools_used": [], "tools_unavailable": ["sast"],
        "scoring_standard": "CVSS4.0", "counts": {"high": 1, "medium": 0, "low": 0},
    },
    "findings": [],
}


def test_blocks_when_no_triage(tmp_path):
    ok, msg = gr.review_status(str(tmp_path))
    assert ok is False
    assert "not complete" in msg


def test_allows_when_triage_present(tmp_path):
    (tmp_path / "TRIAGE.json").write_text(json.dumps(TRIAGE))
    ok, msg = gr.review_status(str(tmp_path))
    assert ok is True
    assert "counts=" in msg


def test_surfaces_report_path_when_rendered(tmp_path):
    (tmp_path / "TRIAGE.json").write_text(json.dumps(TRIAGE))
    (tmp_path / "SECURITY-REPORT.md").write_text("# report")
    ok, msg = gr.review_status(str(tmp_path))
    assert ok is True and "SECURITY-REPORT.md" in msg


def test_blocks_on_unreadable_triage(tmp_path):
    (tmp_path / "TRIAGE.json").write_text("{not json")
    ok, _ = gr.review_status(str(tmp_path))
    assert ok is False


def test_main_blocks_exit_2(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"cwd": str(tmp_path)})))
    assert gr.main() == 2


def test_main_allows_exit_0(monkeypatch, tmp_path):
    (tmp_path / "TRIAGE.json").write_text(json.dumps(TRIAGE))
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"cwd": str(tmp_path)})))
    assert gr.main() == 0
