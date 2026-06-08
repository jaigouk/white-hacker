"""Tests for `correction_records` — normalize kind=='correction' rows (wh-0aq, si-10 borrowing #4).

Row shape is the authoritative one emitted by the capture hook
`plugins/white-hacker/hooks/capture_hooks.py:48-57`:
    {"kind": "correction", "tool": <tool_name>, "target": <redacted cmd/path>,
     "session": <id>, "correction": <redacted user prompt>}
Mapping -> {"scene": target, "wrong": tool, "correct": correction}, each falling back to "".
Append-only, deterministic, no LLM. Rule 9 — pin BOTH the right value AND the wrong value.

Run: uv run --project plugins/white-hacker/skills/sec-learn/scripts pytest \
        plugins/white-hacker/skills/sec-learn/scripts/tests/test_correction_records.py -q
"""
from __future__ import annotations

import harvest as h


def test_correction_row_becomes_scene_wrong_correct():
    rows = [
        {
            "kind": "correction",
            "tool": "Bash",
            "target": "grep -rn secret src/",
            "session": "s1",
            "correction": "F-003 is a false positive, it's auto-escaped",
        }
    ]
    recs = h.correction_records(rows)
    assert recs == [
        {
            "scene": "grep -rn secret src/",
            "wrong": "Bash",
            "correct": "F-003 is a false positive, it's auto-escaped",
        }
    ]
    # The record carries exactly the three normalized keys (no leakage of raw fields).
    assert set(recs[0]) == {"scene", "wrong", "correct"}
    assert "kind" not in recs[0] and "session" not in recs[0]


def test_non_correction_rows_are_ignored():
    rows = [
        {"kind": "trace", "tool": "Read", "target": "a.py", "session": "s1"},
        {"kind": "failed_exploit", "error": "blocked", "session": "s2"},
        {
            "kind": "correction",
            "tool": "Grep",
            "target": "config.py",
            "session": "s3",
            "correction": "that path is test fixture, ignore",
        },
    ]
    recs = h.correction_records(rows)
    # Only the single correction row is emitted...
    assert len(recs) == 1
    assert recs[0]["correct"] == "that path is test fixture, ignore"
    # ...the trace/failed rows did NOT leak in.
    assert all(r.get("wrong") != "Read" for r in recs)
    assert "blocked" not in {r["correct"] for r in recs}


def test_missing_fields_fall_back_to_empty_string():
    # The minimal correction row the harvest test exercises (no tool/target).
    rows = [{"kind": "correction", "correction": "F-3 is a false positive", "session": "s1"}]
    recs = h.correction_records(rows)
    assert recs == [{"scene": "", "wrong": "", "correct": "F-3 is a false positive"}]
    # Absent fields become "" (never None, never KeyError).
    assert recs[0]["scene"] == "" and recs[0]["scene"] is not None
    assert recs[0]["wrong"] == ""


def test_explicit_none_tool_coerces_to_empty_string():
    # The capture hook (capture_hooks.py:50) writes "tool": null on a UserPromptSubmit
    # correction (no tool_name); the record must coerce that to "", never carry None.
    rows = [
        {
            "kind": "correction",
            "tool": None,
            "target": None,
            "session": "s1",
            "correction": "FP: that regex match is in a comment",
        }
    ]
    recs = h.correction_records(rows)
    assert recs == [
        {"scene": "", "wrong": "", "correct": "FP: that regex match is in a comment"}
    ]
    # Explicit None never leaks through.
    assert recs[0]["wrong"] is not None and recs[0]["scene"] is not None


def test_order_is_preserved_append_only():
    rows = [
        {"kind": "correction", "correction": "first", "session": "s1"},
        {"kind": "trace", "session": "s1"},
        {"kind": "correction", "correction": "second", "session": "s2"},
    ]
    recs = h.correction_records(rows)
    assert [r["correct"] for r in recs] == ["first", "second"]
    # Source order preserved, not reordered.
    assert recs[0]["correct"] == "first" and recs[1]["correct"] == "second"
