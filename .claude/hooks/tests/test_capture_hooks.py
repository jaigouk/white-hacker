"""Tests for the deterministic capture hooks (T-8.3, TDD).

Run: uv run --with pytest pytest .claude/hooks/tests/test_capture_hooks.py

One case per hook mode + the secret-redaction negative test.
"""
from __future__ import annotations

import io
import json

import capture_hooks as ch


def _ev(tmp_path, **kw):
    e = {"cwd": str(tmp_path), "_month": "2026-06", "session_id": "s1"}
    e.update(kw)
    return e


def _lines(tmp_path):
    f = tmp_path / "evals" / "traces" / "findings-2026-06.jsonl"
    return [json.loads(l) for l in f.read_text().splitlines()]


def test_trace_appends_jsonl(tmp_path):
    ch.append_trace(_ev(tmp_path, tool_name="Bash", tool_input={"command": "grep -rn foo src/"}), "trace")
    rows = _lines(tmp_path)
    assert rows[0]["kind"] == "trace" and rows[0]["tool"] == "Bash" and "grep" in rows[0]["target"]


def test_failed_exploit_appends_with_error(tmp_path):
    ch.append_trace(_ev(tmp_path, tool_name="Bash", tool_input={"command": "curl x"},
                        tool_response="connection refused"), "failed_exploit")
    rows = _lines(tmp_path)
    assert rows[0]["kind"] == "failed_exploit" and "refused" in rows[0]["error"]


def test_correction_appends(tmp_path):
    ch.append_trace(_ev(tmp_path, prompt="that F-003 is a false positive, it's auto-escaped"), "correction")
    rows = _lines(tmp_path)
    assert rows[0]["kind"] == "correction" and "false positive" in rows[0]["correction"]


def test_append_is_additive(tmp_path):
    ch.append_trace(_ev(tmp_path, tool_name="Read", tool_input={"file_path": "a.py"}), "trace")
    ch.append_trace(_ev(tmp_path, tool_name="Read", tool_input={"file_path": "b.py"}), "trace")
    assert len(_lines(tmp_path)) == 2


def test_cve_digest_emitted_when_present(tmp_path):
    (tmp_path / "evals").mkdir()
    (tmp_path / "evals" / "cve-digest.txt").write_text("CVE-2026-9999 new RCE in libfoo")
    assert "CVE-2026-9999" in ch.cve_digest(_ev(tmp_path))


def test_cve_digest_empty_when_absent(tmp_path):
    assert ch.cve_digest(_ev(tmp_path)) == ""


def test_secret_value_is_redacted(tmp_path):
    secret = "sk-live-abcd1234efgh5678ijkl9012"
    ch.append_trace(_ev(tmp_path, tool_name="Bash",
                        tool_input={"command": f"export TOKEN={secret}"}), "trace")
    raw = (tmp_path / "evals" / "traces" / "findings-2026-06.jsonl").read_text()
    assert secret not in raw and "[REDACTED]" in raw


def test_main_trace_via_stdin(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(
        _ev(tmp_path, tool_name="Bash", tool_input={"command": "ls"}))))
    assert ch.main(["trace"]) == 0
    assert _lines(tmp_path)[0]["tool"] == "Bash"


def test_main_nudge_emits(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    assert ch.main(["learnings_nudge"]) == 0
    assert "sec-learn" in capsys.readouterr().out
