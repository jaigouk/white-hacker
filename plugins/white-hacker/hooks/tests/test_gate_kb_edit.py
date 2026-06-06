"""Tests for the KB-edit gate hook (T-9.3, TDD).

Run: uv run --with pytest pytest plugins/white-hacker/hooks/tests/test_gate_kb_edit.py
"""
from __future__ import annotations

import json

import gate_kb_edit as gk


def _verdict(tmp_path, v):
    (tmp_path / "evals").mkdir(exist_ok=True)
    (tmp_path / "evals" / "gate-verdict.json").write_text(json.dumps({"verdict": v}))


def _write(tmp_path, path):
    return {"tool_name": "Write", "tool_input": {"file_path": path}, "cwd": str(tmp_path)}


def test_allows_kb_edit_on_keep(tmp_path):
    _verdict(tmp_path, "KEEP")
    assert gk.decide(_write(tmp_path, ".claude/skills/ai-attack-kb/reference/x.md"))[0]


def test_blocks_kb_edit_on_revert(tmp_path):
    _verdict(tmp_path, "REVERT")
    assert not gk.decide(_write(tmp_path, ".claude/skills/ai-attack-kb/reference/x.md"))[0]


def test_blocks_kb_edit_without_verdict(tmp_path):
    assert not gk.decide(_write(tmp_path, ".claude/skills/ai-attack-kb/reference/x.md"))[0]


def test_plugin_layout_kb_path_gated_same_way(tmp_path):  # T-10.3: migration robustness
    # the plugin-relative KB path is gated identically to the .claude/ path
    p = "plugins/white-hacker/skills/ai-attack-kb/reference/x.md"
    assert not gk.decide(_write(tmp_path, p))[0]  # no verdict → blocked
    _verdict(tmp_path, "REVERT")
    assert not gk.decide(_write(tmp_path, p))[0]  # REVERT → blocked
    _verdict(tmp_path, "KEEP")
    assert gk.decide(_write(tmp_path, p))[0]      # KEEP → allowed


def test_blocks_checklist_edit_on_revert(tmp_path):
    _verdict(tmp_path, "REVERT")
    assert not gk.decide(_write(tmp_path, ".claude/skills/_shared/reference/core-checklist.md"))[0]


def test_allows_non_kb_edit(tmp_path):
    # a non-KB write is out of this hook's scope (other hooks confine it)
    assert gk.decide(_write(tmp_path, "PATCHES/x.diff"))[0]


def test_blocks_bash_redirection_to_kb_without_keep(tmp_path):
    ev = {"tool_name": "Bash",
          "tool_input": {"command": "echo x > .claude/skills/ai-attack-kb/reference/y.md"},
          "cwd": str(tmp_path)}
    assert not gk.decide(ev)[0]


def test_main_exit_codes(monkeypatch, tmp_path):
    import io
    _verdict(tmp_path, "REVERT")
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_write(tmp_path, ".claude/skills/ai-attack-kb/reference/x.md"))))
    assert gk.main() == 2
    _verdict(tmp_path, "KEEP")
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_write(tmp_path, ".claude/skills/ai-attack-kb/reference/x.md"))))
    assert gk.main() == 0
