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


# --- DATA-path skip (wh-hxt.6; ADR-026 §3): the watchlist DATA file is gated by gate_data_edit's
# content-bound DATA verdict, NOT by this KB eval-J verdict. gate_kb_edit excludes DATA paths so a
# DATA write is not double-gated. Pin BOTH ways (Policy 9): a DATA write is NOT KB-gated even with a
# KEEP eval-J verdict; a sibling KB markdown write in the SAME segment IS still KB-gated. -------

DATA_REL = "plugins/white-hacker/skills/_shared/reference/known-compromised.osv.json"


def test_data_path_is_not_kb_gated_even_without_verdict(tmp_path):
    # the watchlist DATA file must fall OUT of this KB gate (gate_data_edit governs it). With no
    # eval-J verdict on disk a KB path is blocked; the DATA path must instead be allowed-through here.
    assert gk.decide(_write(tmp_path, DATA_REL))[0]


def test_data_path_is_not_kb_gated_even_with_keep_verdict(tmp_path):
    # the critical direction: a stray eval-J KEEP must NOT become the merit that admits a DATA write
    # through gate_kb_edit (false-merit merge). gate_kb_edit returns not-gated; gate_data_edit decides.
    _verdict(tmp_path, "KEEP")
    assert gk.decide(_write(tmp_path, DATA_REL))[0]


def test_kb_markdown_sibling_in_same_segment_is_still_kb_gated(tmp_path):
    # the prose checklist/registry markdown in /_shared/reference/ is STILL KB-gated (only the named
    # DATA file is skipped) — REVERT eval-J verdict blocks it.
    _verdict(tmp_path, "REVERT")
    assert not gk.decide(_write(tmp_path, "plugins/white-hacker/skills/_shared/reference/core-checklist.md"))[0]


def test_data_path_sibling_tmp_is_kb_gated_not_skipped(tmp_path):
    # the skip is a suffix match, not a substring: `…known-compromised.osv.json.tmp` is NOT the DATA
    # file, so it remains KB-gated (no eval-J verdict -> blocked) — the skip must not over-match.
    assert not gk.decide(_write(tmp_path, DATA_REL + ".tmp"))[0]


def test_data_paths_set_is_exactly_the_watchlist_suffix():
    assert gk.DATA_PATHS == ("/_shared/reference/known-compromised.osv.json",)


# --- HIGH-1: path-normalization bypass. _is_gated_path matched RAW paths while the OS write
# (realpath) collapses `//`, `/./`, trailing-slash — a double-slash DATA variant must STILL be
# DATA-skipped (not KB-gated), and a double-slash KB variant must STILL be KB-gated, or poison
# escapes every gate. Pin BOTH directions. -----------------------------------------------------

def test_double_slash_data_path_is_still_data_skipped(tmp_path):
    # even with a KEEP eval-J verdict, the // DATA variant must NOT be admitted-by-merit here — it
    # is DATA-skipped (gate_data_edit governs it). gate_kb_edit returns not-gated -> allow-through.
    poison = "plugins/white-hacker/skills/_shared//reference/known-compromised.osv.json"
    assert not gk._is_gated_path(poison)       # DATA-skipped despite //
    _verdict(tmp_path, "REVERT")
    assert gk.decide(_write(tmp_path, poison))[0]  # not KB-gated (a REVERT would block a KB path)


def test_dot_segment_data_path_is_still_data_skipped(tmp_path):
    poison = "plugins/white-hacker/skills/_shared/reference/./known-compromised.osv.json"
    assert not gk._is_gated_path(poison)


def test_double_slash_kb_markdown_is_still_kb_gated(tmp_path):
    # the normpath fix must keep KB paths gated: a // variant of a real KB markdown is STILL gated.
    poison = "plugins/white-hacker/skills/_shared//reference/core-checklist.md"
    assert gk._is_gated_path(poison)
    assert not gk.decide(_write(tmp_path, poison))[0]   # no verdict -> blocked


def test_double_slash_kb_reference_dir_is_still_kb_gated(tmp_path):
    poison = "plugins/white-hacker/skills//ai-attack-kb/reference/x.md"
    assert gk._is_gated_path(poison)
    assert not gk.decide(_write(tmp_path, poison))[0]


def test_double_slash_data_tmp_sibling_stays_kb_gated(tmp_path):
    # the `.tmp` sibling (even with //) is NOT the DATA file -> NOT skipped -> stays KB-gated.
    sibling = "plugins/white-hacker/skills/_shared//reference/known-compromised.osv.json.tmp"
    assert gk._is_gated_path(sibling)
    assert not gk.decide(_write(tmp_path, sibling))[0]  # no verdict -> blocked


def test_double_slash_bash_redirect_to_kb_still_gated(tmp_path):
    # Bash channel: a // redirect to a KB markdown is still gated (normpath in _is_gated_path).
    ev = {"tool_name": "Bash",
          "tool_input": {"command": "echo x > plugins/white-hacker/skills//ai-attack-kb/reference/y.md"},
          "cwd": str(tmp_path)}
    assert not gk.decide(ev)[0]
