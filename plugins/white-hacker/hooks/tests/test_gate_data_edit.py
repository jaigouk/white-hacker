"""Tests for the Gate-2 DATA write-lane hook (wh-hxt.6, TDD; ADR-026 §3).

Run: uv run --project plugins/white-hacker/hooks --with pytest \
        pytest plugins/white-hacker/hooks/tests/test_gate_data_edit.py -q

`gate_data_edit.py` is the CONSUMER of the content-bound, one-shot `evals/data-verdict.json`
minted by `validate_watchlist.py` (wh-hxt.5). A write to a named DATA path (the watchlist file)
is admitted ONLY when the verdict is KEEP, `path` matches the write target, AND `sha256` matches a
FRESH recompute of the proposed write bytes — then the verdict is consumed (deleted) so it cannot
be replayed. Every invariant pins BOTH directions (Policy 9): the right verdict admits AND a
wrong/absent/stale one blocks.
"""
from __future__ import annotations

import hashlib
import io
import json

import pytest

import gate_data_edit as gd

# The ONLY DATA path initially in scope (QA-#2 — no sidecar placeholder; wh-hxt.4 adds its own).
DATA_REL = "plugins/white-hacker/skills/_shared/reference/known-compromised.osv.json"
KB_REL = "plugins/white-hacker/skills/ai-attack-kb/reference/x.md"


def _sha(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _data_verdict(tmp_path, *, path, content=None, sha256=None, verdict="KEEP"):
    """Write evals/data-verdict.json shaped like validate_watchlist.mint_verdict (sha256 of the
    EXACT validated bytes). Pass `content` to bind the hash to those bytes, or `sha256` directly."""
    (tmp_path / "evals").mkdir(exist_ok=True)
    digest = sha256 if sha256 is not None else _sha(content or "")
    (tmp_path / "evals" / "data-verdict.json").write_text(
        json.dumps({"verdict": verdict, "path": path, "sha256": digest, "validated": "2026-06-11T00:00:00+00:00"})
    )


def _kb_verdict(tmp_path, v="KEEP"):
    """The eval-J keep-or-revert verdict (a DIFFERENT verdict kind) — must NOT admit a DATA write."""
    (tmp_path / "evals").mkdir(exist_ok=True)
    (tmp_path / "evals" / "gate-verdict.json").write_text(json.dumps({"verdict": v}))


def _write(tmp_path, path, content):
    return {"tool_name": "Write", "tool_input": {"file_path": path, "content": content},
            "cwd": str(tmp_path)}


def _edit(tmp_path, path, old, new, *, on_disk):
    """An Edit event; seeds the on-disk file with `on_disk` so the hook can reconstruct post-edit
    bytes by applying old_string->new_string against what is actually on disk."""
    fp = tmp_path / path
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(on_disk)
    return {"tool_name": "Edit",
            "tool_input": {"file_path": path, "old_string": old, "new_string": new},
            "cwd": str(tmp_path)}


def _verdict_exists(tmp_path) -> bool:
    return (tmp_path / "evals" / "data-verdict.json").exists()


# --- DATA_SEGMENTS scope (QA-#2) ---------------------------------------------------------------

def test_data_segments_is_exactly_the_watchlist_path():
    # initially ONLY the watchlist path; the wh-hxt.4 sidecar path is ABSENT (adds itself later).
    assert gd.DATA_SEGMENTS == ("/_shared/reference/known-compromised.osv.json",)
    assert len(gd.DATA_SEGMENTS) == 1
    assert not any("tool-registry" in s for s in gd.DATA_SEGMENTS)


# --- Happy path (both directions) --------------------------------------------------------------

def test_data_write_with_no_verdict_is_blocked(tmp_path):
    assert not gd.decide(_write(tmp_path, DATA_REL, '{"id": "x"}'))[0]


def test_data_write_keep_path_and_content_match_is_allowed(tmp_path):
    content = '{"id": "GHSA-aaaa-bbbb-cccc"}'
    _data_verdict(tmp_path, path=DATA_REL, content=content)
    assert gd.decide(_write(tmp_path, DATA_REL, content))[0]


# --- No eval-J reuse (false-merit closure) -----------------------------------------------------

def test_data_write_with_only_eval_j_keep_is_blocked(tmp_path):
    # a DATA write earning ONLY the corpus-scored KB KEEP must NOT be admitted (false-merit merge).
    _kb_verdict(tmp_path, "KEEP")
    assert not gd.decide(_write(tmp_path, DATA_REL, '{"id": "x"}'))[0]


# --- Content binding (SEC-Q2, both directions) -------------------------------------------------

def test_content_binding_verdict_for_a_blocks_write_of_b(tmp_path):
    content_a = '{"id": "A"}'
    content_b = '{"id": "B-poisoned"}'
    _data_verdict(tmp_path, path=DATA_REL, content=content_a)
    assert not gd.decide(_write(tmp_path, DATA_REL, content_b))[0]  # B != bound sha → blocked
    assert gd.decide(_write(tmp_path, DATA_REL, content_a))[0]      # A == bound sha → allowed


# --- Edit post-edit-byte binding (both directions) ---------------------------------------------

def test_edit_post_edit_bytes_match_is_allowed(tmp_path):
    on_disk = '{"id": "OLD", "k": 1}'
    post = '{"id": "NEW", "k": 1}'
    _data_verdict(tmp_path, path=DATA_REL, content=post)  # verdict binds the POST-edit bytes
    ev = _edit(tmp_path, DATA_REL, '{"id": "OLD"', '{"id": "NEW"', on_disk=on_disk)
    assert gd.decide(ev)[0]


def test_edit_post_edit_bytes_mismatch_is_blocked(tmp_path):
    on_disk = '{"id": "OLD", "k": 1}'
    # verdict binds some OTHER content, not the actual post-edit bytes -> blocked
    _data_verdict(tmp_path, path=DATA_REL, content='{"id": "SOMETHING-ELSE"}')
    ev = _edit(tmp_path, DATA_REL, '{"id": "OLD"', '{"id": "NEW"', on_disk=on_disk)
    assert not gd.decide(ev)[0]


def test_edit_recompute_uses_on_disk_file_not_old_string_only(tmp_path):
    # the post-edit bytes are (on_disk with old->new), not just new_string; bind to the real result.
    on_disk = 'prefix\nTARGET\nsuffix\n'
    post = 'prefix\nREPLACED\nsuffix\n'
    _data_verdict(tmp_path, path=DATA_REL, content=post)
    ev = _edit(tmp_path, DATA_REL, "TARGET", "REPLACED", on_disk=on_disk)
    assert gd.decide(ev)[0]
    # binding ONLY to new_string ("REPLACED") would be the wrong hash -> a sanity guard
    assert _sha(post) != _sha("REPLACED")


# --- One-shot / no replay ----------------------------------------------------------------------

def test_one_shot_consume_blocks_replay(tmp_path):
    content = '{"id": "once"}'
    _data_verdict(tmp_path, path=DATA_REL, content=content)
    assert gd.decide(_write(tmp_path, DATA_REL, content))[0]   # first write admitted
    assert not _verdict_exists(tmp_path)                       # verdict consumed (deleted)
    assert not gd.decide(_write(tmp_path, DATA_REL, content))[0]  # replay with same verdict blocked


def test_verdict_not_consumed_on_a_blocked_write(tmp_path):
    # a mismatching write must NOT consume the verdict (only a SUCCESSFUL admit consumes).
    _data_verdict(tmp_path, path=DATA_REL, content='{"id": "A"}')
    assert not gd.decide(_write(tmp_path, DATA_REL, '{"id": "B"}'))[0]
    assert _verdict_exists(tmp_path)


# --- Fail-closed ------------------------------------------------------------------------------

def test_missing_verdict_blocks(tmp_path):
    assert not gd.decide(_write(tmp_path, DATA_REL, '{"id": "x"}'))[0]


def test_empty_verdict_file_blocks(tmp_path):
    (tmp_path / "evals").mkdir()
    (tmp_path / "evals" / "data-verdict.json").write_text("")
    assert not gd.decide(_write(tmp_path, DATA_REL, '{"id": "x"}'))[0]


def test_unparseable_verdict_file_blocks(tmp_path):
    (tmp_path / "evals").mkdir()
    (tmp_path / "evals" / "data-verdict.json").write_text("{not json")
    assert not gd.decide(_write(tmp_path, DATA_REL, '{"id": "x"}'))[0]


def test_non_keep_verdict_blocks(tmp_path):
    content = '{"id": "x"}'
    _data_verdict(tmp_path, path=DATA_REL, content=content, verdict="REVERT")
    assert not gd.decide(_write(tmp_path, DATA_REL, content))[0]


def test_path_mismatch_blocks(tmp_path):
    content = '{"id": "x"}'
    # verdict validated some OTHER file; this write targets the watchlist -> path mismatch -> blocked
    _data_verdict(tmp_path, path="some/other/file.json", content=content)
    assert not gd.decide(_write(tmp_path, DATA_REL, content))[0]


# --- Suffix not substring ----------------------------------------------------------------------

def test_sibling_tmp_path_is_not_treated_as_the_data_path(tmp_path):
    # a `…known-compromised.osv.json.tmp` sibling must NOT match the DATA suffix -> out of scope ->
    # allowed by THIS hook (it is not a DATA path; other hooks confine it).
    sibling = DATA_REL + ".tmp"
    assert gd.decide(_write(tmp_path, sibling, '{"id": "x"}'))[0]  # not gated by gate_data_edit
    # and a verdict for the real path must not retroactively gate the sibling either
    _data_verdict(tmp_path, path=sibling, content='{"id": "x"}')
    assert gd.decide(_write(tmp_path, sibling, '{"id": "x"}'))[0]


def test_non_data_path_is_allowed(tmp_path):
    # a non-DATA write is out of this hook's scope (other hooks confine it).
    assert gd.decide(_write(tmp_path, "PATCHES/x.diff", "stuff"))[0]


def test_absolute_data_path_is_gated(tmp_path):
    # the agent may pass an absolute file_path; the suffix still matches -> still gated.
    abs_path = str(tmp_path / DATA_REL)
    assert not gd.decide(_write(tmp_path, abs_path, '{"id": "x"}'))[0]  # no verdict -> blocked


# --- main() exit codes -------------------------------------------------------------------------

def test_main_blocked_returns_2(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_write(tmp_path, DATA_REL, '{"id": "x"}'))))
    assert gd.main() == 2  # no verdict -> blocked


def test_main_allowed_returns_0(monkeypatch, tmp_path):
    content = '{"id": "ok"}'
    _data_verdict(tmp_path, path=DATA_REL, content=content)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_write(tmp_path, DATA_REL, content))))
    assert gd.main() == 0


def test_main_unparseable_stdin_returns_0(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("{not json"))
    assert gd.main() == 0


def test_main_empty_stdin_returns_0(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert gd.main() == 0


def test_main_blocked_writes_reason_to_stderr(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_write(tmp_path, DATA_REL, '{"id": "x"}'))))
    rc = gd.main()
    assert rc == 2
    assert "[gate_data_edit] BLOCKED" in capsys.readouterr().err


# --- error handling (missing cwd / tool_input / content -> fail-closed, never a 0 traceback) ----

def test_missing_content_on_data_write_fails_closed(tmp_path):
    content = '{"id": "x"}'
    _data_verdict(tmp_path, path=DATA_REL, content=content)
    ev = {"tool_name": "Write", "tool_input": {"file_path": DATA_REL}, "cwd": str(tmp_path)}
    assert not gd.decide(ev)[0]  # no content to hash -> cannot bind -> blocked


def test_missing_cwd_on_data_write_fails_closed(tmp_path):
    ev = {"tool_name": "Write", "tool_input": {"file_path": DATA_REL, "content": "{}"}}
    # no cwd -> verdict cannot be located under it -> fail-closed block (never a traceback)
    assert not gd.decide(ev)[0]


def _bash(tmp_path, command):
    return {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(tmp_path)}


# === HIGH-1: path-normalization bypass (defeats the whole gate) =================================
# The OS write + confine_self_writes (realpath) collapse `//`, `/./`, trailing `/`; the scope match
# MUST normpath FIRST or a double-slash variant slips out-of-scope and lands poison on the canonical
# inode with NO verdict. Pin BOTH: every path FORM of the DATA file is GATED (no verdict -> blocked),
# AND a content-bound KEEP on the canonical form still admits a canonical write.

def test_double_slash_data_path_is_gated(tmp_path):
    poison = "plugins/white-hacker/skills/_shared//reference/known-compromised.osv.json"
    assert gd._is_data_path(poison)                       # in scope despite //
    assert not gd.decide(_write(tmp_path, poison, '{"id": "poison"}'))[0]  # no verdict -> blocked


def test_dot_segment_data_path_is_gated(tmp_path):
    poison = "plugins/white-hacker/skills/_shared/reference/./known-compromised.osv.json"
    assert gd._is_data_path(poison)
    assert not gd.decide(_write(tmp_path, poison, '{"id": "poison"}'))[0]


def test_trailing_dotdot_data_path_is_gated(tmp_path):
    # a `reference/sub/../known-compromised.osv.json` form normpaths onto the DATA file.
    poison = "plugins/white-hacker/skills/_shared/reference/sub/../known-compromised.osv.json"
    assert gd._is_data_path(poison)
    assert not gd.decide(_write(tmp_path, poison, '{"id": "poison"}'))[0]


def test_canonical_data_path_still_admits_after_normpath(tmp_path):
    # the normpath fix must NOT break the happy path: a canonical write under a bound KEEP admits.
    content = '{"id": "canonical"}'
    _data_verdict(tmp_path, path=DATA_REL, content=content)
    assert gd.decide(_write(tmp_path, DATA_REL, content))[0]


def test_double_slash_sibling_tmp_is_not_gated(tmp_path):
    # normpath must not over-match: `…known-compromised.osv.json.tmp` (even with //) is NOT the DATA
    # file -> out of this hook's scope (allowed here; other hooks confine it).
    sibling = "plugins/white-hacker/skills/_shared//reference/known-compromised.osv.json.tmp"
    assert not gd._is_data_path(sibling)
    assert gd.decide(_write(tmp_path, sibling, '{"id": "x"}'))[0]


# === HIGH-2: the Bash channel must be covered (the DATA-skip removed gate_kb_edit's old coverage) =
# A shell `>`/cp/mv/tee/dd to the watchlist is NEVER a sanctioned mint -> fail-closed block, with no
# verdict and with only an eval-J KEEP. The `.tmp` sibling via Bash stays out of DATA scope.

def test_bash_redirect_to_watchlist_no_verdict_is_blocked(tmp_path):
    cmd = f"echo '{{\"id\": \"poison\"}}' > {DATA_REL}"
    assert not gd.decide(_bash(tmp_path, cmd))[0]


def test_bash_redirect_to_watchlist_with_only_eval_j_keep_is_blocked(tmp_path):
    _kb_verdict(tmp_path, "KEEP")  # false-merit: a KB KEEP must not admit a shell write to DATA
    cmd = f"echo '{{\"id\": \"poison\"}}' > {DATA_REL}"
    assert not gd.decide(_bash(tmp_path, cmd))[0]


def test_bash_redirect_to_watchlist_even_with_matching_data_verdict_is_blocked(tmp_path):
    # a redirect is NEVER content-bound/sanctioned even if a real DATA verdict is present.
    content = '{"id": "x"}'
    _data_verdict(tmp_path, path=DATA_REL, content=content)
    cmd = f"echo '{content}' > {DATA_REL}"
    assert not gd.decide(_bash(tmp_path, cmd))[0]


def test_bash_double_slash_redirect_to_watchlist_is_blocked(tmp_path):
    poison = "plugins/white-hacker/skills/_shared//reference/known-compromised.osv.json"
    assert not gd.decide(_bash(tmp_path, f"echo x > {poison}"))[0]


def test_bash_append_redirect_to_watchlist_is_blocked(tmp_path):
    assert not gd.decide(_bash(tmp_path, f"echo x >> {DATA_REL}"))[0]


def test_bash_cp_to_watchlist_is_blocked(tmp_path):
    assert not gd.decide(_bash(tmp_path, f"cp /tmp/poison.json {DATA_REL}"))[0]


def test_bash_tee_to_watchlist_is_blocked(tmp_path):
    assert not gd.decide(_bash(tmp_path, f"echo x | tee {DATA_REL}"))[0]


def test_bash_redirect_to_tmp_sibling_is_out_of_data_scope(tmp_path):
    # the `.tmp` sibling via Bash is NOT a DATA path -> this hook allows it (gate_kb_edit still gates).
    assert gd.decide(_bash(tmp_path, f"echo x > {DATA_REL}.tmp"))[0]


def test_bash_redirect_to_unrelated_path_is_allowed(tmp_path):
    assert gd.decide(_bash(tmp_path, "echo x > PATCHES/y.diff"))[0]


def test_bash_blocked_reason_is_clear(tmp_path):
    ok, reason = gd.decide(_bash(tmp_path, f"echo x > {DATA_REL}"))
    assert not ok
    assert "watchlist" in reason.lower() and "shell" in reason.lower()


# === Channel coverage: plain redirect (`>`/`>>`) + Write + Edit ================================
# SCOPE-HONEST (Policy 9): this exercises the channels the heuristic DOES cover — plain `>`/`>>`
# redirects (incl. // and /./ path forms), Write, and Edit. It does NOT claim "every channel": the
# Bash tripwire has a KNOWN residual (`>|` noclobber-override, `xargs` launder) made VISIBLE by the
# two strict-xfail tests below — that gap is tracked in wh-hxt.15 (structural token-match hardening,
# a wh-k6l blocker) and mooted pre-wh-k6l by confine realpath + the ADR-012 human-PR gate.

def test_plain_redirect_write_and_edit_channels_blocked(tmp_path):
    forms = [
        DATA_REL,
        "plugins/white-hacker/skills/_shared//reference/known-compromised.osv.json",
        "plugins/white-hacker/skills/_shared/reference/./known-compromised.osv.json",
        str(tmp_path / DATA_REL),
    ]
    for form in forms:
        assert not gd.decide(_write(tmp_path, form, '{"id": "p"}'))[0], f"Write admitted {form}"
        assert not gd.decide(_bash(tmp_path, f"echo p > {form}"))[0], f"Bash admitted {form}"
    # Edit channel: seed the canonical file, attempt an edit with no verdict -> blocked.
    ev = _edit(tmp_path, DATA_REL, "OLD", "NEW", on_disk="OLD")
    assert not gd.decide(ev)[0]


# Known Bash-heuristic residuals (ADR-016 tripwire family) made VISIBLE, not masked. Each asserts the
# gate SHOULD block; it currently does NOT, so strict-xfail. When wh-hxt.15 lands the structural
# token-match these flip to a FAILING xpass (strict=True), forcing whoever does wh-hxt.15 to un-xfail
# them. Mooted pre-wh-k6l by confine realpath + the ADR-012 human-PR gate; tracked as a wh-k6l blocker.
_RESIDUAL_REASON = (
    "Bash heuristic tripwire residual — >|/xargs; structural fix tracked in wh-hxt.15; "
    "mooted pre-wh-k6l by confine realpath + ADR-012 human-PR gate"
)


@pytest.mark.xfail(reason=_RESIDUAL_REASON, strict=True)
def test_pipe_noclobber_redirect_evades_heuristic(tmp_path):
    # `>|` (noclobber override) is not matched by _REDIR_RE -> target not extracted -> SHOULD block.
    assert not gd.decide(_bash(tmp_path, f"echo POISON >| {DATA_REL}"))[0]


@pytest.mark.xfail(reason=_RESIDUAL_REASON, strict=True)
def test_xargs_launder_evades_heuristic(tmp_path):
    # the watchlist arrives as an xargs-substituted arg ({}), not a literal target -> SHOULD block.
    cmd = f"echo {DATA_REL} | xargs -I{{}} cp /tmp/p {{}}"
    assert not gd.decide(_bash(tmp_path, cmd))[0]


# === MED-3: fail-open on a malformed verdict ===================================================
# A valid-JSON-but-non-dict verdict made `.get` raise -> main exited 1 (uncaught) -> reads as ALLOW.

def test_non_dict_verdict_list_blocks(tmp_path):
    (tmp_path / "evals").mkdir()
    (tmp_path / "evals" / "data-verdict.json").write_text(json.dumps(["x"]))
    assert not gd.decide(_write(tmp_path, DATA_REL, '{"id": "x"}'))[0]


def test_non_dict_verdict_string_blocks(tmp_path):
    (tmp_path / "evals").mkdir()
    (tmp_path / "evals" / "data-verdict.json").write_text(json.dumps("x"))
    assert not gd.decide(_write(tmp_path, DATA_REL, '{"id": "x"}'))[0]


def test_non_dict_verdict_int_blocks(tmp_path):
    (tmp_path / "evals").mkdir()
    (tmp_path / "evals" / "data-verdict.json").write_text("42")
    assert not gd.decide(_write(tmp_path, DATA_REL, '{"id": "x"}'))[0]


def test_main_non_dict_verdict_returns_2_not_1(monkeypatch, tmp_path):
    (tmp_path / "evals").mkdir()
    (tmp_path / "evals" / "data-verdict.json").write_text(json.dumps(["x"]))
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_write(tmp_path, DATA_REL, '{"id": "x"}'))))
    assert gd.main() == 2  # NOT 1 (exit 1 would read as ALLOW under the hook protocol)


def test_main_fails_closed_on_unexpected_exception(monkeypatch, tmp_path):
    # force decide() to raise; main() must catch it and fail CLOSED at exit 2 (never an exit-1 leak).
    def boom(_event):
        raise RuntimeError("synthetic")
    monkeypatch.setattr(gd, "decide", boom)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_write(tmp_path, DATA_REL, '{"id": "x"}'))))
    assert gd.main() == 2
