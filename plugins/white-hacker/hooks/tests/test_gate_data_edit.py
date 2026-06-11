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
# redirects (incl. // and /./ path forms), Write, and Edit. wh-hxt.15 additionally closes the
# `>|`/xargs/python-c/ed write-channel residuals via a structural token-scan (the next section).

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


# === wh-hxt.15: structural token-scan closes the Bash write-channel residuals ===================
# A Bash command that WRITES (a `>`/`>>`/`>|`/`&>` redirect or a write/launder verb) or LAUNDERS
# through an interpreter (`python -c`, `eval`, `xargs`, `ed`, …) has NO benign reason to NAME the
# watchlist DATA path -> fail-closed BLOCK. The first two cases below were strict-xfail residuals in
# wh-hxt.6 (`>|` noclobber-override, `xargs` arg-laundering); wh-hxt.15 un-xfails them so they assert
# BLOCK and PASS. The scan is SUBSTRING (catches a path inside a quoted `-c "open('…','w')"`) but
# SCOPED to write/interpreter verbs so a bare `cat <watchlist>` READ is NOT blocked (Policy 9, both
# directions). The remaining ADR-016 residual — a bare-basename relative write from inside the
# reference dir (agent cwd is normally repo root) — is documented in the hook header, out of scope.

def test_pipe_noclobber_redirect_is_blocked(tmp_path):
    # `>|` (noclobber override): _SEPARATOR_RE no longer splits the bare `|` after `>`, _REDIR_RE now
    # accepts `>|`, and the structural scan is a second net. SHOULD block (was a wh-hxt.6 xfail).
    assert not gd.decide(_bash(tmp_path, f"echo POISON >| {DATA_REL}"))[0]


def test_xargs_launder_is_blocked(tmp_path):
    # the watchlist arrives as an xargs-substituted arg ({}), not a lexical redirect target; the
    # structural scan catches the DATA path token in an `xargs` (launder) command. SHOULD block.
    cmd = f"echo {DATA_REL} | xargs -I{{}} cp /tmp/p {{}}"
    assert not gd.decide(_bash(tmp_path, cmd))[0]


def test_python_c_write_to_watchlist_is_blocked(tmp_path):
    # the path is INSIDE a quoted `python3 -c` program (open('…','w')), not a lexical target. The
    # SUBSTRING token-scan catches it; an exact-token match would miss. SHOULD block.
    cmd = f"python3 -c \"open('{DATA_REL}','w').write('POISON')\""
    assert not gd.decide(_bash(tmp_path, cmd))[0]


def test_ed_line_editor_write_to_watchlist_is_blocked(tmp_path):
    # `ed` is an interpreter/launder verb that rewrites a file in place; naming the watchlist as its
    # target in a write-context command -> fail-closed BLOCK.
    cmd = f"printf '1c\\nPOISON\\n.\\nw\\nq\\n' | ed {DATA_REL}"
    assert not gd.decide(_bash(tmp_path, cmd))[0]


def test_cat_read_of_watchlist_is_not_blocked(tmp_path):
    # the != direction (Policy 9): the structural scan is SCOPED to write/interpreter verbs, so a
    # bare `cat <watchlist>` READ is NOT blocked (reads go via the Read tool); a `>|` WRITE of the
    # SAME path IS blocked. The scope distinguishes read from write.
    assert gd.decide(_bash(tmp_path, f"cat {DATA_REL}"))[0]            # READ -> allowed
    assert not gd.decide(_bash(tmp_path, f"echo X >| {DATA_REL}"))[0]  # WRITE -> blocked


def test_structural_scan_does_not_overmatch_tmp_sibling(tmp_path):
    # the boundary check must not let the suffix substring-match a `…json.tmp` sibling: a `>|` to the
    # `.tmp` sibling is OUT of DATA scope -> allowed here (other hooks confine it).
    assert gd.decide(_bash(tmp_path, f"echo X >| {DATA_REL}.tmp"))[0]


# === FINDING-1 (wh-hxt.15 round-1): normpath-parity gap in the structural token-scan ============
# white-hacker PoC (inode-confirmed): _token_names_data did a RAW substring match while its sibling
# _is_data_path runs normpath FIRST, so separator-variant spellings (`//`, `/./`, `/../`) of the
# canonical path slipped the SOLE net for interpreter writes (which have no redirect target) and
# landed poison on the canonical inode from a normal repo-root cwd. The fix separator-COLLAPSES each
# token before the boundary scan. Pin WH's exact vectors, BOTH directions (Policy 9).

# spellings that os.path.normpath collapses onto the canonical watchlist inode.
_SEP_VARIANTS = [
    "plugins/white-hacker/skills/_shared//reference/known-compromised.osv.json",       # //
    "plugins/white-hacker/skills/_shared/./reference/known-compromised.osv.json",      # /./
    "plugins/white-hacker/skills/_shared/reference/../reference/known-compromised.osv.json",  # /../
]


def test_python_c_separator_variant_paths_are_blocked(tmp_path):
    # the 3 separator-variants inside a `python3 -c` open() must BLOCK (were ALLOW(0) bypasses). The
    # canonical control already BLOCKs (test_python_c_write_to_watchlist_is_blocked).
    for v in _SEP_VARIANTS:
        cmd = f"python3 -c \"open('{v}','w').write('POISON')\""
        assert not gd.decide(_bash(tmp_path, cmd))[0], f"python3 -c admitted {v}"


def test_perl_e_double_slash_write_is_blocked(tmp_path):
    # the same separator-collapse closes a `perl -e` open() with a `//` path variant.
    v = "plugins/white-hacker/skills/_shared//reference/known-compromised.osv.json"
    cmd = f"perl -e \"open(F,'>','{v}')\""
    assert not gd.decide(_bash(tmp_path, cmd))[0]


def test_collapse_does_not_overblock_interp_reads_or_tmp_sibling(tmp_path):
    # the != direction (no regression): bare `cat`/`grep` READs of the canonical path are allowed
    # (not write/interp verbs -> not scanned); a `python3 -c` open() of the `…osv.json.tmp` sibling
    # is OUT of DATA scope (suffix followed by `.` ∈ _PATH_CONT survives the collapse) -> allowed.
    assert gd.decide(_bash(tmp_path, f"cat {DATA_REL}"))[0]            # READ -> allowed
    assert gd.decide(_bash(tmp_path, f"grep x {DATA_REL}"))[0]         # READ -> allowed
    cmd = f"python3 -c \"open('{DATA_REL}.tmp','w')\""
    assert gd.decide(_bash(tmp_path, cmd))[0]                          # .tmp sibling -> allowed


def test_collapse_path_seps_normpath_parity():
    # unit: the textual collapse mirrors normpath for the variant spellings WITHOUT corrupting the
    # surrounding code. Pin BOTH: variants collapse onto the canonical suffix; clean forms unchanged.
    seg = "/_shared/reference/known-compromised.osv.json"
    assert gd._collapse_path_seps("open('a/_shared//reference/known-compromised.osv.json','w')") \
        == f"open('a{seg}','w')"
    assert gd._collapse_path_seps("a/_shared/./reference/known-compromised.osv.json") == f"a{seg}"
    assert gd._collapse_path_seps("a/_shared/reference/../reference/known-compromised.osv.json") \
        == f"a{seg}"
    assert gd._collapse_path_seps(f"a{seg}") == f"a{seg}"             # clean form unchanged


def test_token_names_data_after_collapse_both_directions():
    # unit (Policy 9): every separator spelling embedded in code MATCHES; the `.tmp` sibling and an
    # unrelated sibling json do NOT (boundary check survives the collapse).
    seg = "/_shared/reference/known-compromised.osv.json"
    assert gd._token_names_data("open('a/_shared//reference/known-compromised.osv.json','w')")
    assert gd._token_names_data("open('a/_shared/./reference/known-compromised.osv.json','w')")
    assert gd._token_names_data("a/_shared/reference/../reference/known-compromised.osv.json")
    assert gd._token_names_data(f"a{seg}")                            # == canonical
    assert not gd._token_names_data(f"a{seg}.tmp")                    # != sibling (boundary)
    assert not gd._token_names_data("open('a/_shared/reference/other.json','w')")  # != unrelated


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
