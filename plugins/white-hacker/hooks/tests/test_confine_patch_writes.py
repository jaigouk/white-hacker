"""Tests for the sec-patch write-confinement tripwire (T-5.3, TDD).

Run: uv run --with pytest pytest plugins/white-hacker/hooks/tests/test_confine_patch_writes.py

Covers the red-team bypass vectors the groom enumerated: redirection / tee / cp / mv / dd /
truncate / sed -i to a non-allowlisted target; path traversal; absolute + `$`-indirection;
symlink-through-allowlist; interpreter one-liner writes; nested `sh -c`; patch / git-mutation
verbs; `.claude/**` self-writes; compound commands. Plus the allow-set (artifact chain, PATCHES/,
/dev/null, read-only git, commit, pytest, read-only interpreter) so the build pipeline isn't broken.
"""
from __future__ import annotations

import io
import json
import os

import confine_patch_writes as cpw


def _bash(cmd, root):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(root)}


def allow(cmd, root):
    return cpw.decide(_bash(cmd, root))[0]


def deny(cmd, root):
    return not cpw.decide(_bash(cmd, root))[0]


# --- ALLOW: artifact chain + PATCHES/ + safe targets + read-only ----------

def test_allows_artifact_chain_writes(tmp_path):
    for f in ("SCAN-PLAN.json", "VULN-FINDINGS.json", "TRIAGE.json",
              "SECURITY-REPORT.md", "THREAT_MODEL.md", "PATCH-STATE.json", "out.sarif"):
        assert allow(f"echo x > {f}", tmp_path), f


def test_allows_patches_dir(tmp_path):
    assert allow("echo x > PATCHES/F-001-fix.diff", tmp_path)


def test_allows_dev_null_and_temp(tmp_path):
    assert allow("pytest -q > /dev/null", tmp_path)
    assert allow("echo x > /tmp/scratch_probe", tmp_path)


def test_allows_readonly_and_commit(tmp_path):
    for c in ("git status", "git diff", "git log --oneline -5", "git commit -m wip",
              "uv run pytest", "grep -rn foo src/", "mkdir -p PATCHES",
              "python3 -c 'import json,sys; assert True'"):
        assert allow(c, tmp_path), c


# --- DENY: obvious source writes ------------------------------------------

def test_denies_redirection_to_source(tmp_path):
    assert deny("echo x > src/app.py", tmp_path)
    assert deny("echo x >> src/app.py", tmp_path)
    assert deny("printf p > src/app.py", tmp_path)


def test_denies_tee_cp_mv_dd_truncate(tmp_path):
    assert deny("echo x | tee src/app.py", tmp_path)
    assert deny("cp evil.py src/app.py", tmp_path)
    assert deny("mv evil.py src/app.py", tmp_path)
    assert deny("dd if=/dev/zero of=src/app.py", tmp_path)
    assert deny("truncate -s 0 src/app.py", tmp_path)


def test_denies_inplace_edit(tmp_path):
    assert deny("sed -i 's/a/b/' src/app.py", tmp_path)
    assert deny("perl -i -pe 's/a/b/' src/app.py", tmp_path)


# --- DENY: traversal / absolute / indirection -----------------------------

def test_denies_path_traversal(tmp_path):
    assert deny("echo x > PATCHES/../src/app.py", tmp_path)


def test_denies_absolute_into_source(tmp_path):
    assert deny(f"echo x > {tmp_path}/src/app.py", tmp_path)


def test_denies_variable_indirection(tmp_path):
    assert deny("echo x > $PWD/src/app.py", tmp_path)
    assert deny("echo x > $TARGET", tmp_path)
    assert deny("echo x > `echo src/app.py`", tmp_path)


# --- DENY: symlink-through-allowlist (realpath canonicalization) -----------

def test_denies_symlink_through_allowlist(tmp_path):
    (tmp_path / "PATCHES").mkdir()
    (tmp_path / "src").mkdir()
    os.symlink(tmp_path / "src", tmp_path / "PATCHES" / "evil")  # PATCHES/evil -> src
    assert deny("echo x > PATCHES/evil/app.py", tmp_path)


# --- DENY: interpreter one-liner writes -----------------------------------

def test_denies_interpreter_writes(tmp_path):
    assert deny('python3 -c "open(\'src/app.py\',\'w\').write(\'p\')"', tmp_path)
    assert deny("perl -e 'open(F,\">\",\"src/x\"); print F 1'", tmp_path)
    assert deny('awk \'BEGIN{print "x" > "src/app.py"}\'', tmp_path)


# --- DENY: nested shell ----------------------------------------------------

def test_denies_nested_shell(tmp_path):
    assert deny("sh -c 'echo x > src/app.py'", tmp_path)
    assert deny("bash -c 'cp a src/app.py'", tmp_path)


# --- DENY: patch / git mutation -------------------------------------------

def test_denies_patch_and_git_apply(tmp_path):
    assert deny("patch -p1 < fix.diff", tmp_path)
    assert deny("git apply fix.diff", tmp_path)
    assert deny("git am < fix.patch", tmp_path)


def test_denies_git_push_and_destructive(tmp_path):
    assert deny("git push origin main", tmp_path)
    assert deny("git reset --hard HEAD~1", tmp_path)
    assert deny("git clean -fd", tmp_path)
    assert deny("git config core.hooksPath /tmp/x", tmp_path)


def test_allows_git_commit_and_add(tmp_path):
    # commit/add do not write source files; blocking them would break Claude-assisted commits.
    assert allow("git add -A", tmp_path)
    assert allow("git commit -m 'build -> fix -> tests pass'", tmp_path)  # arrows must not trip redir


# --- DENY: writes to .claude/ (self-disablement) --------------------------

def test_denies_dot_claude_writes(tmp_path):
    assert deny("echo x > .claude/settings.json", tmp_path)
    assert deny("echo x > .claude/hooks/confine_patch_writes.py", tmp_path)


# --- compound commands -----------------------------------------------------

def test_denies_if_any_subcommand_is_bad(tmp_path):
    assert deny("echo ok > SCAN-PLAN.json && echo bad > src/app.py", tmp_path)
    assert allow("echo a > SCAN-PLAN.json && echo b > TRIAGE.json", tmp_path)


# --- Write/Edit tool branch (defense-in-depth) ----------------------------

def test_write_tool_path_confined(tmp_path):
    assert not cpw.decide({"tool_name": "Write", "tool_input": {"file_path": "src/app.py"}, "cwd": str(tmp_path)})[0]
    assert cpw.decide({"tool_name": "Write", "tool_input": {"file_path": "PATCHES/F-1.diff"}, "cwd": str(tmp_path)})[0]
    assert cpw.decide({"tool_name": "Edit", "tool_input": {"file_path": "SCAN-PLAN.json"}, "cwd": str(tmp_path)})[0]


# --- main() exit codes (spike-06: exit 2 = block) -------------------------

def test_main_allow_exit_0(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_bash("echo x > SCAN-PLAN.json", tmp_path))))
    assert cpw.main() == 0


def test_main_deny_exit_2(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_bash("echo x > src/app.py", tmp_path))))
    assert cpw.main() == 2


def test_main_malformed_event_failopen(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    assert cpw.main() == 0  # tripwire fails open on a malformed event


# --- invariants ------------------------------------------------------------

def test_residual_risk_documented_in_header():
    src = (cpw.__doc__ or "")
    assert "RESIDUAL RISK" in src and "tripwire" in src.lower()


def test_allowlist_is_pinned():
    assert cpw.ALLOWLIST_BASENAMES == {
        "THREAT_MODEL.md", "SCAN-PLAN.json", "VULN-FINDINGS.json", "TRIAGE.json",
        "SECRETS.json", "DEPS.json", "SECURITY-REPORT.md", "PATCH-STATE.json",
    }
