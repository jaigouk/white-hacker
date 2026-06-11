"""Tests for the plugin PreToolUse hook registration manifest (T-10.3, TDD).

Run: uv run --with pytest pytest plugins/white-hacker/hooks/tests/test_hooks_json.py

Asserts hooks.json is valid JSON, registers a PreToolUse confinement chain, and that every
referenced command resolves (after ${CLAUDE_PLUGIN_ROOT} substitution) to an existing,
executable script. Plugin hook shape verified in spike-06.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

# hooks.json lives next to the hooks package; the package root maps to ${CLAUDE_PLUGIN_ROOT}/hooks,
# so CLAUDE_PLUGIN_ROOT resolves to plugins/white-hacker (the parent of this hooks dir).
HOOKS_DIR = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = HOOKS_DIR.parent
HOOKS_JSON = HOOKS_DIR / "hooks.json"


def _load() -> dict:
    return json.loads(HOOKS_JSON.read_text())


def _commands(manifest: dict) -> list[str]:
    cmds: list[str] = []
    for group in manifest["hooks"]["PreToolUse"]:
        for handler in group["hooks"]:
            if handler.get("type") == "command":
                cmds.append(handler["command"])
    return cmds


def test_hooks_json_is_valid_json():
    assert HOOKS_JSON.exists()
    manifest = _load()  # raises on invalid JSON
    assert isinstance(manifest, dict)


def test_has_pretooluse_hooks():
    manifest = _load()
    assert "hooks" in manifest
    assert "PreToolUse" in manifest["hooks"]
    assert manifest["hooks"]["PreToolUse"], "PreToolUse must have at least one matcher group"


def test_uses_plugin_root_variable():
    manifest = _load()
    cmds = _commands(manifest)
    assert cmds, "expected at least one command hook"
    assert all("${CLAUDE_PLUGIN_ROOT}" in c for c in cmds)


def test_registers_the_three_confinement_scripts():
    manifest = _load()
    cmds = _commands(manifest)
    needed = {"guard_bash.sh", "confine_patch_writes.sh", "confine_self_writes.sh"}
    referenced = {os.path.basename(c) for c in cmds}
    assert needed <= referenced, f"missing: {needed - referenced}"


def test_registers_gate_kb_edit_guardrail():
    """The outer-loop keep-or-revert KB-edit gate (T-9.3) must be wired, not just present as
    logic+tests: an in-session edit to ai-attack-kb/** or _shared/reference/** is blocked unless
    evals/gate-verdict.json says KEEP. Belt-and-suspenders to the CI merge gate."""
    manifest = _load()
    referenced = {os.path.basename(c) for c in _commands(manifest)}
    assert "gate_kb_edit.sh" in referenced, f"gate_kb_edit not registered; got: {referenced}"


def test_registers_gate_data_edit_guardrail():
    """The Gate-2 DATA write-lane gate (wh-hxt.6; ADR-026 §3) must be wired, not just present as
    logic+tests: a write to the named watchlist DATA file is admitted only by a content-bound,
    one-shot `evals/data-verdict.json` KEEP — NOT the eval-J KB verdict (false-merit-merge closure).
    Registered in the existing PreToolUse Bash|Write|Edit group, AFTER gate_kb_edit.sh."""
    manifest = _load()
    cmds = _commands(manifest)
    referenced = {os.path.basename(c) for c in cmds}
    assert "gate_data_edit.sh" in referenced, f"gate_data_edit not registered; got: {referenced}"
    # ordering: gate_data_edit.sh after gate_kb_edit.sh in the same PreToolUse group (spec step 4).
    bases = [os.path.basename(c) for c in cmds]
    assert "gate_kb_edit.sh" in bases and "gate_data_edit.sh" in bases
    assert bases.index("gate_data_edit.sh") > bases.index("gate_kb_edit.sh")


def test_gate_data_edit_resolves_to_executable_script():
    """The registered gate_data_edit.sh resolves (after ${CLAUDE_PLUGIN_ROOT} substitution) to an
    existing, executable script (HARD-ORDERING SEC-Q3: it must be live before any watchlist file)."""
    manifest = _load()
    targets = [c for c in _commands(manifest) if os.path.basename(c) == "gate_data_edit.sh"]
    assert targets, "gate_data_edit.sh not registered"
    for cmd in targets:
        assert "${CLAUDE_PLUGIN_ROOT}" in cmd
        resolved = cmd.replace("${CLAUDE_PLUGIN_ROOT}", str(PLUGIN_ROOT))
        p = Path(resolved)
        assert p.exists(), f"gate_data_edit hook script does not exist: {resolved}"
        assert os.access(p, os.X_OK), f"gate_data_edit hook script not executable: {resolved}"


def _sessionstart_commands(manifest: dict) -> list[str]:
    cmds: list[str] = []
    for group in manifest["hooks"].get("SessionStart", []):
        for handler in group["hooks"]:
            if handler.get("type") == "command":
                cmds.append(handler["command"])
    return cmds


def test_registers_sessionstart_project_facts():
    """SessionStart is now registered (T-10.6) and points to an existing executable script.

    Honors bug anthropics/claude-code#16538: the reliable path is project-scope registration
    (documented in onboarding, T-10.7); the plugin still advertises the SessionStart hook here.
    """
    manifest = _load()
    assert "SessionStart" in manifest["hooks"], "SessionStart must be registered (T-10.6)"
    cmds = _sessionstart_commands(manifest)
    assert cmds, "SessionStart must have at least one command hook"
    referenced = {os.path.basename(c) for c in cmds}
    assert "sessionstart_project_facts.sh" in referenced, f"got: {referenced}"
    for cmd in cmds:
        assert "${CLAUDE_PLUGIN_ROOT}" in cmd
        resolved = cmd.replace("${CLAUDE_PLUGIN_ROOT}", str(PLUGIN_ROOT))
        p = Path(resolved)
        assert p.exists(), f"SessionStart hook script does not exist: {resolved}"
        assert os.access(p, os.X_OK), f"SessionStart hook script not executable: {resolved}"


def test_does_not_register_gate_review_in_pretooluse():
    manifest = _load()
    cmds = _commands(manifest)
    assert all("gate_review" not in c for c in cmds)


def test_every_command_resolves_to_executable_script():
    manifest = _load()
    for cmd in _commands(manifest) + _sessionstart_commands(manifest):
        resolved = cmd.replace("${CLAUDE_PLUGIN_ROOT}", str(PLUGIN_ROOT))
        p = Path(resolved)
        assert p.exists(), f"hook script does not exist: {resolved}"
        assert os.access(p, os.X_OK), f"hook script not executable: {resolved}"


def test_matchers_cover_bash_write_edit():
    manifest = _load()
    matchers = " ".join(g.get("matcher", "") for g in manifest["hooks"]["PreToolUse"])
    for tool in ("Bash", "Write", "Edit"):
        assert tool in matchers, f"matcher does not cover {tool}"
