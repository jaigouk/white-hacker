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
