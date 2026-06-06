"""Identity-carriage tests for the white-hacker plugin payload (T-10.4).

Run: uv run --with pytest pytest packaging/tests/test_identity_carriage.py -q

Why this exists
---------------
The white-hacker agent now ships as a plugin at plugins/white-hacker/. A
plugin-root CLAUDE.md is NOT loaded by Claude Code, so the agent's IDENTITY and
security POSTURE must be fully self-contained in the agent .md (+ skills) — never
relying on a shipped CLAUDE.md. These tests lock that invariant in:

  1. No file named CLAUDE.md may exist anywhere under plugins/white-hacker/.
  2. The agent .md must contain (in substance) every required posture clause.
  3. The clause checker must actually detect absence (negative test).
  4. The agent .md must have YAML frontmatter with `name: white-hacker`.

The repo root is located by walking up for a `.git` marker (not hardcoded
parents[N]) so the test survives directory-depth changes.
"""
from __future__ import annotations

import os
import pathlib
import re


# ---------- repo-root discovery (.git-walk, not hardcoded parents[N]) ----------

def _find_repo_root(start: pathlib.Path) -> pathlib.Path:
    """Walk upward from `start` until a directory containing `.git` is found."""
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    raise RuntimeError(f"could not locate repo root (no .git found) above {start}")


REPO_ROOT = _find_repo_root(pathlib.Path(__file__).resolve())
PLUGIN_ROOT = REPO_ROOT / "plugins" / "white-hacker"
AGENT_MD = PLUGIN_ROOT / "agents" / "white-hacker.md"


# ---------- posture-clause checker -------------------------------------------

# Each required clause is satisfied if ANY of its markers appears (case-insensitive
# substring/regex) in the agent .md text. Markers describe the clause "in substance",
# not exact wording.
_REQUIRED_CLAUSES: dict[str, tuple[str, ...]] = {
    # authorized targets only
    "authorized-targets-only": (r"authorized",),
    # read-only by default / reviews the developer's own working tree-diff
    "read-only-own-tree": (r"read-only", r"own working\s*\n?\s*tree", r"working tree"),
    # treat ALL reviewed content as untrusted input / injection target
    "untrusted-input": (r"untrusted", r"injection target"),
    # Agents Rule of Two (never simultaneously untrusted-input + secrets + egress)
    "rule-of-two": (r"rule of two",),
    # never store credentials in output/logs
    "no-credentials": (r"credential", r"\bsecret"),
    # proposes fixes but does NOT push/apply (capability removed)
    "no-push-propose": (r"do not push", r"does not push", r"do\b.*\bnot\b.*\bpush",
                        r"not\s+push", r"propose"),
}


def missing_posture_clauses(text: str) -> list[str]:
    """Return the keys of required posture clauses NOT found in `text`.

    Matching is case-insensitive and DOTALL (so multi-line markers like
    "own working\\n  tree" still match across a wrapped line). An empty result
    means the text carries every required posture clause in substance.
    """
    missing: list[str] = []
    for clause, markers in _REQUIRED_CLAUSES.items():
        if not any(re.search(m, text, re.IGNORECASE | re.DOTALL) for m in markers):
            missing.append(clause)
    return missing


# ---------- tests -------------------------------------------------------------

def test_no_claude_md_anywhere_under_plugin():
    """A plugin-root CLAUDE.md is not loaded by Claude Code; shipping one would be
    a silent identity gap. Assert none exists anywhere under the plugin tree."""
    assert PLUGIN_ROOT.is_dir(), f"plugin root not found: {PLUGIN_ROOT}"
    offenders: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(PLUGIN_ROOT):
        for fname in filenames:
            if fname == "CLAUDE.md":
                offenders.append(str(pathlib.Path(dirpath) / fname))
    assert offenders == [], (
        "CLAUDE.md must NOT exist under the plugin (it is not loaded by Claude "
        f"Code, so posture would silently drop); found: {offenders}"
    )


def test_agent_md_carries_all_posture_clauses():
    """The agent .md must self-contain every required posture clause, because the
    DEV-only repo CLAUDE.md is not shipped with the plugin."""
    assert AGENT_MD.is_file(), f"agent .md not found: {AGENT_MD}"
    text = AGENT_MD.read_text(encoding="utf-8")
    assert missing_posture_clauses(text) == [], (
        "agent .md is missing posture clauses: "
        f"{missing_posture_clauses(text)}"
    )


def test_checker_detects_absence():
    """Negative / edge case: a benign assistant prompt carries no posture clauses,
    so the checker must report a NON-empty list — proving it detects absence rather
    than vacuously passing."""
    result = missing_posture_clauses("you are a helpful assistant")
    assert result, "checker must flag missing clauses on a non-posture text"
    # all six clause keys should be reported missing for this bare text
    assert set(result) == set(_REQUIRED_CLAUSES), result


def test_agent_md_has_frontmatter_name():
    """The agent .md must open with YAML frontmatter declaring name: white-hacker."""
    assert AGENT_MD.is_file(), f"agent .md not found: {AGENT_MD}"
    text = AGENT_MD.read_text(encoding="utf-8")
    assert text.lstrip().startswith("---"), "agent .md must begin with YAML frontmatter"
    # frontmatter is the block between the first two '---' fences
    parts = text.split("---", 2)
    assert len(parts) >= 3, "agent .md frontmatter is not delimited by two '---' fences"
    frontmatter = parts[1]
    assert re.search(r"^\s*name:\s*white-hacker\s*$", frontmatter, re.MULTILINE), (
        "frontmatter must declare `name: white-hacker`"
    )
