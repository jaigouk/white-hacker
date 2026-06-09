"""Tests for the vendor-lane scrubber (wh-7gh).

Run: uv run --with pytest pytest install/tests/ -q

The load-bearing test is `test_real_vendored_tree_has_zero_leaks`: it vendors the REAL agent + the 13
consumer skills exactly as install.sh does, scrubs, and asserts find_leaks() is empty. That is the
drift guard — a future source edit that reintroduces a dev-repo reference fails here, loud (Policy 12).
The synthetic unit tests pin the mechanics (intent, not just behaviour — Policy 9).
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import scrub_vendored as sv

REPO = Path(__file__).resolve().parents[2]
PAYLOAD = REPO / "plugins" / "white-hacker"


# ---- strip_section mechanics -------------------------------------------------------------------

def test_strip_section_removes_block_up_to_next_heading():
    text = "## Keep me\nalpha\n\n## Drop me (x)\nbeta\n### sub\ngamma\n\n## Also keep\ndelta\n"
    out, removed = sv.strip_section(text, "## Drop me")
    assert removed is True
    assert "## Drop me" not in out and "beta" not in out and "### sub" not in out and "gamma" not in out
    # the surrounding sections survive intact
    assert "## Keep me" in out and "alpha" in out and "## Also keep" in out and "delta" in out


def test_strip_section_to_eof_when_last():
    text = "## Body\nkeep\n\n## Verification criteria (definition of done)\nx\ny\nz\n"
    out, removed = sv.strip_section(text, "## Verification criteria")
    assert removed is True
    assert out.rstrip().endswith("keep")
    assert "Verification criteria" not in out and "x\ny\nz" not in out


def test_strip_section_noop_when_header_absent():
    text = "## Only section\nbody\n"
    out, removed = sv.strip_section(text, "## Not here")
    assert removed is False and out == text


def test_strip_section_does_not_match_subheading_prefix():
    # a '### Verification…' subheading must NOT be treated as the top-level section header
    text = "## Real\nbody\n### Verification notes\nkeep this\n## Next\ntail\n"
    out, removed = sv.strip_section(text, "## Verification")
    assert removed is False and "keep this" in out


# ---- find_leaks --------------------------------------------------------------------------------

def test_find_leaks_detects_planted_tokens(tmp_path):
    # a path-bearing spike link is caught via `docs/research`; a bare `(spike-09 §F2)` provenance
    # parenthetical is deliberately NOT a leak (tolerated inert, like `(ADR-015)`).
    (tmp_path / "a.md").write_text(
        "see docs/research/spike-09-foo.md and ${CLAUDE_PLUGIN_ROOT}/x, run /sec-learn\n"
    )
    (tmp_path / "ok.md").write_text("designed per (spike-09 §F2) and (ADR-015) — fine, inert.\n")
    (tmp_path / "b.py").write_text("# clean even with docs/research in a comment\nx = 1\n")
    leaks = sv.find_leaks(tmp_path)
    toks = {lk["token"] for lk in leaks}
    assert "docs/research" in toks and "${CLAUDE_PLUGIN_ROOT}" in toks and "/sec-learn" in toks
    assert all(lk["file"] == "a.md" for lk in leaks)  # ok.md (bare provenance) + b.py (code) untouched


def test_find_leaks_ignores_venv_and_caches(tmp_path):
    venv = tmp_path / "skills" / "x" / ".venv"
    venv.mkdir(parents=True)
    (venv / "leak.py").write_text("import evals/  # noqa\n")
    assert sv.find_leaks(tmp_path) == []


# ---- scrub() behaviour on a synthetic tree -----------------------------------------------------

def test_scrub_drops_producer_files(tmp_path):
    p = tmp_path / "skills" / "ai-attack-kb" / "scripts"
    (p / "tests").mkdir(parents=True)
    (p / "precommit_safety.py").write_text("# producer-only gate\n")
    (p / "tests" / "test_precommit_safety.py").write_text("# its test\n")
    report = sv.scrub(tmp_path)
    assert not (p / "precommit_safety.py").exists()
    assert not (p / "tests" / "test_precommit_safety.py").exists()
    assert "skills/ai-attack-kb/scripts/precommit_safety.py" in report["files_dropped"]


def test_scrub_applies_agent_replacements(tmp_path):
    agent = tmp_path / "agents" / "white-hacker.md"
    agent.parent.mkdir(parents=True)
    agent.write_text(
        "## The review loop\n"
        "Skills live under `skills/` (plugin-relative; resolved at runtime as "
        "`${CLAUDE_PLUGIN_ROOT}/skills/`).\nbody\n"
    )
    sv.scrub(tmp_path)
    out = agent.read_text()
    assert "${CLAUDE_PLUGIN_ROOT}" not in out
    assert ".claude/skills/" in out  # neutered to the vendored location


# ---- THE GUARD: real vendored payload, end to end ----------------------------------------------

def _vendor_real_tree(dst: Path) -> Path:
    """Reproduce install.sh vendor(): copy the agent + the 13 consumer skills (sans venvs)."""
    claude = dst / ".claude"
    (claude / "agents").mkdir(parents=True)
    shutil.copy(PAYLOAD / "agents" / "white-hacker.md", claude / "agents" / "white-hacker.md")
    ignore = shutil.ignore_patterns(".venv", "__pycache__", ".pytest_cache")
    for s in sv.CONSUMER_SKILLS:
        src = PAYLOAD / "skills" / s
        if src.is_dir():
            shutil.copytree(src, claude / "skills" / s, ignore=ignore)
    return claude


def test_real_vendored_tree_has_zero_leaks(tmp_path):
    claude = _vendor_real_tree(tmp_path)
    # sanity: the un-scrubbed tree DOES leak (else the test proves nothing)
    assert sv.find_leaks(claude), "expected the raw payload to contain dev-repo refs before scrub"
    report = sv.scrub(claude)
    if report["leaks"]:
        msg = "\n".join(f"  {lk['file']}:{lk['line']} [{lk['token']}] {lk['text']}" for lk in report["leaks"])
        pytest.fail(f"{len(report['leaks'])} dev-repo leak(s) survived the scrub:\n{msg}")


def test_real_scrub_preserves_inner_loop_skills(tmp_path):
    claude = _vendor_real_tree(tmp_path)
    sv.scrub(claude)
    # the producer skills were never copied; every consumer skill keeps a non-trivial SKILL.md
    assert not (claude / "skills" / "sec-learn").exists()
    assert not (claude / "skills" / "sec-kb-refresh").exists()
    for s in sv.CONSUMER_SKILLS:
        skill_md = claude / "skills" / s / "SKILL.md"
        if s == "_shared":
            continue  # _shared is a lib (reference/ + scripts/), no SKILL.md
        assert skill_md.exists(), f"{s}/SKILL.md missing after scrub"
        assert len(skill_md.read_text()) > 400, f"{s}/SKILL.md gutted by scrub"


def test_real_agent_keeps_inner_loop_identity(tmp_path):
    claude = _vendor_real_tree(tmp_path)
    sv.scrub(claude)
    agent = (claude / "agents" / "white-hacker.md").read_text()
    # outer-loop section is gone; inner-loop identity + team awareness remain
    assert "## Self-improvement (the outer loop)" not in agent
    assert "## The review loop" in agent
    assert "## Team-workflow awareness" in agent
    assert "## Verification of your own work" in agent
    # the resource-aware execution-budget section is inner-loop guidance — it MUST ship to targets
    assert "## Execution budget" in agent and "OOM-safety is a HARD rule" in agent
    # the concrete per-command caps must ship too (don't freeze a target user's host)
    assert "Concrete per-command caps" in agent and "nice -n 10" in agent and "pytest -n auto" in agent
