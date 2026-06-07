"""Tests for the ADR-005 skill linter (T-8.1, TDD).

Run: uv run --with pyyaml --with pytest pytest plugins/white-hacker/skills/ai-attack-kb/scripts/tests/test_lint_skill.py

A passing skill; over-cap name / description / description+when_to_use; oversize SKILL.md;
a nested reference/ subdir; and a dir lint over multiple skills.
"""
from __future__ import annotations

from pathlib import Path

import lint_skill as ls


def _skill(tmp_path, name="sec-x", desc="A concise description.", when=None, body_lines=20):
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    fm = [f"name: {name}", f"description: {desc}"]
    if when is not None:
        fm.append(f"when_to_use: {when}")
    body = "\n".join(f"line {i}" for i in range(body_lines))
    (d / "SKILL.md").write_text("---\n" + "\n".join(fm) + "\n---\n\n# " + name + "\n" + body + "\n")
    return d / "SKILL.md"


def test_passing_skill(tmp_path):
    assert ls.lint_skill_file(_skill(tmp_path)) == []


def test_name_over_cap(tmp_path):
    assert ls.lint_skill_file(_skill(tmp_path, name="x" * 65))


def test_description_over_cap(tmp_path):
    assert ls.lint_skill_file(_skill(tmp_path, desc="d" * 1025))


def test_description_plus_when_over_cap(tmp_path):
    errs = ls.lint_skill_file(_skill(tmp_path, desc="d" * 1000, when="w" * 600))
    assert any("description+when_to_use" in e for e in errs)


def test_oversize_skill_file(tmp_path):
    assert ls.lint_skill_file(_skill(tmp_path, body_lines=520))


def test_reference_must_be_one_level_deep(tmp_path):
    sk = _skill(tmp_path, name="kb")
    nested = sk.parent / "reference" / "deep"
    nested.mkdir(parents=True)
    (nested / "x.md").write_text("x")
    errs = ls.lint_skill_file(sk)
    assert any("one level deep" in e for e in errs)


def test_missing_frontmatter(tmp_path):
    d = tmp_path / "sec-y"; d.mkdir()
    (d / "SKILL.md").write_text("# no front matter\n")
    assert ls.lint_skill_file(d / "SKILL.md")


def test_lint_dir_multiple(tmp_path):
    _skill(tmp_path, name="sec-a")
    _skill(tmp_path, name="sec-b")
    results = ls.lint_dir(tmp_path)
    assert len(results) == 2 and all(v == [] for v in results.values())


def test_main_usage_error():
    assert ls.main([]) == 2


def test_main_pass(tmp_path):
    _skill(tmp_path, name="sec-ok")
    assert ls.main([str(tmp_path)]) == 0


def test_main_fail(tmp_path):
    _skill(tmp_path, name="x" * 65)
    assert ls.main([str(tmp_path)]) == 1


# --- strict-YAML frontmatter gate (T-QA-3) ---------------------------------
# `claude plugin validate` parses frontmatter with STRICT YAML. A plain unquoted
# value containing `: ` (an inner colon) is read as a nested mapping and the whole
# frontmatter is silently dropped at runtime. lint_skill must catch this — the
# lenient char-cap extractor alone shipped 3 broken skills.


def _skill_raw_front(tmp_path, name, front_lines):
    """Write a SKILL.md with the given raw frontmatter lines (verbatim)."""
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    body = "\n".join(f"line {i}" for i in range(20))
    (d / "SKILL.md").write_text("---\n" + "\n".join(front_lines) + "\n---\n\n# " + name + "\n" + body + "\n")
    return d / "SKILL.md"


def test_unquoted_colon_in_description_fails_strict(tmp_path):
    """A plain description with an inner `: ` is not strict-YAML-parseable -> ERROR."""
    sk = _skill_raw_front(
        tmp_path,
        "sec-bad",
        ["name: sec-bad", "description: AI/LLM review: improper output handling and more"],
    )
    errs = ls.lint_skill_file(sk)
    assert any("strict YAML" in e or "frontmatter" in e.lower() for e in errs), errs


def test_block_scalar_description_passes_strict(tmp_path):
    """A folded block-scalar description with a colon parses fine -> no strict error."""
    sk = _skill_raw_front(
        tmp_path,
        "sec-good",
        [
            "name: sec-good",
            "description: >",
            "  AI/LLM review: improper output handling and more wrapped over",
            "  a couple of indented lines, all one folded scalar.",
        ],
    )
    errs = ls.lint_skill_file(sk)
    assert not any("strict YAML" in e for e in errs), errs


def test_shipped_skills_pass_strict_yaml():
    """Regression: every shipped plugin SKILL.md frontmatter is strict-YAML-parseable."""
    skills_dir = Path(__file__).resolve().parents[4] / "skills"
    shipped = sorted(skills_dir.glob("*/SKILL.md"))
    assert shipped, f"no shipped SKILL.md found under {skills_dir}"
    for sk in shipped:
        errs = ls.lint_skill_file(sk)
        strict_errs = [e for e in errs if "strict YAML" in e]
        assert not strict_errs, f"{sk}: {strict_errs}"
