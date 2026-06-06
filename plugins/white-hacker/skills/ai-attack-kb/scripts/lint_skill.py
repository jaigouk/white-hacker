"""ADR-005 skill size-cap linter (T-8.1).

Enforces the always-loaded-surface caps so skills/the KB stay cheap to load:
  * `name` <= 64 chars
  * `description` <= 1024 chars
  * `description` + `when_to_use` <= 1536 chars
  * `SKILL.md` < 500 lines
  * `reference/` is one level deep (no nested subdirs)

This is the script every "lint passes" criterion in the plan refers to. KB *entry* schema +
provenance is enforced separately by `validate_kb.py` (T-4.1).

CLI:
    uv run --with pyyaml python lint_skill.py .claude/skills/   # lints every */SKILL.md
Exit 0 = all pass, 1 = a cap violated, 2 = usage error.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def split_front_matter(text: str) -> tuple[str | None, str]:
    """(front_matter_yaml, body); front is None if absent/unterminated. (No jsonschema dep.)"""
    if not text.startswith("---"):
        return None, text
    lines = text.splitlines(keepends=True)
    for i in range(1, len(lines)):
        if lines[i].rstrip("\n") in ("---", "..."):
            return "".join(lines[1:i]), "".join(lines[i + 1:])
    return None, text


def front_fields(front: str) -> dict[str, str]:
    """Lenient top-level `key: value` extractor matching Claude Code's frontmatter parsing.

    Strict YAML rejects a plain value containing `: ` (e.g. a description with a colon), but CC
    accepts it, so we must too. Handles single-line values (value = rest of line, colons and all)
    and folded/literal block scalars (`key: >` / `|` with indented continuation lines).
    """
    fields: dict[str, str] = {}
    lines = front.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*):\s?(.*)$", line)
        if m and not line[:1].isspace():
            key, val = m.group(1), m.group(2)
            if val.strip() in (">", "|", ">-", "|-", ">+", "|+"):
                block, j = [], i + 1
                while j < len(lines) and (lines[j][:1].isspace() or not lines[j].strip()):
                    block.append(lines[j].strip())
                    j += 1
                fields[key] = " ".join(b for b in block if b)
                i = j
                continue
            fields[key] = val.strip()
        i += 1
    return fields


NAME_CAP = 64
DESC_CAP = 1024
DESC_PLUS_WHEN_CAP = 1536
SKILL_LINE_CAP = 500  # must be < 500


def lint_skill_file(path: Path) -> list[str]:
    path = Path(path)
    errors: list[str] = []
    text = path.read_text()

    n = len(text.splitlines())
    if n >= SKILL_LINE_CAP:
        errors.append(f"SKILL.md is {n} lines (must be < {SKILL_LINE_CAP})")

    front, _ = split_front_matter(text)
    if front is None:
        errors.append("missing or unterminated YAML front-matter")
        return errors
    meta = front_fields(front)
    name = meta.get("name", "")
    desc = meta.get("description", "")
    when = meta.get("when_to_use", "")
    if len(name) > NAME_CAP:
        errors.append(f"name is {len(name)} chars (> {NAME_CAP})")
    if len(desc) > DESC_CAP:
        errors.append(f"description is {len(desc)} chars (> {DESC_CAP})")
    if len(desc) + len(when) > DESC_PLUS_WHEN_CAP:
        errors.append(f"description+when_to_use is {len(desc) + len(when)} chars (> {DESC_PLUS_WHEN_CAP})")

    ref = path.parent / "reference"
    if ref.is_dir():
        for child in ref.iterdir():
            if child.is_dir():
                errors.append(f"reference/ must be one level deep; found subdir {child.name}/")
    return errors


def lint_dir(root: Path) -> dict[str, list[str]]:
    root = Path(root)
    skills = sorted(root.glob("*/SKILL.md"))
    return {str(s): lint_skill_file(s) for s in skills}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    targets = [a for a in argv if not a.startswith("-")]
    if not targets:
        print("usage: lint_skill.py <skills-dir-or-SKILL.md> ...")
        return 2
    rc = 0
    for t in targets:
        p = Path(t)
        results = {str(p): lint_skill_file(p)} if p.name == "SKILL.md" else lint_dir(p)
        if not results:
            print(f"(no SKILL.md found under {t})")
        for skill, errs in results.items():
            if errs:
                rc = 1
                print(f"LINT FAIL {skill}:")
                for e in errs:
                    print(f"  - {e}")
            else:
                print(f"OK {skill}")
    return rc


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
