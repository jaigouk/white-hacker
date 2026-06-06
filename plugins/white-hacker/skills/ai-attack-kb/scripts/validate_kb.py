"""Validate ai-attack-kb reference entries (T-4.1).

Each `reference/<technique-class>.md` is ONE KB entry: YAML front-matter (the schema
fields) + a body whose first paragraph is a <=120-word summary. This validator:
  * parses each entry's YAML front-matter,
  * validates it against `../kb-entry-schema.json` (Draft 2020-12),
  * enforces size caps (<=120-word summary, <=400-line file),
  * enforces unique `id` across the directory (typed, never-reused ids; ADR-012).

T-8.1 later adds `review_by`/refresh gating on top; this is the functional base.

CLI:
    uv run --with jsonschema --with pyyaml python validate_kb.py <kb-reference-dir-or-file> ...

Exit code 0 = all valid, 1 = at least one invalid, 2 = usage error.
"""
from __future__ import annotations

import datetime as _dt
import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "kb-entry-schema.json"

MAX_SUMMARY_WORDS = 120
MAX_FILE_LINES = 400


def load_schema(path: Path = SCHEMA_PATH) -> dict:
    return json.loads(path.read_text())


def _normalize(obj):
    """YAML parses unquoted `2026-06-06` to datetime.date; the schema wants ISO strings.

    Recursively convert date/datetime values to their ISO-8601 string form so a
    naturally-written (unquoted) date field still validates against the date pattern.
    """
    if isinstance(obj, dict):
        return {k: _normalize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize(v) for v in obj]
    if isinstance(obj, _dt.datetime):
        return obj.date().isoformat()
    if isinstance(obj, _dt.date):
        return obj.isoformat()
    return obj


def split_front_matter(text: str) -> tuple[str | None, str]:
    """Return (front_matter_yaml, body). front_matter is None if absent/malformed."""
    if not text.startswith("---"):
        return None, text
    lines = text.splitlines(keepends=True)
    # first line is the opening fence; find the closing `---` fence.
    for i in range(1, len(lines)):
        if lines[i].rstrip("\n") in ("---", "..."):
            front = "".join(lines[1:i])
            body = "".join(lines[i + 1:])
            return front, body
    return None, text


def summary_word_count(body: str) -> int:
    """Word count of the first non-empty paragraph (the entry summary)."""
    for block in body.split("\n\n"):
        block = block.strip()
        if block:
            return len(block.split())
    return 0


def validate_entry(meta: dict, schema: dict | None = None) -> list[str]:
    """Schema errors for one parsed front-matter dict (empty list = valid)."""
    schema = schema if schema is not None else load_schema()
    validator = Draft202012Validator(schema)
    return [
        f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
        for e in sorted(validator.iter_errors(_normalize(meta)), key=lambda e: list(e.path))
    ]


def validate_file(path: Path, schema: dict | None = None) -> tuple[str | None, list[str]]:
    """Validate one entry file. Returns (entry_id_or_None, errors)."""
    schema = schema if schema is not None else load_schema()
    errors: list[str] = []
    text = Path(path).read_text()

    if len(text.splitlines()) > MAX_FILE_LINES:
        errors.append(f"file exceeds {MAX_FILE_LINES} lines")

    front, body = split_front_matter(text)
    if front is None:
        errors.append("missing or unterminated YAML front-matter (`---` fences)")
        return None, errors

    try:
        meta = yaml.safe_load(front)
    except yaml.YAMLError as exc:
        errors.append(f"unparseable YAML front-matter: {exc}")
        return None, errors
    if not isinstance(meta, dict):
        errors.append("front-matter is not a mapping")
        return None, errors

    errors.extend(validate_entry(meta, schema))

    words = summary_word_count(body)
    if words > MAX_SUMMARY_WORDS:
        errors.append(f"summary is {words} words (>{MAX_SUMMARY_WORDS}-word cap)")

    return meta.get("id"), errors


def validate_dir(path: Path, schema: dict | None = None) -> list[str]:
    """Validate every *.md entry in a directory; add a cross-file unique-id check."""
    schema = schema if schema is not None else load_schema()
    path = Path(path)
    files = sorted(path.glob("*.md")) if path.is_dir() else [path]
    if not files:
        return [f"no *.md entries found under {path}"]

    all_errors: list[str] = []
    seen: dict[str, str] = {}
    for f in files:
        fid, errs = validate_file(f, schema)
        all_errors.extend(f"{f.name}: {e}" for e in errs)
        if fid is not None:
            if fid in seen:
                all_errors.append(f"duplicate id {fid}: {f.name} and {seen[fid]}")
            else:
                seen[fid] = f.name
    return all_errors


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    targets = [a for a in argv if not a.startswith("-")]
    if not targets:
        print("usage: validate_kb.py <kb-reference-dir-or-file> ...")
        return 2

    schema = load_schema()
    rc = 0
    for t in targets:
        errors = validate_dir(Path(t), schema)
        if errors:
            rc = 1
            print(f"INVALID {t}:")
            for e in errors:
                print(f"  - {e}")
        else:
            print(f"OK {t}")
    return rc


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
