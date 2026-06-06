"""Validate a white-hacker findings document against the canonical schema.

The schema (`../reference/finding-schema.json`) is the keystone contract; every JSON
artifact (VULN-FINDINGS.json, TRIAGE.json) and every eval gate validates against it.

CLI:
    uv run --with jsonschema python validate_findings.py TRIAGE.json [--no-dup-ids]

Exit code 0 = valid, 1 = invalid, 2 = usage error.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "reference" / "finding-schema.json"


def load_schema(path: Path = SCHEMA_PATH) -> dict:
    return json.loads(path.read_text())


def validate(doc: dict, schema: dict | None = None) -> list[str]:
    """Return a list of human-readable schema errors (empty list = valid)."""
    schema = schema if schema is not None else load_schema()
    validator = Draft202012Validator(schema)
    return [
        f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
        for e in sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    ]


def duplicate_ids(doc: dict) -> list[str]:
    """Return finding ids that appear more than once."""
    seen: set[str] = set()
    dups: set[str] = set()
    for finding in doc.get("findings", []):
        fid = finding.get("id")
        if fid in seen:
            dups.add(fid)
        seen.add(fid)
    return sorted(dups)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    check_dups = "--no-dup-ids" in argv
    files = [a for a in argv if not a.startswith("-")]
    if not files:
        print("usage: validate_findings.py <findings.json> [--no-dup-ids]")
        return 2

    schema = load_schema()
    rc = 0
    for f in files:
        try:
            doc = json.loads(Path(f).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(f"INVALID {f}: could not read/parse JSON: {exc}")
            rc = 1
            continue
        errors = validate(doc, schema)
        if check_dups:
            errors += [f"duplicate finding id: {d}" for d in duplicate_ids(doc)]
        if errors:
            rc = 1
            print(f"INVALID {f}:")
            for e in errors:
                print(f"  - {e}")
        else:
            print(f"OK {f}")
    return rc


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
