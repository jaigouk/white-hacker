"""Validate a SCAN-PLAN.json against the canonical scan-plan schema.

Mirrors `_shared/scripts/validate_findings.py`; the schema lives next to the skill
(`../scan-plan-schema.json`). Downstream stages (sec-vuln-scan) and CI can gate on this.

CLI:
    uv run --with jsonschema python validate_scan_plan.py SCAN-PLAN.json

Exit code 0 = valid, 1 = invalid, 2 = usage error.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "scan-plan-schema.json"


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


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    files = [a for a in argv if not a.startswith("-")]
    if not files:
        print("usage: validate_scan_plan.py <SCAN-PLAN.json>")
        return 2

    schema = load_schema()
    rc = 0
    for f in files:
        try:
            doc = json.loads(Path(f).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(f"{f}: cannot read/parse: {exc}")
            rc = 1
            continue
        errors = validate(doc, schema)
        if errors:
            rc = 1
            print(f"{f}: INVALID")
            for err in errors:
                print(f"  - {err}")
        else:
            print(f"{f}: valid")
    return rc


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
