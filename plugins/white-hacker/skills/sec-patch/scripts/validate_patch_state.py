"""Validate a sec-patch PATCH-STATE.json against patch-state-schema.json (T-5.2).

The ladder rungs (build / poc_stopped / tests_passed / reattack) are tri-state
{pass,fail,n/a} — they record what was DEMONSTRATED, not severity (PLAN 6.1).

CLI:
    uv run --with jsonschema python validate_patch_state.py PATCH-STATE.json ...

Exit code 0 = valid, 1 = invalid, 2 = usage error.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "patch-state-schema.json"


def load_schema(path: Path = SCHEMA_PATH) -> dict:
    return json.loads(path.read_text())


def validate(doc: dict, schema: dict | None = None) -> list[str]:
    """Return human-readable schema errors (empty list = valid)."""
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
        print("usage: validate_patch_state.py <PATCH-STATE.json> ...")
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
