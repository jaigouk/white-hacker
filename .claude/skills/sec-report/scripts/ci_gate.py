"""CI gate (T-6.2): fail a PR when a findings/triage JSON is too severe.

Validates the document against the canonical finding-schema FIRST, then checks
`summary.counts` against thresholds (default: fail when `high > 0`).

CLI:
    uv run --with jsonschema python ci_gate.py TRIAGE.json [--max-high N] [--max-medium N] [--max-low N]

Exit code 0 = pass, 1 = gate tripped, 2 = usage error / malformed / non-schema JSON.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "_shared" / "reference" / "finding-schema.json"


def load_schema(path: Path = SCHEMA_PATH) -> dict:
    return json.loads(path.read_text())


def schema_errors(doc: dict, schema: dict | None = None) -> list[str]:
    schema = schema if schema is not None else load_schema()
    validator = Draft202012Validator(schema)
    return [
        f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
        for e in sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    ]


def gate(counts: dict, max_high: int = 0, max_medium: int | None = None,
         max_low: int | None = None) -> list[str]:
    """Return a list of tripped thresholds (empty = pass)."""
    over: list[str] = []
    if counts.get("high", 0) > max_high:
        over.append(f"high={counts.get('high', 0)} > max-high={max_high}")
    if max_medium is not None and counts.get("medium", 0) > max_medium:
        over.append(f"medium={counts.get('medium', 0)} > max-medium={max_medium}")
    if max_low is not None and counts.get("low", 0) > max_low:
        over.append(f"low={counts.get('low', 0)} > max-low={max_low}")
    return over


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="ci_gate.py", add_help=True)
    parser.add_argument("file")
    parser.add_argument("--max-high", type=int, default=0)
    parser.add_argument("--max-medium", type=int, default=None)
    parser.add_argument("--max-low", type=int, default=None)
    try:
        ns = parser.parse_args(argv)
    except SystemExit:
        return 2

    try:
        doc = json.loads(Path(ns.file).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"INVALID {ns.file}: could not read/parse JSON: {exc}")
        return 2

    errors = schema_errors(doc)
    if errors:
        print(f"INVALID {ns.file}: does not conform to finding-schema:")
        for e in errors[:5]:
            print(f"  - {e}")
        return 2

    over = gate(doc["summary"]["counts"], ns.max_high, ns.max_medium, ns.max_low)
    if over:
        print(f"GATE FAILED ({ns.file}): " + "; ".join(over))
        return 1
    print(f"GATE PASSED ({ns.file}): counts within thresholds")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
