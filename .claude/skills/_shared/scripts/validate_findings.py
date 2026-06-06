"""Validate a white-hacker findings document against the canonical schema.

The schema (`../reference/finding-schema.json`) is the keystone contract; every JSON
artifact (VULN-FINDINGS.json, TRIAGE.json) and every eval gate validates against it.

CLI:
    uv run --with jsonschema python validate_findings.py TRIAGE.json [--no-dup-ids] \
        [--check-kb-refs <ai-attack-kb-reference-dir>]

`--check-kb-refs` asserts every finding's `kb_refs` id resolves to an actual KB entry
`id` in the given directory (T-4.6) — a dangling reference fails the document.

Exit code 0 = valid, 1 = invalid, 2 = usage error.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "reference" / "finding-schema.json"

# Front-matter `id:` line of an ai-attack-kb entry. Parsed without pyyaml to keep this
# validator dependency-light (jsonschema only). Ids are unquoted AISEC-… tokens.
_KB_ID_RE = re.compile(r"^id:\s*[\"']?(AISEC-[A-Z0-9-]+)[\"']?\s*$", re.MULTILINE)


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


def kb_entry_ids(kb_dir: Path) -> set[str]:
    """Collect the `id`s of every ai-attack-kb entry under `kb_dir` (front-matter scan)."""
    ids: set[str] = set()
    kb_dir = Path(kb_dir)
    for f in sorted(kb_dir.glob("*.md")):
        # only scan the leading front-matter block (between the first two `---` fences)
        text = f.read_text()
        front = text.split("---", 2)[1] if text.startswith("---") else text
        m = _KB_ID_RE.search(front)
        if m:
            ids.add(m.group(1))
    return ids


def unresolved_kb_refs(doc: dict, kb_ids: set[str]) -> list[str]:
    """Return human-readable errors for finding `kb_refs` that don't resolve to a KB id."""
    errors: list[str] = []
    for finding in doc.get("findings", []):
        for ref in finding.get("kb_refs", []):
            if ref not in kb_ids:
                errors.append(f"finding {finding.get('id')}: kb_ref {ref!r} does not resolve to a KB entry")
    return errors


def _parse_args(argv: list[str]) -> tuple[list[str], bool, str | None]:
    """Return (files, check_dups, kb_dir). Handles `--check-kb-refs <dir>` consuming its value."""
    files: list[str] = []
    check_dups = False
    kb_dir: str | None = None
    it = iter(argv)
    for a in it:
        if a == "--no-dup-ids":
            check_dups = True
        elif a == "--check-kb-refs":
            kb_dir = next(it, None)
        elif a.startswith("--check-kb-refs="):
            kb_dir = a.split("=", 1)[1]
        elif a.startswith("-"):
            continue  # unknown flag: ignore
        else:
            files.append(a)
    return files, check_dups, kb_dir


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    files, check_dups, kb_dir = _parse_args(argv)
    if not files:
        print("usage: validate_findings.py <findings.json> [--no-dup-ids] [--check-kb-refs <kb-dir>]")
        return 2

    kb_ids: set[str] | None = None
    if kb_dir is not None:
        if not Path(kb_dir).is_dir():
            print(f"usage: --check-kb-refs dir not found: {kb_dir}")
            return 2
        kb_ids = kb_entry_ids(Path(kb_dir))

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
        if kb_ids is not None:
            errors += unresolved_kb_refs(doc, kb_ids)
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
