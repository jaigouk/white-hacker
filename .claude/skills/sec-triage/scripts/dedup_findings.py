"""Deterministic dedup pass for findings (T-1.4).

Rule of thumb: "two findings are duplicates if fixing one fixes the other." This is the cheap,
deterministic first pass — same `file` + same `category` + lines within a window collapse to a
single canonical finding; duplicates get `canonical_of` set to the canonical's id. The harder
cross-file semantic pass is the LLM's job in `sec-triage` (documented in SKILL.md).

Guarantees: every finding still appears once in the list; duplicates reference a canonical id;
the operation is idempotent; `summary.counts` is recomputed over canonical findings only.

CLI:  uv run python dedup_findings.py VULN-FINDINGS.json [-o TRIAGE.json] [--window N]
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

LINE_WINDOW = 10


def dedup(doc: dict, window: int = LINE_WINDOW) -> dict:
    """Return a copy of `doc` with deterministic duplicates collapsed via `canonical_of`."""
    doc = copy.deepcopy(doc)
    findings = doc.get("findings", [])
    canonicals: list[dict] = []  # findings that remain canonical (canonical_of is None)

    for f in findings:
        if f.get("canonical_of") is not None:
            # Already marked a duplicate by a prior pass — preserve the mapping (idempotency).
            continue
        match = next(
            (
                c for c in canonicals
                if f["file"] == c["file"]
                and f["category"] == c["category"]
                and abs(f["line"] - c["line"]) <= window
                and f["id"] != c["id"]
            ),
            None,
        )
        if match is None:
            canonicals.append(f)
        else:
            f["canonical_of"] = match["id"]

    # Recompute counts over canonical findings only (unique findings).
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.get("canonical_of") is None:
            counts[f["severity"].lower()] += 1
    if "summary" in doc and isinstance(doc["summary"], dict) and "counts" in doc["summary"]:
        doc["summary"]["counts"] = counts
    return doc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Deterministic dedup of a findings document.")
    p.add_argument("infile")
    p.add_argument("-o", "--out", help="write result here (default: stdout)")
    p.add_argument("--window", type=int, default=LINE_WINDOW)
    args = p.parse_args(argv)

    doc = json.loads(Path(args.infile).read_text())
    result = dedup(doc, window=args.window)
    out = json.dumps(result, indent=2)
    if args.out:
        Path(args.out).write_text(out + "\n")
    else:
        print(out)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
