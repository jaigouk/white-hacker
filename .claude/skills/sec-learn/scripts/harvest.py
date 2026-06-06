"""Collate capture-hook traces into the sec-learn reflection input (T-8.5).

Reads `evals/traces/findings-*.jsonl` (append-only, redacted — T-8.3) and groups the rows into
corrections, failed exploits, and tool calls, with per-session counts. Deterministic, no LLM, no
network. The reflective reasoning runs on this collated input.

CLI:
    uv run python harvest.py <traces-dir>   # prints the collated reflection input as JSON
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


def harvest(traces_dir) -> dict:
    rows: list[dict] = []
    for f in sorted(Path(traces_dir).glob("findings-*.jsonl")):
        for line in f.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    corrections = [r for r in rows if r.get("kind") == "correction"]
    failed = [r for r in rows if r.get("kind") == "failed_exploit"]
    by_session = Counter(r.get("session", "") for r in rows)
    return {
        "total_rows": len(rows),
        "corrections": corrections,
        "failed_exploits": failed,
        "by_session": dict(by_session),
        "sessions": sorted(by_session),
    }


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: harvest.py <traces-dir>")
        return 2
    print(json.dumps(harvest(argv[0]), indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
