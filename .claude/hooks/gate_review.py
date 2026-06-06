"""Team-mode review gate (T-6.5): block 'review complete' until TRIAGE.json exists.

In team mode the tech-lead must not treat the review as done until white-hacker actually produced
its triaged artifact. On a TaskCompleted / TeammateIdle event this hook checks for `TRIAGE.json` in
the project dir: absent -> block (exit 2) so the lead WAITs; present -> allow and surface ONLY the
summary counts + the report path (never raw discovery). Protocol mirrors spike-06 (stdin event
JSON; exit 2 = block).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def review_status(cwd: str) -> tuple[bool, str]:
    """(complete, message). complete=False blocks; message carries only summary + report path."""
    triage = Path(cwd) / "TRIAGE.json"
    if not triage.exists():
        return False, "review not complete: TRIAGE.json not found — WAIT for white-hacker"
    try:
        doc = json.loads(triage.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"TRIAGE.json present but unreadable: {exc}"
    counts = (doc.get("summary") or {}).get("counts", {})
    report = Path(cwd) / "SECURITY-REPORT.md"
    report_ref = "SECURITY-REPORT.md" if report.exists() else "(report not yet rendered)"
    return True, f"review complete: counts={counts}; report={report_ref}"


def decide(event: dict) -> tuple[bool, str]:
    return review_status(event.get("cwd") or os.getcwd())


def main(argv: list[str] | None = None) -> int:
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        event = {}
    ok, msg = decide(event)
    (sys.stdout if ok else sys.stderr).write(f"[gate_review] {msg}\n")
    return 0 if ok else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
