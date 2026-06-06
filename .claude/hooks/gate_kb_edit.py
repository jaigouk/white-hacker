"""PreToolUse/Stop gate on KB edits (T-9.3): a KB / checklist write is allowed only when the
keep-or-revert gate has produced a KEEP verdict (`evals/gate-verdict.json`).

Belt-and-suspenders to the CI merge gate: an in-session edit to `ai-attack-kb/**` or
`_shared/reference/**` is blocked (exit 2) unless the verdict file says KEEP — so a regressing KB
change cannot land even mid-session. The verdict file is produced by `keep_or_revert.py` (T-9.2)
run in the PR pipeline; it is read-only to the agent.

Protocol (spike-06): stdin event JSON; exit 2 = block.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

GATED_SEGMENTS = ("/ai-attack-kb/", "/_shared/reference/")
_REDIR_RE = re.compile(r"""(?:^|\s)(?:\d+|&)?>>?\s*("[^"]*"|'[^']*'|[^\s|;&<>]+)""")


def _is_gated_path(p: str) -> bool:
    p = p.strip().strip("'\"")
    return any(seg in "/" + p for seg in GATED_SEGMENTS)


def _edits_kb(event: dict) -> bool:
    tool = event.get("tool_name", "")
    ti = event.get("tool_input") or {}
    if tool in ("Write", "Edit", "NotebookEdit"):
        return _is_gated_path(ti.get("file_path") or ti.get("path") or ti.get("notebook_path") or "")
    if tool == "Bash":
        return any(_is_gated_path(m.group(1)) for m in _REDIR_RE.finditer(ti.get("command", "")))
    return False


def decide(event: dict) -> tuple[bool, str]:
    if not _edits_kb(event):
        return True, ""
    vp = Path(event.get("cwd") or ".") / "evals" / "gate-verdict.json"
    if not vp.exists():
        return False, "KB edit blocked: no keep-or-revert verdict on file (run the gate first)"
    try:
        v = json.loads(vp.read_text()).get("verdict")
    except (OSError, json.JSONDecodeError):
        return False, "KB edit blocked: unreadable gate verdict"
    if v == "KEEP":
        return True, ""
    return False, f"KB edit blocked: gate verdict is {v!r} (only a KEEP verdict may land)"


def main(argv: list[str] | None = None) -> int:
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return 0
    ok, reason = decide(event)
    if not ok:
        sys.stderr.write(f"[gate_kb_edit] BLOCKED: {reason}\n")
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
