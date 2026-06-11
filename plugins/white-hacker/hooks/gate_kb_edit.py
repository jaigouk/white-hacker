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
import os
import re
import sys
from pathlib import Path

GATED_SEGMENTS = ("/ai-attack-kb/", "/_shared/reference/")
# Gate-2 DATA paths (wh-hxt.6; ADR-026 §3): these named DATA files inside /_shared/reference/ are
# governed by the content-bound, one-shot `evals/data-verdict.json` (gate_data_edit.py), NOT by this
# corpus-scored eval-J KEEP — reusing the KB verdict for a DATA row would be a false-merit merge
# (ADR-024 §5). They are excluded here (checked by exact path SUFFIX, BEFORE the GATED_SEGMENTS
# substring test) so a DATA write is not double-gated by the KB verdict. Deliberately DUPLICATED
# from gate_data_edit.DATA_SEGMENTS — independent PreToolUse hooks, no cross-import coupling
# (ADR-026 §3); revisit only at a 3rd DATA consumer.
DATA_PATHS = ("/_shared/reference/known-compromised.osv.json",)
# wh-hxt.15: `>>?\|?` — _REDIR_RE accepts a `>|` noclobber-override. This hook has NO _SEPARATOR_RE
# (it runs _REDIR_RE.finditer on the WHOLE command at :61), so the REDIR arm alone closes `>|` — no
# lookbehind is needed (and `>>?` requires a literal `>`, so `\|?` can't false-match a plain pipe).
_REDIR_RE = re.compile(r"""(?:^|\s)(?:\d+|&)?>>?\|?\s*("[^"]*"|'[^']*'|[^\s|;&<>]+)""")


def _norm(p: str) -> str:
    """Canonical forward-slash path with a single leading '/'. normpath FIRST (HIGH-1: the OS write
    + confine_self_writes use realpath, collapsing `//`, `/./`, trailing `/` — without this a
    `…/_shared//reference/known-compromised.osv.json` variant would dodge BOTH the DATA-skip and the
    GATED_SEGMENTS substring test and escape every gate)."""
    p = p.strip().strip("'\"").replace("\\", "/")
    p = os.path.normpath(p).replace(os.sep, "/")
    return p if p.startswith("/") else "/" + p


def _is_data_path(p: str) -> bool:
    """True iff `p` (normpath-collapsed) ends with a Gate-2 DATA suffix (exact suffix, not substring
    — a sibling `…known-compromised.osv.json.tmp` is NOT a DATA path and stays KB-gated)."""
    n = _norm(p)
    return any(n.endswith(seg) for seg in DATA_PATHS)


def _is_gated_path(p: str) -> bool:
    n = _norm(p)
    if any(n.endswith(seg) for seg in DATA_PATHS):  # DATA paths → gate_data_edit's lane, not KB
        return False
    return any(seg in n for seg in GATED_SEGMENTS)


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
