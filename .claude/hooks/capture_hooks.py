"""Deterministic capture hooks (T-8.3): the outer loop's trace input. Async, ~0 cost, no LLM.

Modes map to Claude Code hook events:
  trace           (PostToolUse)        -> append the tool call to the monthly JSONL
  failed_exploit  (PostToolUse, error) -> append a failed exploit/scan attempt
  correction      (UserPromptSubmit)   -> append a user correction
  cve_digest      (SessionStart)       -> emit the freshness digest on stdout (injected into context)
  learnings_nudge (Stop / SessionEnd)  -> emit a 'run /sec-learn' nudge on stdout

Append-only JSONL at `<cwd>/evals/traces/findings-YYYY-MM.jsonl`. SECRET REDACTION: no secret VALUE
is ever written to a trace line (api keys, bearer tokens, long high-entropy strings -> [REDACTED]).
Protocol (spike-06): event JSON on stdin; these are non-blocking (always exit 0).
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import sys
from pathlib import Path

SECRET_RE = re.compile(
    r"sk-[A-Za-z0-9_\-]{8,}"           # OpenAI-style (incl. sk-proj-/sk-live-)
    r"|AKIA[0-9A-Z]{16}"               # AWS access key id
    r"|ghp_[A-Za-z0-9]{20,}"           # GitHub PAT
    r"|Bearer\s+[A-Za-z0-9._\-]{8,}"   # bearer tokens
    r"|[A-Za-z0-9+/]{32,}={0,2}"       # long high-entropy base64-ish blobs
)


def redact(value) -> str:
    s = value if isinstance(value, str) else json.dumps(value)
    return SECRET_RE.sub("[REDACTED]", s)


def _traces_dir(event: dict) -> Path:
    return Path(event.get("cwd") or ".") / "evals" / "traces"


def _month(event: dict) -> str:
    return event.get("_month") or _dt.date.today().strftime("%Y-%m")


def append_trace(event: dict, kind: str) -> Path:
    d = _traces_dir(event)
    d.mkdir(parents=True, exist_ok=True)
    ti = event.get("tool_input") or {}
    line = {
        "kind": kind,
        "tool": event.get("tool_name"),
        "target": redact(str(ti.get("command") or ti.get("file_path") or "")),
        "session": event.get("session_id", ""),
    }
    if kind == "failed_exploit":
        line["error"] = redact(str(event.get("tool_response") or event.get("error") or ""))
    if kind == "correction":
        line["correction"] = redact(str(event.get("prompt") or event.get("user_message") or ""))
    f = d / f"findings-{_month(event)}.jsonl"
    with f.open("a") as fh:
        fh.write(json.dumps(line) + "\n")
    return f


def cve_digest(event: dict) -> str:
    p = Path(event.get("cwd") or ".") / "evals" / "cve-digest.txt"
    return p.read_text() if p.exists() else ""


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    mode = argv[0] if argv else ""
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return 0
    if mode in ("trace", "failed_exploit", "correction"):
        append_trace(event, mode)
    elif mode == "cve_digest":
        sys.stdout.write(cve_digest(event))
    elif mode == "learnings_nudge":
        sys.stdout.write("Reminder: run /sec-learn to reflect on this session's FPs/misses "
                         "(proposes dated diffs behind the eval gate; never auto-merges).\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
