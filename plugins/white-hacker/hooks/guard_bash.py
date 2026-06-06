"""PreToolUse review-posture guard (T-6.4) — sibling to confine_patch_writes.

Enforces the review posture structurally during a scan (Agents Rule of Two: the reviewer is an
injection target, so it must not combine untrusted input + secret access + egress). Denies:
  * destructive Bash (`rm -rf`);
  * git mutation that rewrites/exports the tree (`git push`/`apply`/`am`);
  * any reference to a SECRET file (`.env`, `id_rsa`, `*.pem`/`*.key`, `~/.ssh/**`,
    `~/.aws/credentials`, `.npmrc`/`.pypirc`/`.netrc`) — the agent inspects files with the Read
    tool, never Bash, so this is low-FP for legitimate review;
  * exfil-shaped egress (`curl`/`wget`/`scp`/`nc`/… with a file-upload flag).

Allows benign read-only Bash, `uv run`, `grep`/`cat` of non-secret files, `git status`/`diff`/`log`,
and `.env.example`/`.sample`/`.template` templates.

RESIDUAL RISK: heuristic command parsing (same caveats as confine_patch_writes) — a tripwire, not a
boundary. Composes with confine_patch_writes as a second `hooks.PreToolUse` Bash entry (ADR-016).
Protocol (spike-06): reads the PreToolUse event JSON on stdin; exit 2 = hard block.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys

_SEPARATOR_RE = re.compile(r"\|\||&&|;|\||&|\n")
WRAPPERS = {"timeout", "time", "nice", "nohup", "stdbuf", "env", "sudo", "command", "builtin", "xargs", "\\"}
NET_VERBS = {"curl", "wget", "nc", "ncat", "scp", "sftp", "ssh", "telnet", "socat", "ftp"}

# secret-file references (paths/args). `.env.example|sample|template|dist` are NOT secrets.
SECRET_RE = re.compile(
    r"(?:^|/)\.env(?:$|\.(?!example|sample|template|dist|md)[\w.]+)"
    r"|(?:^|/)(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)\b"
    r"|\.(?:pem|key|p12|pfx|keystore|jks|asc)\b"
    r"|(?:^|/)\.ssh/"
    r"|(?:^|/)\.aws/credentials"
    r"|(?:^|/)\.(?:npmrc|pypirc|netrc)\b",
    re.IGNORECASE,
)
UPLOAD_FLAGS = {"-T", "--upload-file"}


def is_secret_ref(token: str) -> bool:
    return bool(SECRET_RE.search(token.strip().strip("'\"")))


def _tokens(sub: str) -> list[str]:
    try:
        return shlex.split(sub)
    except ValueError:
        return sub.split()


def _verb(tokens: list[str]) -> tuple[str, list[str]]:
    i = 0
    while i < len(tokens) and (tokens[i] in WRAPPERS or os.path.basename(tokens[i]) in WRAPPERS):
        i += 1
    rest = tokens[i:]
    return (os.path.basename(rest[0]) if rest else ""), rest


def _check_sub(sub: str) -> str | None:
    tokens = _tokens(sub)
    if not tokens:
        return None
    verb, rest = _verb(tokens)

    # destructive
    if verb == "rm":
        flags = "".join(t[1:] for t in rest[1:] if t.startswith("-") and not t.startswith("--"))
        longs = {t for t in rest[1:] if t.startswith("--")}
        recursive = "r" in flags or "R" in flags or "--recursive" in longs
        force = "f" in flags or "--force" in longs
        if recursive and force:
            return "destructive `rm -rf` blocked during review"

    # git mutation / export
    if verb == "git":
        gv = rest[1] if len(rest) > 1 else ""
        if gv in {"push", "apply", "am"}:
            return f"`git {gv}` blocked (review is read-only; proposes, never pushes/applies)"

    # secret-file references (anywhere in the command)
    for t in rest:
        if is_secret_ref(t):
            return f"reference to a secret file blocked: {t} (inspect via the Read tool, not Bash)"

    # exfil-shaped egress: a network verb carrying a file upload
    if verb in NET_VERBS:
        for t in rest[1:]:
            if t in UPLOAD_FLAGS:
                return f"egress with file upload blocked: {verb} {t}"
            if t.startswith(("-d", "--data", "-F", "--form")) and "@" in t:
                return f"egress with inline file upload blocked: {verb} {t}"
            if t in ("-d", "--data", "--data-binary", "--data-raw", "-F", "--form"):
                nxt = rest[rest.index(t) + 1] if rest.index(t) + 1 < len(rest) else ""
                if nxt.startswith("@") or "@" in nxt:
                    return f"egress with inline file upload blocked: {verb} {t} {nxt}"

    return None


def decide(event: dict) -> tuple[bool, str]:
    if event.get("tool_name") != "Bash":
        return True, ""
    command = (event.get("tool_input") or {}).get("command", "")
    for sub in _SEPARATOR_RE.split(command):
        sub = sub.strip()
        if not sub:
            continue
        reason = _check_sub(sub)
        if reason:
            return False, reason
    return True, ""


def main(argv: list[str] | None = None) -> int:
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return 0
    allowed, reason = decide(event)
    if not allowed:
        sys.stderr.write(f"[guard_bash] BLOCKED: {reason}\n")
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
