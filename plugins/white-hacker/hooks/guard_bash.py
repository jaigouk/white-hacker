"""PreToolUse review-posture guard (T-6.4) — sibling to confine_patch_writes.

Enforces the review posture structurally during a scan (Agents Rule of Two: the reviewer is an
injection target, so it must not combine untrusted input + secret access + egress). Denies:
  * destructive Bash (`rm -rf`);
  * git mutation that rewrites/exports the tree (`git push`/`apply`/`am`);
  * any reference to a SECRET file (`.env`, `id_rsa`, `*.pem`/`*.key`, `~/.ssh/**`,
    `~/.aws/credentials`, `.npmrc`/`.pypirc`/`.netrc`) — the agent inspects files with the Read
    tool, never Bash, so this is low-FP for legitimate review;
  * exfil-shaped egress (`curl`/`wget`/`scp`/`nc`/… with a file-upload flag);
  * active-scan verbs (`nmap`/`masscan`/`zmap`) — network scanning is outside the read-only
    working-tree review posture (ADR-031 C5);
  * cloud-mutation verbs (`aws`/`gcloud`/`az`/`terraform`/`kubectl`/`helm`/`pulumi`) — live
    infrastructure mutation is outside the authorized review scope (ADR-031 C1).

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
ACTIVE_SCAN_VERBS = {"nmap", "masscan", "zmap"}
CLOUD_MUTATION_VERBS = {"aws", "gcloud", "az", "terraform", "kubectl", "helm", "pulumi"}

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
    """Return (bare_verb, rest) after stripping leading wrapper tokens.

    Skips wrapper tokens (sudo/nice/timeout/…) together with any option-flags
    and their arguments that belong to the wrapper (e.g. ``nice -n 10``).
    """
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in WRAPPERS or os.path.basename(tok) in WRAPPERS:
            i += 1
            # skip option flags belonging to this wrapper (e.g. -n 10, --adjustment 10)
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 1
                # skip the option's argument if it looks like a value (not a flag or a verb)
                if i < len(tokens) and not tokens[i].startswith("-"):
                    i += 1
        else:
            break
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

    # active network scanning — outside the read-only working-tree review posture (ADR-031 C5)
    if verb in ACTIVE_SCAN_VERBS:
        return (
            f"`{verb} ...` blocked during review "
            f"(active network scan is out of the read-only review scope)"
        )

    # cloud / infra mutation — outside the authorized review scope (ADR-031 C1)
    if verb in CLOUD_MUTATION_VERBS:
        if verb == "az":
            verb_label = "Azure CLI `az`"
        else:
            verb_label = f"`{verb}`"
        return (
            f"{verb_label} blocked during review "
            f"(cloud/infra mutation is out of the read-only review scope)"
        )

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
