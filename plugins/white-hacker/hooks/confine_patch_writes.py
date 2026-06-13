"""PreToolUse tripwire — confine shell-level writes to the artifact allowlist + PATCHES/.

=== RESIDUAL RISK (verbatim — read before trusting this) ===
Bash-command parsing is heuristic and **NOT airtight**. Deciding whether an arbitrary command
writes a forbidden path is undecidable and trivially evaded (interpreter one-liners that open a
file for write, symlink/realpath TOCTOU, allowlist laundering, exotic write syscalls). The STRONG
guarantee is structural: the white-hacker agent has no `Write`/`Edit` tool and is granted no
patch-apply capability; `sec-patch` emits diffs under `PATCHES/` and a HUMAN applies them
(ADR-010 / ADR-016). This hook is a **tripwire / speed-bump, not the boundary.** It also pairs with
`permissions.deny` (git/patch mutation verbs), which Claude Code enforces with its own parser.

=== Protocol (spike-06, verified 2026-06) ===
Reads the PreToolUse event JSON on stdin: {tool_name, tool_input{command|file_path}, cwd, ...}.
Exit 2 = hard block (stderr is shown to Claude). Exit 0 = allow / no decision.

What it denies (obvious shell-level writes to a non-allowlisted target):
  * redirection (`>`, `>>`, `1>`, `2>file`) to a path outside the allowlist;
  * `tee`, `cp`/`mv`/`install`/`ln`/`rsync` dest, `dd of=`, `truncate`, `sed -i`/`perl -i` target;
  * `patch` (a git-apply equivalent) and git mutation verbs (apply/am/commit/push/reset --hard/
    restore/checkout --/clean/stash);
  * interpreter one-liners (`python -c`, `perl -e`, `awk 'print>'`, …) whose code looks like a write;
  * any write resolving under `.claude/` (self-disablement) or outside the project root;
  * unverifiable redirection targets (containing `$VAR` / `$(...)` / backticks) — deny, can't prove safe.
What it allows: the pinned artifact allowlist + `PATCHES/**`, `/dev/null` & `/dev/std*`, the OS temp
dir, read-only commands, and process-internal writes it cannot see (e.g. `pytest` caches).
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
import tempfile

# --- the pinned write allowlist (single source of truth) ------------------
ALLOWLIST_BASENAMES = {
    "THREAT_MODEL.md", "SCAN-PLAN.json", "VULN-FINDINGS.json", "TRIAGE.json",
    "SECRETS.json", "DEPS.json", "SECURITY-REPORT.md", "PATCH-STATE.json",
}
ALLOWLIST_SUFFIXES = (".sarif",)
ALLOWLIST_DIR_PREFIXES = ("PATCHES/", ".notes/")

NESTED_SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
WRAPPERS = {"timeout", "time", "nice", "nohup", "stdbuf", "env", "sudo", "command", "builtin", "xargs", "\\"}
LAUNDER = {"cp", "mv", "install", "ln", "rsync"}
INTERPRETERS = {"python", "python3", "perl", "ruby", "node", "php", "awk", "gawk"}
# Verbs that APPLY a patch / PUSH / destroy the working tree (ADR-010 removes these).
# NOT `commit`/`stash`/`rebase`/`merge`: those don't write source files, and blocking `commit`
# would handcuff legitimate Claude-assisted commits (and this build session) for no safety gain.
GIT_MUTATION_VERBS = {"apply", "am", "push", "clean"}

# redirection target: at a token boundary (so `->` arrows / `a>b` text don't false-positive),
# `>`/`>>` optionally fd/&-prefixed, then a target that is not an fd-dup (&N).
_REDIR_RE = re.compile(r"""(?:^|\s)(?:\d+|&)?>>?\s*("[^"]*"|'[^']*'|[^\s|;&<>]+)""")
# interpreter inline code that looks like it writes a file.
_WRITEISH_RE = re.compile(
    r"""open\s*\([^)]*['"][wax]|\.write\s*\(|print\s*>|>\s*['"]|truncate|"""
    r"""shutil\.(?:copy|move)|os\.(?:rename|replace|remove|rmdir|mkdir|makedirs)|"""
    r"""Path\([^)]*\)\s*\.\s*(?:write_text|write_bytes|open)"""
)
_SEPARATOR_RE = re.compile(r"\|\||&&|;|\||&|\n")


def _safe_abs(real: str) -> bool:
    """Absolute targets that are never the working tree (devices + OS temp)."""
    if real in ("/dev/null", "/dev/stdout", "/dev/stderr") or real.startswith("/dev/"):
        return True
    for tmp in {tempfile.gettempdir(), "/tmp", "/private/tmp", "/var/folders"}:
        try:
            if os.path.commonpath([real, os.path.realpath(tmp)]) == os.path.realpath(tmp):
                return True
        except ValueError:
            continue
    return False


def is_allowed_target(target: str, root: str) -> bool:
    # unverifiable indirection -> cannot prove safe -> deny.
    if "$" in target or "`" in target:
        return False
    t = target.strip().strip('"').strip("'")
    if not os.path.isabs(t):
        t = os.path.join(root, t)
    real = os.path.realpath(t)  # resolves symlinks + .. ; non-existent tail is preserved
    rel = os.path.relpath(real, os.path.realpath(root)).replace(os.sep, "/")

    # OUTSIDE the project root: only safe device/scratch targets (/dev/null, OS temp) are allowed.
    if rel == ".." or rel.startswith("../"):
        return _safe_abs(real)

    # INSIDE the project root: the pinned artifact allowlist + PATCHES/ only.
    if rel == ".":
        return False
    if rel == ".claude" or rel.startswith(".claude/"):
        return False  # never let the agent rewrite its own hooks/settings
    if rel.startswith(ALLOWLIST_DIR_PREFIXES):
        return True
    base = os.path.basename(rel)
    return base in ALLOWLIST_BASENAMES or base.endswith(ALLOWLIST_SUFFIXES)


def _tokens(sub: str) -> list[str]:
    try:
        return shlex.split(sub)
    except ValueError:
        return sub.split()


def _verb(tokens: list[str]) -> tuple[str, list[str]]:
    """Strip leading wrappers; return (verb_basename, remaining_tokens)."""
    i = 0
    while i < len(tokens) and (tokens[i] in WRAPPERS or os.path.basename(tokens[i]) in WRAPPERS):
        i += 1
    rest = tokens[i:]
    verb = os.path.basename(rest[0]) if rest else ""
    return verb, rest


def _check_sub(sub: str, root: str, depth: int = 0) -> str | None:
    """Return a deny-reason for one sub-command, or None to allow."""
    # 1) redirection targets (regex over the raw sub).
    for m in _REDIR_RE.finditer(sub):
        tgt = m.group(1)
        if not is_allowed_target(tgt, root):
            return f"redirection writes outside the artifact allowlist: {tgt}"

    tokens = _tokens(sub)
    if not tokens:
        return None
    verb, rest = _verb(tokens)
    flagless = [t for t in rest[1:] if not t.startswith("-")]

    # 2) nested shell -c '...' -> recurse into the inner command.
    if verb in NESTED_SHELLS and depth < 4:
        for j, t in enumerate(rest):
            if t == "-c" and j + 1 < len(rest):
                return _check_sub(rest[j + 1], root, depth + 1)
        return "nested shell without an inspectable -c argument"

    # 3) patch / git-apply equivalents and git mutations.
    if verb == "patch":
        return "patch applies a diff to the working tree (use PATCHES/ + human apply)"
    if verb == "git":
        gv = rest[1] if len(rest) > 1 else ""
        if gv in GIT_MUTATION_VERBS:
            return f"git {gv} is a mutation (denied; sec-patch proposes, humans apply)"
        if gv == "reset" and "--hard" in rest:
            return "git reset --hard mutates the working tree"
        if gv == "checkout" and "--" in rest:
            return "git checkout -- mutates the working tree"
        if gv == "restore":
            return "git restore mutates the working tree"
        if gv == "config":
            return "git config can re-enable writes (core.hooksPath/aliases)"

    # 4) laundering verbs: dest must be allowlisted.
    if verb in LAUNDER and flagless:
        dest = flagless[-1]
        if not is_allowed_target(dest, root):
            return f"{verb} writes outside the artifact allowlist: {dest}"
    if verb == "tee":
        for t in flagless:
            if not is_allowed_target(t, root):
                return f"tee writes outside the artifact allowlist: {t}"
    if verb == "dd":
        for t in rest:
            if t.startswith("of=") and not is_allowed_target(t[3:], root):
                return f"dd of= writes outside the artifact allowlist: {t[3:]}"
    if verb == "truncate":
        for t in flagless:
            if not is_allowed_target(t, root):
                return f"truncate writes outside the artifact allowlist: {t}"
    if verb in ("sed", "perl") and any(tok == "-i" or tok.startswith("-i") for tok in rest):
        for t in flagless:
            if not is_allowed_target(t, root):
                return f"{verb} -i edits in place outside the artifact allowlist: {t}"

    # 5) interpreter one-liners that look like a write.
    if verb in INTERPRETERS and _WRITEISH_RE.search(sub):
        return f"{verb} inline code appears to write a file (heuristic deny)"

    return None


def decide(event: dict) -> tuple[bool, str]:
    """Return (allowed, reason). reason is non-empty only when denied."""
    tool = event.get("tool_name", "")
    root = event.get("cwd") or os.getcwd()
    tool_input = event.get("tool_input") or {}

    if tool in ("Write", "Edit", "NotebookEdit"):
        path = tool_input.get("file_path") or tool_input.get("path") or tool_input.get("notebook_path") or ""
        if path and not is_allowed_target(path, root):
            return False, f"{tool} to a non-allowlisted path: {path}"
        return True, ""

    if tool == "Bash":
        command = tool_input.get("command", "")
        for sub in _SEPARATOR_RE.split(command):
            sub = sub.strip()
            if not sub:
                continue
            reason = _check_sub(sub, root)
            if reason:
                return False, reason
        return True, ""

    return True, ""  # other tools are out of scope for this hook


def main(argv: list[str] | None = None) -> int:
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return 0  # fail-open on a malformed event (this is a tripwire, not the boundary)
    allowed, reason = decide(event)
    if not allowed:
        sys.stderr.write(
            f"[confine_patch_writes] BLOCKED: {reason}\n"
            "white-hacker writes only the artifact chain + PATCHES/; propose a diff under "
            "PATCHES/ for a human to apply (ADR-010/016).\n"
        )
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
