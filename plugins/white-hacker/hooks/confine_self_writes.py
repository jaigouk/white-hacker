"""PreToolUse outer-loop confinement (T-8.4): keep self-improvement writes in their lane.

The outer loop (sec-learn / sec-kb-refresh) may write ONLY:
  * `ai-attack-kb/**` (the fast KB tier), `.claude/rules/**`, `PATCHES/**`, `evals/traces/**`,
    and the auto-memory dir.
It must NOT write:
  * source / working tree, `evals/corpus/**` or the gate scripts (`keep_or_revert.py`,
    `baseline.json`, `score.py`, `label-schema.json`) — the frozen eval is a SEPARATE, read-only
    identity (si-08 §3.4); its OWN control/identity files (self-disablement) — settings,
    hook registration (`hooks.json`), and plugin/marketplace manifests
    (`plugin.json`/`marketplace.json`, anything under `.claude-plugin/`), wherever the layout
    (thin `.claude/` or distributed `plugins/`) places them.
It also (via guard_bash) blocks secret-file reads, destructive Bash, git mutation, and exfil egress,
and restricts network egress to the **allow-listed feed hosts** (si-07).

RESIDUAL RISK: heuristic Bash parsing (same caveats as confine_patch_writes) — a tripwire, not the
boundary; composes as a 3rd PreToolUse Bash entry. Protocol (spike-06): stdin event; exit 2 = block.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys

import guard_bash as gb

FROZEN_BASENAMES = {"keep_or_revert.py", "baseline.json", "score.py", "label-schema.json"}
# Self-disablement / identity control files: once distributed as a plugin the agent must not be
# able to rewrite its OWN harness wiring (settings, hook registration, plugin/marketplace manifests)
# regardless of where the layout puts them. Matched by basename + the plugin-manifest dir marker.
CONTROL_BASENAMES = {
    "settings.json", "settings.local.json", "hooks.json", "plugin.json", "marketplace.json",
}
# Writable lane. NOTE: `.claude/rules/` is intentionally EXCLUDED — identity preservation (T-9.4,
# si-08 §5.2) protects the agent role / rules / CLAUDE.md, which supersedes the broader T-8.4
# allow-set. `_shared/reference/` is in the lane so sec-learn can PROPOSE checklist/tool-registry
# diffs (PR-gated); the identity files are denied because they are not in any allow segment.
ALLOW_SEGMENTS = ("/ai-attack-kb/", "/_shared/reference/", "/PATCHES/", "/evals/traces/")
FEED_HOSTS = {
    "api.osv.dev", "storage.googleapis.com", "api.github.com", "raw.githubusercontent.com",
    "github.com", "export.arxiv.org", "rss.arxiv.org", "arxiv.org", "genai.owasp.org",
    "owasp.org", "cheatsheetseries.owasp.org", "csrc.nist.gov", "www.nist.gov",
    "modelcontextprotocol.io", "embracethered.com", "simonwillison.net",
}
_SEPARATOR_RE = re.compile(r"\|\||&&|;|\||&|\n")
_REDIR_RE = re.compile(r"""(?:^|\s)(?:\d+|&)?>>?\s*("[^"]*"|'[^']*'|[^\s|;&<>]+)""")
_URL_RE = re.compile(r"https?://([^/\s'\"]+)", re.IGNORECASE)
LAUNDER = {"cp", "mv", "install", "ln", "rsync", "tee"}
NET_VERBS = {"curl", "wget", "nc", "ncat", "scp", "sftp", "ssh", "telnet", "socat", "ftp"}
WRAPPERS = {"timeout", "time", "nice", "nohup", "stdbuf", "env", "sudo", "command", "xargs", "\\"}


def is_write_allowed(target: str, root: str) -> bool:
    if "$" in target or "`" in target:
        return False
    t = target.strip().strip("'\"")
    if not os.path.isabs(t):
        t = os.path.join(root, t)
    real = os.path.realpath(t)
    realn = real.replace(os.sep, "/")
    rel = os.path.relpath(real, os.path.realpath(root)).replace(os.sep, "/")
    if rel == ".." or rel.startswith("../"):  # outside repo root
        return "/memory/" in realn or real in ("/dev/null", "/dev/stdout", "/dev/stderr")
    norm = "/" + rel
    if rel.startswith("evals/corpus/") or "/evals/corpus/" in norm:  # frozen corpus
        return False
    if os.path.basename(rel) in FROZEN_BASENAMES:                    # frozen gate scripts
        return False
    if (                                                            # self-disablement
        os.path.basename(rel) in CONTROL_BASENAMES
        or "/.claude-plugin/" in norm
        or rel.startswith(".claude/settings")
    ):
        return False
    return any(seg in norm for seg in ALLOW_SEGMENTS)


def _verb_and_args(sub: str) -> tuple[str, list[str]]:
    try:
        toks = shlex.split(sub)
    except ValueError:
        toks = sub.split()
    i = 0
    while i < len(toks) and (toks[i] in WRAPPERS or os.path.basename(toks[i]) in WRAPPERS):
        i += 1
    rest = toks[i:]
    return (os.path.basename(rest[0]) if rest else ""), rest


def _write_targets(sub: str) -> list[str]:
    targets = [m.group(1) for m in _REDIR_RE.finditer(sub)]
    verb, rest = _verb_and_args(sub)
    flagless = [t for t in rest[1:] if not t.startswith("-")]
    if verb in LAUNDER and flagless:
        if verb == "tee":
            targets.extend(flagless)
        else:
            targets.append(flagless[-1])
    if verb in ("sed", "perl") and any(t == "-i" or t.startswith("-i") for t in rest):
        targets.extend(flagless)
    if verb == "truncate":
        targets.extend(flagless)
    for t in rest:
        if t.startswith("of="):
            targets.append(t[3:])
    return [t for t in targets if t]


def _egress_violation(sub: str) -> str | None:
    verb, rest = _verb_and_args(sub)
    if verb not in NET_VERBS:
        return None
    hosts = _URL_RE.findall(sub)
    if not hosts:
        return f"network egress with no verifiable host: {verb}"
    for h in hosts:
        host = h.split("@")[-1].split(":")[0].lower()
        if host not in FEED_HOSTS:
            return f"egress to non-feed host blocked: {host}"
    return None


def decide(event: dict) -> tuple[bool, str]:
    # 1) compose the review-posture guard (secret reads, exfil, rm -rf, git mutation)
    allowed, reason = gb.decide(event)
    if not allowed:
        return False, f"guard_bash: {reason}"

    tool = event.get("tool_name", "")
    root = event.get("cwd") or os.getcwd()
    ti = event.get("tool_input") or {}

    if tool in ("Write", "Edit", "NotebookEdit"):
        path = ti.get("file_path") or ti.get("path") or ti.get("notebook_path") or ""
        if path and not is_write_allowed(path, root):
            return False, f"{tool} outside the self-improvement write lane: {path}"
        return True, ""

    if tool == "Bash":
        for sub in _SEPARATOR_RE.split(ti.get("command", "")):
            sub = sub.strip()
            if not sub:
                continue
            ev = _egress_violation(sub)
            if ev:
                return False, ev
            for tgt in _write_targets(sub):
                if not is_write_allowed(tgt, root):
                    return False, f"write outside the self-improvement lane: {tgt}"
    return True, ""


def main(argv: list[str] | None = None) -> int:
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return 0
    allowed, reason = decide(event)
    if not allowed:
        sys.stderr.write(f"[confine_self_writes] BLOCKED: {reason}\n")
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
