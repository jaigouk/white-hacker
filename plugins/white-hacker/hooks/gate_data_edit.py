"""PreToolUse gate on Gate-2 DATA edits (wh-hxt.6; ADR-026 §3): the supply-chain **watchlist**
(`known-compromised.osv.json`) is DATA, not corpus-scorable KB, so it cannot ride the eval-J
keep-or-revert KEEP (`evals/gate-verdict.json`) that `gate_kb_edit.py` consumes — reusing it would
be a *false-merit merge* (ADR-024 §5). This is the CONSUMER of the SEPARATE, content-bound,
one-shot DATA verdict minted by `validate_watchlist.py` (wh-hxt.5) at `evals/data-verdict.json`.

A Write/Edit to a named DATA path is admitted ONLY when that verdict is KEEP **and** its `path`
matches the write target **and** its `sha256` matches a FRESH recompute of the proposed write bytes
— for a Write the bytes are `tool_input.content`; for an Edit the bytes are the POST-EDIT result of
applying `old_string`->`new_string` to the on-disk file (genuinely new logic — gate_kb_edit never
reconstructs Edit content). On a successful admit the verdict is **consumed** (deleted) so a stale
KEEP cannot be replayed for a second, unvalidated write (SEC-Q2 — closes the replay/TOCTOU hole
`gate_kb_edit` leaves open). Anything else (no/empty/unparseable verdict · REVERT · path mismatch ·
sha256 mismatch · missing content/cwd) → **fail-closed block** (exit 2). Non-DATA paths are out of
scope here (other hooks confine them).

HARD ORDERING (SEC-Q3 / QA-#1): this hook MUST be registered before `known-compromised.osv.json`
ever exists (wh-k6l / the feeder) — otherwise a premature watchlist file would be gated by the
WRONG verdict kind (the absent / unrelated eval-J KEEP). This module gates; it does NOT create the
data file.

Policy 5: pure deterministic checks (hashlib + path normalization) — no LLM / RNG / network.
Protocol (spike-06): stdin event JSON; exit 2 = block, exit 0 = allow.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import sys
from pathlib import Path

# Path-SPECIFIC DATA file SUFFIXES (NOT the broad `/_shared/reference/` segment gate_kb_edit uses).
# Matched by exact normalized-path SUFFIX so a sibling `…known-compromised.osv.json.tmp` does NOT
# match. Initially ONLY the watchlist file (QA-#2 — NO placeholder sidecar entry; wh-hxt.4 adds its
# own sidecar path here WITH its own test). This tuple is deliberately DUPLICATED in
# gate_kb_edit.DATA_PATHS (independent PreToolUse hooks; no cross-import coupling — ADR-026 §3).
DATA_SEGMENTS = ("/_shared/reference/known-compromised.osv.json",)

_VERDICT_REL = ("evals", "data-verdict.json")

# Bash write/redirect target extraction (HIGH-2). Copied locally from confine_self_writes (~:56) —
# the hooks stay independent (no cross-import). A shell `>`/`>>` (or a cp/mv/tee/dd/sed -i launder)
# to the watchlist is NEVER a sanctioned mint (the only legitimate path is the validator + a
# content-bound Write under a DATA verdict), so any such target on a DATA path → fail-closed block.
_SEPARATOR_RE = re.compile(r"\|\||&&|;|\||&|\n")
_REDIR_RE = re.compile(r"""(?:^|\s)(?:\d+|&)?>>?\s*("[^"]*"|'[^']*'|[^\s|;&<>]+)""")
_LAUNDER = {"cp", "mv", "install", "ln", "rsync", "tee"}
_WRAPPERS = {"timeout", "time", "nice", "nohup", "stdbuf", "env", "sudo", "command", "xargs", "\\"}


def _norm(p: str) -> str:
    """Canonical forward-slash path with a single leading '/' for SUFFIX matching. normpath FIRST
    (HIGH-1: the OS write + confine_self_writes use realpath, collapsing `//`, `/./`, trailing `/`
    — a raw match would let `…/_shared//reference/known-compromised.osv.json` slip the scope and
    land poison on the canonical inode with no verdict). normpath collapses those before the match;
    `_resolve:62` already did this for the path-equality compare, so the scope check now agrees."""
    p = p.strip().strip("'\"").replace(os.sep, "/")
    p = os.path.normpath(p).replace(os.sep, "/")
    return p if p.startswith("/") else "/" + p


def _is_data_path(p: str) -> bool:
    """True iff `p` (normpath-collapsed) ends with a DATA suffix — exact path-segment suffix, never
    a substring; a `…known-compromised.osv.json.tmp` sibling does NOT match."""
    n = _norm(p)
    return any(n.endswith(seg) for seg in DATA_SEGMENTS)


def _verb_and_args(sub: str) -> tuple[str, list[str]]:
    """The command verb (basename, wrappers like nice/sudo skipped) + its tokens."""
    try:
        toks = shlex.split(sub)
    except ValueError:
        toks = sub.split()
    i = 0
    while i < len(toks) and (toks[i] in _WRAPPERS or os.path.basename(toks[i]) in _WRAPPERS):
        i += 1
    rest = toks[i:]
    return (os.path.basename(rest[0]) if rest else ""), rest


def _bash_write_targets(command: str) -> list[str]:
    """Every write/redirect target in a Bash command (redirects + cp/mv/tee/dd-of= launders).
    Mirrors confine_self_writes._write_targets (~:100), pared to what a watchlist-poisoning write
    could use. Targets are matched against DATA suffixes by the caller (normpath'd in `_is_data_path`)."""
    targets: list[str] = []
    for sub in _SEPARATOR_RE.split(command):
        sub = sub.strip()
        if not sub:
            continue
        targets.extend(m.group(1) for m in _REDIR_RE.finditer(sub))
        verb, rest = _verb_and_args(sub)
        flagless = [t for t in rest[1:] if not t.startswith("-")]
        if verb in _LAUNDER and flagless:
            targets.extend(flagless if verb == "tee" else [flagless[-1]])
        if verb in ("sed", "perl") and any(t == "-i" or t.startswith("-i") for t in rest):
            targets.extend(flagless)
        if verb == "truncate":
            targets.extend(flagless)
        for t in rest:
            if t.startswith("of="):
                targets.append(t[3:])
    return [t.strip().strip("'\"") for t in targets if t.strip().strip("'\"")]


def _resolve(cwd: str, p: str) -> str:
    """Logical absolute path of `p` under `cwd` (normpath join; no realpath — the write target may
    not exist yet). Used to compare the verdict's `path` against the write target path."""
    p = p.strip().strip("'\"")
    if not os.path.isabs(p):
        p = os.path.join(cwd, p)
    return os.path.normpath(p).replace(os.sep, "/")


def _proposed_bytes(event: dict, cwd: str) -> bytes | None:
    """The EXACT bytes the write would land. Write: `tool_input.content`. Edit: the POST-EDIT bytes
    (apply old_string->new_string to the on-disk file under cwd, hash the result). None when the
    bytes cannot be determined (missing content / unreadable on-disk file) → fail-closed upstream."""
    tool = event.get("tool_name", "")
    ti = event.get("tool_input") or {}
    if tool == "Write":
        content = ti.get("content")
        return content.encode("utf-8") if isinstance(content, str) else None
    if tool == "Edit":
        path = ti.get("file_path") or ti.get("path") or ""
        old = ti.get("old_string")
        new = ti.get("new_string")
        if not isinstance(old, str) or not isinstance(new, str):
            return None
        try:
            current = (Path(cwd) / path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        # Mirror Edit semantics: replace old_string with new_string in the on-disk content. (A
        # genuine Edit requires old_string present; if absent the post-edit bytes equal the current
        # bytes and will simply not match the verdict's sha256 → blocked, which is correct.)
        return current.replace(old, new).encode("utf-8")
    return None


def decide(event: dict) -> tuple[bool, str]:
    tool = event.get("tool_name", "")
    ti = event.get("tool_input") or {}

    # Bash channel (HIGH-2): the gate_kb_edit DATA-skip REMOVED gate_kb_edit's old Bash-redirect
    # coverage of the watchlist, so this hook must cover it. A shell `>`/cp/mv/tee/dd to a DATA path
    # is NEVER a sanctioned mint (only the validator + a content-bound Write under a verdict is) —
    # do NOT try to content-bind a redirect; fail-closed block it outright.
    if tool == "Bash":
        for tgt in _bash_write_targets(ti.get("command", "")):
            if _is_data_path(tgt):
                return False, "DATA edit blocked: shell write to the watchlist DATA path is never sanctioned (use the validator + a content-bound Write)"
        return True, ""

    if tool not in ("Write", "Edit"):
        return True, ""  # other tools never write the watchlist → out of scope
    target = ti.get("file_path") or ti.get("path") or ""
    if not _is_data_path(target):
        return True, ""  # not a DATA path → out of this hook's scope

    cwd = event.get("cwd")
    if not cwd:
        return False, "DATA edit blocked: no cwd to locate the data verdict (fail-closed)"

    vp = Path(cwd, *_VERDICT_REL)
    raw = ""
    if vp.exists():
        try:
            raw = vp.read_text(encoding="utf-8")
        except OSError:
            return False, "DATA edit blocked: unreadable data verdict (fail-closed)"
    if not raw.strip():
        return False, "DATA edit blocked: no content-bound data verdict on file (run the validator first)"
    try:
        verdict = json.loads(raw)
    except json.JSONDecodeError:
        return False, "DATA edit blocked: unparseable data verdict (fail-closed)"

    # MED-3: valid JSON that is not an object (`["x"]`, `"x"`, `42`) would make `.get` raise — a
    # non-dict verdict is malformed → fail-closed.
    if not isinstance(verdict, dict):
        return False, "DATA edit blocked: verdict is not a JSON object (fail-closed)"

    if verdict.get("verdict") != "KEEP":
        return False, f"DATA edit blocked: data verdict is {verdict.get('verdict')!r} (only KEEP may land)"

    vpath = verdict.get("path")
    if not isinstance(vpath, str) or _resolve(cwd, vpath) != _resolve(cwd, target):
        return False, "DATA edit blocked: data verdict path does not match the write target"

    proposed = _proposed_bytes(event, cwd)
    if proposed is None:
        return False, "DATA edit blocked: cannot determine the proposed write content (fail-closed)"
    if hashlib.sha256(proposed).hexdigest() != verdict.get("sha256"):
        return False, "DATA edit blocked: write content sha256 does not match the validated bytes (content binding)"

    # One-shot consume (ADR-026 §3): a KEEP admits exactly the one matching write; delete the
    # verdict so the same KEEP cannot be replayed for a second, unvalidated write.
    try:
        vp.unlink()
    except OSError:
        return False, "DATA edit blocked: could not consume the one-shot data verdict (fail-closed)"
    return True, ""


def main(argv: list[str] | None = None) -> int:
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return 0
    # MED-3: ANY unforeseen exception in decide() must fail CLOSED (exit 2) — the hook protocol
    # treats only exit 2 as a block, so an uncaught traceback (exit 1) would read as ALLOW.
    try:
        ok, reason = decide(event)
    except Exception as exc:  # noqa: BLE001 — fail-closed on anything unexpected
        sys.stderr.write(f"[gate_data_edit] BLOCKED: unexpected error, failing closed ({type(exc).__name__})\n")
        return 2
    if not ok:
        sys.stderr.write(f"[gate_data_edit] BLOCKED: {reason}\n")
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
