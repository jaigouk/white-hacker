"""IDE/agent config-persistence floor — OFFLINE, static, behind the ide-hygiene capability.

A supply-chain payload (the Hades / Shai-Hulud / Miasma class) does not only trojanize a
*dependency*; it writes an auto-exec directive into a target repo's on-disk **assistant /
editor config** so the *target's* tooling runs a dropper the moment the folder is opened or a
session starts — persistence that no dependency-level SCA gate (deps-scan) sees. This module
is the deterministic FLOOR that covers that gap. It is the enforceable arm of `ai-llm-review`
§9 (`_shared/reference/ai-llm.md` §9 "AI-assistant config-file poisoning"), which today is
model-judgment only. It parses two config families and fires a high-confidence,
`tool_assisted:false`, signal-not-block candidate when an AUTO-EXEC trigger references a
PRIMARY-SOURCED dropper basename:

  1. `.vscode/tasks.json` — a task whose `runOptions.runOn == "folderOpen"` AUTO-RUNS when the
     folder opens (official VS Code Tasks docs, "Run behavior" / `runOptions`:
     https://code.visualstudio.com/docs/editor/tasks). FIRE when such a task's `command`/`args`
     reference a dropper basename. (Presentation/auto-reveal is NOT auto-exec — only
     `runOn=="folderOpen"` is the structural trigger.)
  2. `.claude/settings.json` and `.claude/settings.local.json` — a `SessionStart` hook runs its
     command at session start (the agent analogue of folderOpen; official Claude Code hooks docs
     https://code.claude.com/docs/en/hooks.md, verified in-repo by
     docs/research/spike-06-claude-code-hooks-protocol-2026-06.md). Nesting (from the plugin's
     own working hooks.json): `hooks.SessionStart[*].hooks[*].command`. FIRE when a command
     references a dropper basename. Only those TWO project settings files are checked — NOT a
     `settings*.json` glob: Claude Code auto-executes only `settings.json` + `settings.local.json`,
     so a glob would over-match non-executed files and raise false positives.

MODEL FOR JUDGMENT ONLY (Policy 5): this is a DETERMINISTIC parser/rule (like
`sec-detect/detect_tools.py`) — no LLM, no network, no exec/eval of config content. It fires
the STRUCTURAL predicate (auto-exec trigger AND a primary-sourced dropper basename); the "is
this text imperative/exec-shaped?" judgment stays DOWNSTREAM in `ai-llm-review` §9 triage.

Degrade, never raise (ADR-003, mirrors ext_scan.py / deps-scan S8): malformed / oversized /
symlink-escaping config is skipped (no finding, no exception) and the capability records
`ide-hygiene` in `summary.tools_unavailable` (it could not fully inspect the tree, so it must
NOT silently look "clean"). An unscannable `project_dir` likewise degrades. A scannable tree
with no config of these families is clean, NOT degraded (the editor-present-but-empty
analogue). `tool_assisted:false` — this is the Read/Grep/Glob floor (ADR-015); confidence is
capped by `degradation.cap_floor_confidence`. Reuses `ext_scan.py`'s `degradation` import +
bounded-read-via-handle idiom; MIRRORS (does NOT cross-import) deps-scan `ioc_scan.py`'s
`_repo_rel` + realpath-confine.
"""
from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Iterator

import degradation as dg

CAPABILITY = "ide-hygiene"
KB_REF = "AISEC-SUPPLY-CHAIN-003"
_OWASP = ["A06:2021"]  # Vulnerable and Outdated Components
_CATEGORY = "ai-config-persistence"

# Floor confidence for the only severity this detector emits (then capped by
# degradation.cap_floor_confidence). An auto-exec dropper reference is always HIGH.
_FLOOR_HIGH_CONFIDENCE = 0.7

# DO-NOT-COPY gate (wh-5ox) — every dropper basename is re-derived from a PRIMARY source, not
# the unlicensed community YARA. Authoritative list = KB AISEC-SUPPLY-CHAIN-003
# (ai-attack-kb/reference/supply-chain-3.md), sourced to:
#   * Socket, "Shai-Hulud descends to Hades: Miasma PyPI wave" (2026-06-07,
#     https://socket.dev/blog/shai-hulud-descends-to-hades-miasma-pypi-wave) — `.claude/setup.mjs`,
#     `.github/setup.js`;
#   * StepSecurity, "The Hades Campaign (PyPI)" (2026-06-08,
#     https://www.stepsecurity.io/blog/the-hades-campaign-pypi-packages) — `.vscode/setup.mjs`;
# corroborated in docs/research/20260610_hades_shai_hulud_pypi.md. The ticket body's example
# triplet listed `config.mjs`/`ai_init.js`, which have NO primary source in-repo and read like
# the community YARA the gate forbids — they are intentionally EXCLUDED (source wins, Policy 7).
# A future primary-sourced basename plugs in here cleanly.
DROPPER_TARGETS = frozenset({"setup.mjs", "setup.js"})

# Bounded read cap: a config under an untrusted repo could ship a giant / deeply-nested file to
# blow up RAM at json.loads. A real tasks.json / settings.json is a few KB; 1 MB is generous
# headroom. An oversized file is skipped (read is bounded via a handle as a stat/size-race
# backstop — read <= cap+1 bytes, NOT read_bytes() which slurps the whole file first).
_MAX_CONFIG_BYTES = 1_000_000

# The config files inspected, as POSIX-relative paths under the scanned project root. The
# settings set is an EXPLICIT 2-tuple, NOT a `settings*.json` glob — Claude Code auto-executes
# only `settings.json` + `settings.local.json` at SessionStart, so a glob would over-match
# non-executed files (e.g. a backup / unrelated `settings.foo.json`) and raise false positives.
_TASKS_REL = ".vscode/tasks.json"
_SETTINGS_RELS = (".claude/settings.json", ".claude/settings.local.json")


# --------------------------------------------------------------------------- #
# bounded, confinement-checked JSON read (reuse ext_scan.py's handle idiom;
# mirror ioc_scan.py's realpath-confine + symlink skip — different package)
# --------------------------------------------------------------------------- #
def _confined_load(rel: str, project_dir: str) -> tuple[dict | None, bool]:
    """Load `<project_dir>/<rel>` → (doc, present_uninspectable).

    `doc` is the parsed object, or None when the file is absent / unparsable / oversized /
    not an object. `present_uninspectable` is True when a file IS there on disk but we could
    NOT safely inspect it (a symlink / realpath escape, or malformed / oversized JSON) — that
    drives the degrade flag so the capability never silently reports an un-inspected config as
    clean. A simply-absent file is (None, False). NEVER raises (ADR-003).

    HIGH (mirror ioc_scan.py:108-119): the scanned tree is UNTRUSTED. We read a config ONLY
    when it is not a symlink AND its realpath stays under the project's realpath — a symlinked
    `.vscode/tasks.json` pointing at `~/.ssh/id_rsa` / `/etc/*` must never be followed (that
    would aim the reader at host content and mis-attribute it to an in-tree locator)."""
    abs_path = os.path.join(project_dir, rel)
    if not os.path.lexists(abs_path):
        return None, False  # genuinely absent — nothing to inspect, not a degrade
    # confinement: refuse to follow a symlink or any realpath that escapes the tree.
    if os.path.islink(abs_path):
        return None, True
    root_real = os.path.realpath(project_dir)
    real = os.path.realpath(abs_path)
    if real != root_real and not real.startswith(root_real + os.sep):
        return None, True
    try:
        if os.path.getsize(abs_path) > _MAX_CONFIG_BYTES:
            return None, True  # oversized untrusted config → skip (can't trust / can't inspect)
        # bounded read via a handle: at most cap+1 bytes (NOT read_bytes(), which would slurp
        # the whole file into RAM first), then reject if the cap was exceeded — guards a
        # stat/size race where the file grew after the size check. RAM stays bounded.
        with open(abs_path, "rb") as fh:
            raw = fh.read(_MAX_CONFIG_BYTES + 1)
        if len(raw) > _MAX_CONFIG_BYTES:
            return None, True
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        # RecursionError: an untrusted, deeply-NESTED config (e.g. `"["*N + "]"*N`) can sit
        # UNDER the byte cap yet exceed json.loads' recursion limit. RecursionError is a
        # RuntimeError subclass (NOT a ValueError), so it must be named explicitly — the byte
        # cap defends RAM-by-SIZE, this defends parse-DEPTH. Narrow tuple by design (ADR-003 /
        # Policy 12 — never broaden to bare `Exception`); handler does no recursion-heavy work.
        return None, True  # malformed / unreadable / over-nested — un-inspectable → degrade
    if not isinstance(doc, dict):
        return None, True  # a non-object config is malformed for our purposes
    return doc, False


# --------------------------------------------------------------------------- #
# dropper-reference predicate (deterministic, basename-EXACT — no substring FP)
# --------------------------------------------------------------------------- #
# Token boundaries: whitespace OR a shell separator / command-substitution char. Splitting on
# these (not whitespace alone) surfaces a basename glued to a separator (`x&&setup.mjs`); the
# EXACT-basename match downstream keeps precision regardless of how finely we split.
_EXEC_SEPARATORS = re.compile(r"[\s;&|<>()$`]+")


def _exec_tokens(parts: Iterable[object]) -> Iterator[str]:
    """Yield tokens split on whitespace AND shell separators, then punctuation-stripped.

    A `command` may be a whole shell line (`"node .vscode/setup.mjs"`, `"benign&&setup.mjs"`) or
    `args` may carry the target separately — both are flattened here. Splitting on shell separators
    (`; & | < > ( ) $` and backtick) as well as whitespace surfaces a dropper basename even when it
    is GLUED to a separator with no preceding `/` or space; the EXACT-basename match in
    `_referenced_dropper` keeps precision (a wider split cannot admit a look-alike). Non-strings
    are ignored."""
    for part in parts:
        if not isinstance(part, str):
            continue
        for tok in _EXEC_SEPARATORS.split(part.replace("\\", "/")):
            cleaned = tok.strip("'\"`();,&|<>")
            if cleaned:
                yield cleaned


def _referenced_dropper(parts: Iterable[object]) -> str | None:
    """Return the dropper basename referenced by any exec token, else None.

    EXACT basename match (the last `/`-segment of a token must EQUAL a DROPPER_TARGETS entry) —
    never a Python substring, which would re-admit a false positive (`mysetup.mjs` /
    `setup.mjs.bak` must NOT match `setup.mjs`)."""
    for tok in _exec_tokens(parts):
        base = tok.rsplit("/", 1)[-1]
        if base in DROPPER_TARGETS:
            return base
    return None


# --------------------------------------------------------------------------- #
# per-family predicates
# --------------------------------------------------------------------------- #
def _tasks_dropper(doc: dict) -> str | None:
    """For a parsed `.vscode/tasks.json`, return the dropper basename of the FIRST task that
    auto-runs (`runOptions.runOn == "folderOpen"`) AND references one, else None.

    Structural AND: a folderOpen task with no dropper ref, OR a dropper ref without folderOpen,
    is NOT a hit. Malformed sub-shapes (a non-list `tasks`, a non-dict task) are skipped."""
    tasks = doc.get("tasks")
    if not isinstance(tasks, list):
        return None
    for task in tasks:
        if not isinstance(task, dict):
            continue
        run_options = task.get("runOptions")
        run_on = run_options.get("runOn") if isinstance(run_options, dict) else None
        if run_on != "folderOpen":
            continue  # only the documented auto-exec trigger qualifies
        args = task.get("args")
        parts: list[object] = [task.get("command")]
        if isinstance(args, list):
            parts.extend(args)
        hit = _referenced_dropper(parts)
        if hit is not None:
            return hit
    return None


def _sessionstart_dropper(doc: dict) -> str | None:
    """For a parsed `.claude/settings.json` / `.claude/settings.local.json`, return the dropper
    basename of the FIRST `SessionStart` hook command that references one, else None.

    Traverses the documented `hooks.SessionStart[*].hooks[*].command` nesting; malformed
    sub-shapes are skipped (degrade, never raise)."""
    hooks = doc.get("hooks")
    if not isinstance(hooks, dict):
        return None
    groups = hooks.get("SessionStart")
    if not isinstance(groups, list):
        return None
    for group in groups:
        if not isinstance(group, dict):
            continue
        inner = group.get("hooks")
        if not isinstance(inner, list):
            continue
        for hook in inner:
            if not isinstance(hook, dict):
                continue
            hit = _referenced_dropper([hook.get("command")])
            if hit is not None:
                return hit
    return None


# --------------------------------------------------------------------------- #
# repo-relative locator (mirror ioc_scan.py:129 — do NOT cross-import)
# --------------------------------------------------------------------------- #
def _repo_rel(rel: str) -> str | None:
    """Normalize a known relative config path to a POSIX repo-relative `file`, or None if it
    escapes the tree. finding-schema.json requires `^[^/~]` (an absolute/home path would leak
    the host's machine layout into a committed report). Same belt-and-braces escape check as
    ioc_scan.py:129 — the confinement in `_confined_load` should already prevent an escape."""
    posix = rel.replace(os.sep, "/")
    if posix == ".." or posix.startswith("../") or posix.startswith("/") or posix.startswith("~"):
        return None
    return posix


# --------------------------------------------------------------------------- #
# finding construction (reuse ext_scan.py's tool_assisted:false shape)
# --------------------------------------------------------------------------- #
def _make_finding(rel_file: str, trigger: str, dropper: str) -> dict:
    """Build a finding-schema candidate for an auto-exec config-persistence hit.

    `tool_assisted:false` (the floor) → confidence capped by cap_floor_confidence;
    `verified:static_review_only` — a structural match is a candidate, §9 triage decides."""
    scenario = (
        f"{rel_file} {trigger} and references the dropper basename '{dropper}': an on-disk "
        f"AI-assistant/editor config that AUTO-EXECUTES on folder-open / session-start, the "
        f"persistence shape of a supply-chain payload (KB AISEC-SUPPLY-CHAIN-003 — Hades / "
        f"Shai-Hulud / Miasma; primary sources Socket + StepSecurity). Deterministic floor "
        f"candidate, signal-not-block; static_review_only — ai-llm-review §9 judges whether "
        f"the command is exec-shaped."
    )
    finding = {
        "id": "F-000",  # renumbered by scan() when merged into the document
        "canonical_of": None,
        "file": rel_file,
        "line": 0,  # config/file-level locator (no reliable line from json.loads)
        "severity": "HIGH",
        "category": _CATEGORY,
        "owasp": list(_OWASP),
        "preconditions": [],
        "access_required": "local",
        "verified": "static_review_only",
        "confidence": _FLOOR_HIGH_CONFIDENCE,
        "exploit_scenario": scenario,
        "recommendation": (
            f"Treat {rel_file} as untrusted DATA: do NOT open the folder / start a session "
            f"with this config active. Confirm the auto-run directive and the '{dropper}' "
            f"target against the primary source (KB AISEC-SUPPLY-CHAIN-003); remove the "
            f"auto-exec trigger and the dropper, and rotate any credential the bootstrap could "
            f"reach. Signal-not-block — this is a floor candidate, not a verdict."
        ),
        "first_link": rel_file,
        "tool_assisted": False,  # this is the floor — never tool-backed
        "kb_refs": [KB_REF],
    }
    return dg.cap_floor_confidence(finding)


# --------------------------------------------------------------------------- #
# scan — inspect the two config families, build a finding-schema document
# --------------------------------------------------------------------------- #
def scan(project_dir: str, scoring_standard: str = "CVSS4.0") -> dict:
    """Inspect `<project_dir>/.vscode/tasks.json` (folderOpen auto-run) and
    `<project_dir>/.claude/settings.json` + `settings.local.json` (SessionStart hook) for a primary-sourced dropper
    reference and emit a finding-schema-valid document.

    Emits one `tool_assisted:false` HIGH candidate per offending config file. NEVER blocks;
    NEVER raises (ADR-003). Degrades clean — recording `ide-hygiene` in
    `summary.tools_unavailable` — when the tree is unscannable OR a present config could not be
    inspected (symlink/escape, malformed, oversized). A scannable tree with no config of these
    families is clean, NOT degraded."""
    if not os.path.isdir(project_dir):
        return _build_doc([], degraded=True, scoring_standard=scoring_standard)

    findings: list[dict] = []
    degraded = False

    # .vscode/tasks.json — folderOpen auto-run → dropper
    doc, uninspectable = _confined_load(_TASKS_REL, project_dir)
    degraded = degraded or uninspectable
    if doc is not None:
        dropper = _tasks_dropper(doc)
        rel = _repo_rel(_TASKS_REL)
        if dropper is not None and rel is not None:
            findings.append(_make_finding(rel, "auto-runs on folder-open (runOptions.runOn=='folderOpen')", dropper))

    # .claude/settings.json + settings.local.json — SessionStart hook → dropper
    for settings_rel in _SETTINGS_RELS:
        sdoc, suninspectable = _confined_load(settings_rel, project_dir)
        degraded = degraded or suninspectable
        if sdoc is None:
            continue
        sdropper = _sessionstart_dropper(sdoc)
        srel = _repo_rel(settings_rel)
        if sdropper is not None and srel is not None:
            findings.append(_make_finding(srel, "runs a SessionStart hook command", sdropper))

    findings = _renumber(findings)
    return _build_doc(findings, degraded=degraded, scoring_standard=scoring_standard)


def _renumber(findings: list[dict]) -> list[dict]:
    """Assign stable F-NNN ids (sorted by file for determinism — each config file emits at most
    one finding, all HIGH, so file order is total)."""
    ordered = sorted(findings, key=lambda f: f["file"])
    out: list[dict] = []
    for idx, finding in enumerate(ordered, start=1):
        renumbered = dict(finding)
        renumbered["id"] = f"F-{idx:03d}"
        out.append(renumbered)
    return out


def _build_doc(findings: list[dict], *, degraded: bool, scoring_standard: str) -> dict:
    """Wrap findings in a finding-schema-valid document with derived summary counts."""
    counts = {
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings if f["severity"] == "LOW"),
    }
    tools_unavailable = [CAPABILITY] if degraded else []
    return {
        "summary": {
            "scanned_langs": [],
            "tools_used": [],
            "tools_unavailable": tools_unavailable,
            "scoring_standard": scoring_standard,
            "counts": counts,
        },
        "findings": findings,
    }


if __name__ == "__main__":  # pragma: no cover
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(scan(target), indent=2))
