"""Inert campaign-IOC grep pack — a deterministic, pure-stdlib FLOOR scan (wh-5ox.1).

CVE-based SCA and the S1–S8 manifest floor (`supply_chain.py`) both work over a project's
*dependency graph*. They do NOT scan the project's own FILE CONTENTS for the fixed string
artifacts a known supply-chain campaign leaves behind — a token-wipe beacon literal, a
commit marker, an exfil-staging filename shape, an ICP-canister C2 host, a double-exec lock
marker. Today those literals exist only as KB prose (`ai-attack-kb/reference/supply-chain-3.md`)
for the *model* to recall; this module is the cheap deterministic detector for them.

It walks a scanned `project_dir` tree, greps each readable text file for the FIXED literals
loaded from the DATA/value-plane `reference/campaign-iocs.json`, and on an EXACT substring
match emits a `tool_assisted:false`, human-triaged finding-schema candidate. It NEVER blocks
and NEVER raises (unreadable / binary / undecodable files are skipped). A missing / empty /
malformed data file degrades clean: zero findings + `ioc-scan` in `summary.tools_unavailable`.

DO-NOT-COPY (binding — see EPIC wh-5ox): the shipped `campaign-iocs.json` is EMPTY of real
literals. Community YARA/IOC sets are UNLICENSED and partly DISPUTED; every real literal must
be re-derived from a PRIMARY source (CVE/GHSA, vendor advisory, the artifact) and carry that
URL before being added. A non-primary literal is marked `low_durability`. This module is the
MECHANISM + SCHEMA; populating the literals is a follow-up research/watchlist step.

Rule 5 (model only for judgment): every function here is a deterministic pure function — no
LLM, no network, no RNG. Stdlib only (json, os, pathlib). Reuses `supply_chain.py`'s
`_repo_rel` approach (supply_chain.py:1163) for repo-relative paths and
`degradation.cap_floor_confidence` (degradation.py:59) for the floor-confidence cap.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import degradation as dg

CAPABILITY = "ioc-scan"
KB_REF = "AISEC-SUPPLY-CHAIN-003"
_OWASP = ["A06:2021"]  # Vulnerable and Outdated Components
_CATEGORY = "supply-chain"
_VALID_SEVERITY = ("HIGH", "MEDIUM", "LOW")

# Floor confidence per severity (then capped by degradation.cap_floor_confidence to 0.8).
_CONFIDENCE = {"HIGH": 0.7, "MEDIUM": 0.6, "LOW": 0.5}

# Directories excluded from the walk: resource discipline (every touched file is scanned by
# endpoint security) + ADR scoping. A literal buried in a vendored/build/VCS dir is noise.
_EXCLUDED_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "target", "vendor",
})

# LOW-1: cap each file read so a single huge/streaming file can't exhaust memory. A floor
# candidate on a truncated head is fine; a literal that sits only past the cap is not read.
_MAX_READ_BYTES = 2_000_000  # ~2 MB head

# Default DATA-plane location, resolved relative to this module (reference/ one level up).
_DEFAULT_IOCS_PATH = Path(__file__).resolve().parent.parent / "reference" / "campaign-iocs.json"


# --------------------------------------------------------------------------- #
# DATA plane — load the campaign-IOC literals (skip-don't-raise, like malware_db.py)
# --------------------------------------------------------------------------- #
def load_iocs(iocs_path: str | Path | None = None) -> list[dict]:
    """Load the usable IOC entries from `campaign-iocs.json`.

    Returns a list of entries that each carry a non-empty `literal` (empty/placeholder
    entries provide no coverage and are dropped). A missing / unreadable / malformed file,
    or one without a list `iocs`, yields `[]` — this function NEVER raises (the caller then
    degrades clean), mirroring `malware_db.load_malware_db` (malware_db.py:27)."""
    path = Path(iocs_path) if iocs_path is not None else _DEFAULT_IOCS_PATH
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return []
    if not isinstance(doc, dict):
        return []
    raw = doc.get("iocs")
    if not isinstance(raw, list):
        return []
    entries: list[dict] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        literal = entry.get("literal")
        if not isinstance(literal, str) or not literal:
            continue  # placeholder / empty literal → no coverage
        entries.append(entry)
    return entries


# --------------------------------------------------------------------------- #
# tree walk — readable text files only, excluded dirs pruned
# --------------------------------------------------------------------------- #
def _iter_text_files(project_dir: str):
    """Yield (abs_path, head_text) for every CONFINED, readable, UTF-8-decodable regular file
    under `project_dir`, pruning `_EXCLUDED_DIRS`.

    HIGH-1 (symlink-file escape): the scanned tree is UNTRUSTED. `os.walk(followlinks=False)`
    won't DESCEND a symlinked dir, but a symlink FILE in `filenames` would still be opened and
    `read_text` would FOLLOW it — aiming the reader at out-of-tree host secrets
    (`~/.ssh/id_rsa`, `/etc/*`) and mis-attributing that content to a benign in-tree locator.
    We therefore read a file ONLY when its `realpath` stays under the project's `realpath`
    (skips symlinks pointing out of the tree, and any intermediate-symlink escape). A symlink
    whose target is in-tree is also skipped — the real regular file is read directly, so no
    content is lost and nothing is double-counted.

    LOW-1: read at most `_MAX_READ_BYTES` (no unbounded read). Undecodable (binary) /
    unreadable files are skipped — this generator NEVER raises."""
    root_real = os.path.realpath(project_dir)
    root_prefix = root_real + os.sep
    for dirpath, dirnames, filenames in os.walk(project_dir, topdown=True):
        # prune excluded dirs in place so os.walk never descends into them
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIRS]
        for name in filenames:
            abs_path = os.path.join(dirpath, name)
            # HIGH-1: skip symlinks outright (and any path whose realpath escapes the tree).
            if os.path.islink(abs_path):
                continue
            real = os.path.realpath(abs_path)
            if real != root_real and not real.startswith(root_prefix):
                continue  # confinement breach → never read
            try:
                with open(abs_path, encoding="utf-8") as fh:
                    text = fh.read(_MAX_READ_BYTES)  # LOW-1: bounded head read
            except (OSError, ValueError, UnicodeDecodeError):
                continue  # unreadable / binary / undecodable → skip, never raise
            yield abs_path, text


def _repo_rel(path: str, project_dir: str) -> str | None:
    """Path relative to the scanned project root (POSIX separators), or None if it escapes.

    finding-schema.json requires a repo-relative `file` (`^[^/~]`); an absolute/home path
    would leak the host's machine layout into a committed report. Same approach as
    supply_chain.py:1163. MED-1 (defense-in-depth): if the normalized relative path escapes
    the tree (== ".." or starts with "../"), return None so the caller drops the finding
    rather than emit a `..`-bearing path (the realpath confinement in `_iter_text_files`
    should already prevent this; this is the belt-and-braces check)."""
    rel = os.path.relpath(path, project_dir).replace(os.sep, "/")
    if rel == ".." or rel.startswith("../"):
        return None
    return rel


# --------------------------------------------------------------------------- #
# finding builder — mirrors supply_chain.py's _make_kernel_finding shape
# --------------------------------------------------------------------------- #
def _make_finding(rel_file: str, entry: dict) -> dict:
    """Build a finding-schema candidate for an exact IOC match in `rel_file`.

    `tool_assisted:false` (this is the floor) → confidence capped by cap_floor_confidence.
    `verified:static_review_only` — a fixed-string match is a candidate, a human triages."""
    severity = entry.get("severity")
    if severity not in _VALID_SEVERITY:
        severity = "HIGH"
    ioc_id = entry.get("id", "?")
    kind = entry.get("kind", "?")
    source = entry.get("primary_source", "?")
    low_durability = bool(entry.get("low_durability", False))
    durability = " (low-durability — not primary-confirmed)" if low_durability else ""
    scenario = (
        f"{rel_file} contains a FIXED campaign IOC literal (id={ioc_id}, kind={kind})"
        f"{durability} associated with a known supply-chain campaign "
        f"(primary_source={source}). An exact fixed-string match is a strong candidate that "
        f"the tree was touched by that campaign's payload; static_review_only — a human "
        f"triages (re-derive from the primary source; do not block)."
    )
    finding = {
        "id": "F-000",  # renumbered by scan() when merged into the document
        "canonical_of": None,
        "file": rel_file,
        "line": 0,
        "severity": severity,
        "category": _CATEGORY,
        "owasp": list(_OWASP),
        "preconditions": [],
        "access_required": "unknown",
        "verified": "static_review_only",
        "confidence": _CONFIDENCE[severity],
        "exploit_scenario": scenario,
        "recommendation": (
            "Confirm the match against the primary source for this campaign; treat the file "
            "as untrusted, isolate before rotating any exposed credential, and remove the "
            "campaign artifact. Signal-not-block — this is a floor candidate, not a verdict."
        ),
        "first_link": rel_file,
        "tool_assisted": False,  # the floor — never tool-backed
        "kb_refs": [KB_REF],
    }
    return dg.cap_floor_confidence(finding)


# --------------------------------------------------------------------------- #
# scan — walk the tree, grep for literals, build a finding-schema document
# --------------------------------------------------------------------------- #
def scan(
    project_dir: str,
    iocs_path: str | Path | None = None,
    scoring_standard: str = "CVSS4.0",
) -> dict:
    """Grep `project_dir` (recursively, excluded dirs pruned) for the FIXED campaign
    literals in `campaign-iocs.json` and emit a finding-schema-valid document.

    On an EXACT substring match, emit one `tool_assisted:false` candidate per (file, IOC).
    NEVER blocks; NEVER raises. When the data file is missing / empty / malformed OR carries
    no usable literal, the capability has no coverage: zero findings and `ioc-scan` is
    recorded in `summary.tools_unavailable` (graceful degradation, ADR-003). G1: a
    nonexistent / non-directory `project_dir` is ALSO a degrade signal (an unscannable tree
    must never be reported as a silent "clean")."""
    entries = load_iocs(iocs_path)
    # Degrade when there is no usable IOC pack OR no scannable tree (G1) — either way the
    # capability produced no coverage, so it must surface in tools_unavailable, not look clean.
    degraded = (not entries) or (not os.path.isdir(project_dir))

    findings: list[dict] = []
    if entries and os.path.isdir(project_dir):
        for abs_path, text in _iter_text_files(project_dir):
            rel_file = _repo_rel(abs_path, project_dir)
            if rel_file is None:
                continue  # MED-1: path escaped the tree → drop, never emit a `..` path
            for entry in entries:
                if entry["literal"] in text:  # EXACT fixed-substring match
                    findings.append(_make_finding(rel_file, entry))

    findings = _renumber(findings)
    return _build_doc(findings, degraded, scoring_standard)


def _renumber(findings: list[dict]) -> list[dict]:
    """Assign stable F-NNN ids (sorted by file then severity for determinism)."""
    severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    ordered = sorted(
        findings, key=lambda f: (f["file"], severity_rank.get(f["severity"], 9))
    )
    out: list[dict] = []
    for idx, finding in enumerate(ordered, start=1):
        renumbered = dict(finding)
        renumbered["id"] = f"F-{idx:03d}"
        out.append(renumbered)
    return out


def _build_doc(findings: list[dict], degraded: bool, scoring_standard: str) -> dict:
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
