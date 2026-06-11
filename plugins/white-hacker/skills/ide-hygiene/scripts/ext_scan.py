"""IDE/editor-extension hygiene floor — OFFLINE, static, behind the ide-hygiene capability.

A trojanized editor extension (the Nx-Console / TeamPCP / "Carnage" class) ships a valid
marketplace version, installs without error, and runs arbitrary code on `activate` — none
of which a dependency-level SCA gate (deps-scan) sees, because an editor extension is NOT a
project dependency: it lives HOST-LEVEL under the user's editor profile, outside any scanned
repo. This module is the floor that covers that gap. It:

  1. ENUMERATES installed extensions — the editor CLI (`code --list-extensions
     --show-versions`) when present, else the on-disk `~/.vscode/extensions/*/package.json`
     fallback (VS Code's documented per-extension layout). Pure stdlib; NEVER raises.
  2. PIN/VERIFIES each (publisher, name, version) against the watchlist `extension` block
     (watchlist-entry-schema.json:57-70). The DATA (which extensions are bad) is wh-k6l's
     job — this module hardcodes NO specific package name/version; an empty watchlist
     correctly finds nothing.
  3. GREPS each extension's activation entry for the two-tier malware shape — an env-cred
     probe (`process.env.AWS_SECRET_ACCESS_KEY`, `NPM_TOKEN`, …) AND a second-stage
     fetch-and-exec (`fetch(...).then(eval)` / `eval(... )` / `child_process` exec of a
     downloaded payload) — emitting a LOWER-confidence candidate. One tier alone is not
     enough (a benign extension legitimately reads env or fetches; the combination is the
     tell).

Host-level finding locator (the design wrinkle): finding-schema.json `file` is guarded
`^[^/~]` — review output is committed to a PUBLIC repo, so an absolute / `~` path would leak
the host's machine layout (and FAILS schema validation). An extension lives OUTSIDE the
scanned repo, so there is no repo-relative path for it; instead the locator is the stable
MARKETPLACE IDENTIFIER `ext:<publisher>.<name>@<version>` — it is the canonical id of the
finding, passes `^[^/~]`, and carries no host path. The on-disk directory is used only to
READ the manifest/activation file; it is NEVER emitted.

Degrade-clean (ADR-003, mirrors deps-scan S8 `malware-db`): no editor CLI AND no on-disk
extensions dir → record `ide-hygiene` in `summary.tools_unavailable`, emit zero findings,
NEVER raise / block. Rule 5: every function is a deterministic pure function — no LLM, no
RNG, no network. `tool_assisted:false`; confidence capped via degradation.cap_floor_confidence.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import degradation as dg

CAPABILITY = "ide-hygiene"
KB_REF = "AISEC-SUPPLY-CHAIN-003"
_OWASP = ["A06:2021"]  # Vulnerable and Outdated Components
_CATEGORY_WATCHLIST = "ide-extension"
_CATEGORY_ACTIVATION = "ide-extension-activation"

# Floor confidence per emitted severity (then capped by degradation.cap_floor_confidence).
_CONFIDENCE = {"HIGH": 0.7, "MEDIUM": 0.6, "LOW": 0.5}

# Default editor CLI probed for enumeration. Swappable per ADR-015 — the agent depends on
# the "enumerate installed extensions" capability, never on a brand; the on-disk fallback
# means a missing CLI degrades, it does not block.
_DEFAULT_EDITOR_CLI = "code"

# --------------------------------------------------------------------------- #
# activation-code grep patterns (the two-tier malware shape). Each is a RECOGNITION
# pattern — this module recognizes these strings, it never authors a payload. Tier A =
# env-credential probe; Tier B = second-stage fetch-and-exec. A candidate needs BOTH.
# --------------------------------------------------------------------------- #
# Tier A — reading a credential/secret out of the process environment.
_ENV_CRED_PATTERNS = (
    r"process\.env\.[A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*",
    r"process\.env\[\s*['\"][^'\"]*(?:TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)[^'\"]*['\"]\s*\]",
    r"~/\.aws", r"~/\.ssh", r"~/\.npmrc", r"~/\.claude",
)
_ENV_CRED_RE = [re.compile(p, re.IGNORECASE) for p in _ENV_CRED_PATTERNS]

# Tier B — fetching a second stage AND executing it (download-and-run). `eval` matches
# BOTH a call `eval(` AND a bare reference (`.then(eval)` / a callback) — the canonical
# trojan idiom passes `eval` to `.then()` without call-parens of its own.
_EXEC_PRIM = r"(?:eval|new\s+Function)\b"
_FETCH_EXEC_PATTERNS = (
    rf"\bfetch\s*\([\s\S]{{0,300}}?{_EXEC_PRIM}",   # fetch(...) ... eval / .then(eval)
    rf"{_EXEC_PRIM}[\s\S]{{0,300}}?\bfetch\s*\(",   # eval(await fetch(...))
    r"child_process[\s\S]{0,300}?https?://",         # exec a downloaded payload
    r"https?://[\s\S]{0,300}?child_process",
)
_FETCH_EXEC_RE = [re.compile(p) for p in _FETCH_EXEC_PATTERNS]

# Files inside an extension dir that hold its activation logic (best-effort, capped read).
_ACTIVATION_GLOBS = ("extension.js", "extension.cjs", "extension.mjs", "main.js", "out/extension.js")
_MAX_ACTIVATION_BYTES = 2_000_000  # cap the read so a giant bundle can't stall the floor

# Cap the manifest read too (MED-2): this module's threat model is a TROJANIZED extension
# that controls its own package.json — an unbounded read could ship a multi-GB / deeply-
# nested manifest to blow up RAM at json.loads. An oversized manifest is SKIPPED (the
# extension's metadata can't be trusted anyway), exactly like an unparseable one. A real
# VS Code package.json is a few KB; 2 MB is generous headroom.
_MAX_MANIFEST_BYTES = 2_000_000


# --------------------------------------------------------------------------- #
# enumerate — editor CLI first, then the on-disk ~/.vscode/extensions fallback
# --------------------------------------------------------------------------- #
def _parse_folder_name(folder: str) -> tuple[str, str, str] | None:
    """`<publisher>.<name>-<version>` → (publisher, name, version), or None.

    The VS Code on-disk folder name is `publisher.name-version` (e.g.
    `acme.trojan-lint-9.9.9`). Split on the LAST `-` that begins a version-looking token,
    and on the FIRST `.` for publisher/name. Only used as a fallback when a manifest is
    missing fields — the manifest is authoritative when present."""
    m = re.match(r"^([^.]+)\.(.+)-(\d[^-]*)$", folder)
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3)


def _read_manifest(folder: Path) -> dict | None:
    """Parse one extension `package.json` → dict, or None if unreadable / not an object.

    Byte-CAPPED (MED-2): a trojanized extension controls its own manifest, so an oversized
    file is stat-skipped (and the read is bounded as a backstop against a stat/size race)
    BEFORE `json.loads` — a multi-GB / deeply-nested manifest can't blow up RAM. NEVER
    raises: a missing/unreadable/garbage/oversized manifest → None (the dir degrades,
    skipped exactly like an unparseable one), not a crash."""
    path = folder / "package.json"
    try:
        if path.stat().st_size > _MAX_MANIFEST_BYTES:
            return None  # oversized → skip (untrusted, can't be a real ~few-KB manifest)
        # bounded read via a handle: read at most cap+1 bytes (NOT read_bytes(), which would
        # slurp the whole file into RAM first), then reject if the cap was exceeded — guards
        # a stat/size race where the file grew after the stat. RAM stays bounded either way.
        with path.open("rb") as fh:
            raw = fh.read(_MAX_MANIFEST_BYTES + 1)
        if len(raw) > _MAX_MANIFEST_BYTES:
            return None
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


def _enumerate_ondisk(extensions_dir: str | Path) -> list[dict]:
    """Walk `extensions_dir` for `*/package.json` extension manifests → records.

    Each record = `{publisher, name, version, id, dir}` where `id == publisher.name`
    (the marketplace id — NOT the folder name). The manifest is AUTHORITATIVE; the folder
    name only fills an INDIVIDUAL field the manifest omitted. A dir whose manifest is
    UNPARSEABLE is SKIPPED (its metadata can't be trusted for pin/verify — a corrupt
    manifest could be a tampered/half-written extension); a missing/odd dir is also
    skipped. This NEVER raises — a good sibling is still enumerated."""
    try:
        root = Path(extensions_dir)
    except TypeError:
        return []
    if not root.is_dir():
        return []
    out: list[dict] = []
    for folder in sorted(p for p in root.iterdir() if p.is_dir()):
        doc = _read_manifest(folder)
        if doc is None:
            continue  # unparseable/odd manifest → can't trust metadata → skip
        fb_pub, fb_name, fb_ver = _parse_folder_name(folder.name) or ("", "", "")
        publisher = str(doc.get("publisher") or fb_pub)
        name = str(doc.get("name") or fb_name)
        version = str(doc.get("version") or fb_ver)
        if not publisher or not name or not version:
            continue
        out.append({
            "publisher": publisher,
            "name": name,
            "version": version,
            "id": f"{publisher}.{name}",
            "dir": str(folder),
        })
    return out


def _enumerate_cli(editor_cli: str) -> list[dict] | None:
    """Try `<editor_cli> --list-extensions --show-versions` → records, or None when the
    CLI is absent / errors / yields nothing parseable (so the caller falls back to disk).

    Output shape: one `publisher.name@version` line per extension. No `dir` is known from
    the CLI (the grep tier therefore runs only on the on-disk path). NEVER raises."""
    exe = shutil.which(editor_cli)
    if exe is None:
        return None
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, resolved exe
            [exe, "--list-extensions", "--show-versions"],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    out: list[dict] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        m = re.match(r"^([^.@\s]+)\.([^@\s]+)@(\S+)$", line)
        if not m:
            continue
        publisher, name, version = m.group(1), m.group(2), m.group(3)
        out.append({
            "publisher": publisher, "name": name, "version": version,
            "id": f"{publisher}.{name}", "dir": "",
        })
    return out or None


def _default_extensions_dir() -> str:
    """The documented VS Code per-user extensions dir (`~/.vscode/extensions`).

    Resolved at call time only as a default for the on-disk fallback; it is READ from, never
    emitted (host paths never reach a finding). `~` is expanded here, not stored anywhere."""
    return str(Path("~/.vscode/extensions").expanduser())


def enumerate_extensions(
    extensions_dir: str | Path | None = None,
    editor_cli: str | None = _DEFAULT_EDITOR_CLI,
) -> list[dict]:
    """Enumerate installed editor extensions: editor CLI first, on-disk fallback second.

    Returns a list of `{publisher, name, version, id, dir}` (id = `publisher.name`; `dir`
    is "" for a CLI-sourced record). `editor_cli=None` forces the on-disk path (used in
    tests + when no CLI capability is wanted). `extensions_dir=None` uses the documented
    `~/.vscode/extensions` default. NEVER raises — a missing CLI AND a missing dir → []."""
    _editor_present, exts = _collect(extensions_dir, editor_cli)
    return exts


# --------------------------------------------------------------------------- #
# pin/verify against the watchlist `extension` block
# --------------------------------------------------------------------------- #
def _ext_index(watchlist: list[dict] | None) -> dict[str, set[str]]:
    """Fold the watchlist `extension` rows into `{ext_id: set(bad_versions)}`.

    Reads ONLY `target:"extension"` rows' `extension` block (marketplace/id/bad_versions —
    watchlist-entry-schema.json:57-70); other targets (dependency/tool) are ignored here.
    An empty/absent `bad_versions` → the whole-extension wildcard `"*"` (any installed
    version is bad). NEVER raises: a malformed row is skipped. NO package name/version is
    hardcoded — the DATA comes entirely from the passed watchlist (do-not-copy gate)."""
    index: dict[str, set[str]] = {}
    for row in watchlist or []:
        if not isinstance(row, dict) or row.get("target") != "extension":
            continue
        block = row.get("extension")
        if not isinstance(block, dict):
            continue
        ext_id = block.get("id")
        if not isinstance(ext_id, str) or not ext_id:
            continue
        bad = block.get("bad_versions")
        if isinstance(bad, list) and bad:
            versions = {str(v) for v in bad}
        else:
            versions = {"*"}  # whole-extension wildcard
        index.setdefault(ext_id, set()).update(versions)
    return index


def _is_watchlisted(ext: dict, index: dict[str, set[str]]) -> bool:
    """True when the extension's id is watchlisted AND its installed version is listed
    (or the wildcard `"*"` is set). EXACT version match — never a Python substring (which
    would re-admit a false positive, e.g. `"1.2" in "1.2.3"`)."""
    bad = index.get(ext["id"])
    if bad is None:
        return False
    return ext["version"] in bad or "*" in bad


# --------------------------------------------------------------------------- #
# activation-code grep tier
# --------------------------------------------------------------------------- #
def _activation_text(ext_dir: str) -> str:
    """Read the extension's activation entry text (best-effort, byte-capped).

    Reads the first matching activation file (`extension.js` etc.); empty string when the
    dir is unknown ("" for a CLI-sourced record) or no entry file is readable. NEVER raises."""
    if not ext_dir:
        return ""
    root = Path(ext_dir)
    for rel in _ACTIVATION_GLOBS:
        path = root / rel
        try:
            if path.is_file():
                return path.read_text(encoding="utf-8", errors="ignore")[:_MAX_ACTIVATION_BYTES]
        except OSError:
            continue
    return ""


def _activation_signals(text: str) -> tuple[bool, bool]:
    """Return (env_cred_probe, fetch_and_exec) for an activation entry's text."""
    env_probe = any(rx.search(text) for rx in _ENV_CRED_RE)
    fetch_exec = any(rx.search(text) for rx in _FETCH_EXEC_RE)
    return env_probe, fetch_exec


def _grep_activation(ext: dict) -> bool:
    """True iff the extension's activation entry shows BOTH tiers (env-cred probe AND a
    second-stage fetch-and-exec) — the two-tier shape. One tier alone is benign."""
    env_probe, fetch_exec = _activation_signals(_activation_text(ext.get("dir", "")))
    return env_probe and fetch_exec


# --------------------------------------------------------------------------- #
# finding construction (mirrors supply_chain.py / the finding-schema contract)
# --------------------------------------------------------------------------- #
def _locator(ext: dict) -> str:
    """The host-level finding locator: `ext:<publisher>.<name>@<version>`. Stable, passes
    finding-schema `^[^/~]`, leaks no host path (the design wrinkle — see module docstring)."""
    return f"ext:{ext['id']}@{ext['version']}"


def _make_watchlist_finding(idx: int, ext: dict) -> dict:
    loc = _locator(ext)
    scenario = (
        f"installed editor extension {ext['id']} @ {ext['version']} matches a watchlist "
        f"`extension` row (known-malicious/compromised version): a trojanized extension runs "
        f"arbitrary code on activate at host level, outside any project SCA gate; "
        f"static_review_only, triage decides."
    )
    finding = {
        "id": f"F-{idx:03d}",
        "canonical_of": None,
        "file": loc,
        "line": 0,
        "severity": "HIGH",
        "category": _CATEGORY_WATCHLIST,
        "owasp": list(_OWASP),
        "preconditions": [],
        "access_required": "local",
        "verified": "static_review_only",
        "confidence": _CONFIDENCE["HIGH"],
        "exploit_scenario": scenario,
        "recommendation": (
            f"Uninstall {ext['id']} immediately (it is on the malicious-extension watchlist), "
            f"rotate any credentials the editor session could reach, and verify the publisher "
            f"+ version against the marketplace advisory before reinstalling any version."
        ),
        "first_link": loc,
        "tool_assisted": False,  # this is the floor — never tool-backed
        "kb_refs": [KB_REF],
    }
    return dg.cap_floor_confidence(finding)


def _make_activation_finding(idx: int, ext: dict) -> dict:
    loc = _locator(ext)
    scenario = (
        f"editor extension {ext['id']} @ {ext['version']} activation entry contains BOTH an "
        f"environment-credential probe AND a second-stage fetch-and-exec (download-and-run): "
        f"the two-tier shape of a trojanized extension that steals secrets then runs a remote "
        f"payload on activate; lower-confidence heuristic, static_review_only, triage decides."
    )
    finding = {
        "id": f"F-{idx:03d}",
        "canonical_of": None,
        "file": loc,
        "line": 0,
        "severity": "MEDIUM",
        "category": _CATEGORY_ACTIVATION,
        "owasp": list(_OWASP),
        "preconditions": [],
        "access_required": "local",
        "verified": "static_review_only",
        "confidence": _CONFIDENCE["MEDIUM"],
        "exploit_scenario": scenario,
        "recommendation": (
            f"Inspect {ext['id']}'s activation entry: confirm the env-credential read + the "
            f"fetched-and-executed payload are intended; if not, uninstall and rotate exposed "
            f"credentials. Not yet on the watchlist — verify before trusting (this is a grep "
            f"heuristic, not a confirmed match)."
        ),
        "first_link": loc,
        "tool_assisted": False,
        "kb_refs": [KB_REF],
    }
    return dg.cap_floor_confidence(finding)


def _counts(findings: list[dict]) -> dict:
    c = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        c[f["severity"].lower()] += 1
    return c


# --------------------------------------------------------------------------- #
# scan — build a finding-schema.json-valid document
# --------------------------------------------------------------------------- #
def scan(
    extensions_dir: str | Path | None = None,
    watchlist: list[dict] | None = None,
    editor_cli: str | None = _DEFAULT_EDITOR_CLI,
    scoring_standard: str = "CVSS4.0",
) -> dict:
    """Enumerate installed extensions, pin/verify against the watchlist `extension` block,
    grep each activation entry for the two-tier shape, and emit a schema-valid document.

    Degrades clean: when no editor CLI is reachable AND the on-disk extensions dir is
    absent (nothing to enumerate), `ide-hygiene` is recorded in `summary.tools_unavailable`
    and zero findings are emitted — NEVER raises / blocks (ADR-003, deps-scan S8 mirror).
    Always `tool_assisted:false` (this is the floor). `watchlist=None`/`[]` → the pin/verify
    tier finds nothing (the DATA is wh-k6l's job); the activation grep still runs."""
    editor_present, exts = _collect(extensions_dir, editor_cli)

    index = _ext_index(watchlist)
    findings: list[dict] = []
    idx = 1
    for ext in exts:
        if _is_watchlisted(ext, index):
            findings.append(_make_watchlist_finding(idx, ext))
            idx += 1
        if _grep_activation(ext):
            findings.append(_make_activation_finding(idx, ext))
            idx += 1

    tools_unavailable = [] if editor_present else [CAPABILITY]
    return {
        "summary": {
            "scanned_langs": [],
            "tools_used": [],
            "tools_unavailable": tools_unavailable,
            "scoring_standard": scoring_standard,
            "counts": _counts(findings),
        },
        "findings": findings,
    }


def _collect(
    extensions_dir: str | Path | None, editor_cli: str | None
) -> tuple[bool, list[dict]]:
    """Return (editor_present, extensions). `editor_present` is True when EITHER the editor
    CLI is reachable OR the on-disk extensions dir exists — it drives the degrade flag
    independently of whether any extension was found (a present-but-empty editor is NOT
    'unavailable')."""
    cli_present = bool(editor_cli) and shutil.which(editor_cli) is not None
    if editor_cli and cli_present:
        cli = _enumerate_cli(editor_cli)
        if cli is not None:
            return True, cli
    target = _default_extensions_dir() if extensions_dir is None else extensions_dir
    try:
        dir_present = Path(target).is_dir()
    except TypeError:
        dir_present = False
    exts = _enumerate_ondisk(target) if dir_present else []
    return (cli_present or dir_present), exts


if __name__ == "__main__":  # pragma: no cover
    print(json.dumps(scan(), indent=2))
