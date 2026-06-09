"""Supply-chain-malware floor (S1–S8) — OFFLINE, static, behind the SCA capability.

CVE-based SCA (`npm audit` / OSV-by-CVE) has a structural blind spot: NOVEL malicious
packages (typosquats, slopsquats, install-script malware, self-propagating worms) have a
valid version, install without error, and are not in any CVE DB yet — so the native gate
APPROVES them (spike-09 F2). This module is the floor that covers that gap: it reads only
on-disk files (manifest + lockfile + the referenced install scripts), emits low/medium-
confidence `tool_assisted:false` candidates, and NEVER blocks. Triage + a human decide.

Design (spike-09 §F5):
  * an ecosystem-AGNOSTIC signal core (S1–S8 + scoring) over a normalized struct, plus
  * a per-ecosystem ADAPTER that produces that struct. Shipped here: the npm adapter.
    PyPI / RubyGems / Go / Cargo / Maven are follow-on adapters behind the same interface.

Rule 5 (model only for judgment): every function here is a deterministic pure function —
no LLM, no network, no RNG. Stdlib only (json, re, pathlib, unicodedata) — no new runtime
dep. Reuses `normalize_deps.py`'s finding shape + `degradation.py`'s floor-confidence cap.

Scoring (spike-09 F2): emit a candidate on ANY HIGH signal (S5/S6/S8) OR when ≥2 lower
signals corroborate; a lone S1/S3 is informational only (never a finding). Each finding's
`recommendation` maps to an F4 remediation-ladder rung (spike-09 §F4).
"""
from __future__ import annotations

import json
import re
import unicodedata
import xml.etree.ElementTree as ET
from pathlib import Path

# `tomllib` is stdlib only on Python 3.11+. The package floor is `>=3.10` (matching the
# repo's other 13 packages — Rule 11, no convention fork), so import it defensively: on
# 3.10 it's absent and the TOML adapters degrade gracefully (ADR-003) rather than crash
# at import. CI runs 3.13 (tomllib present), so TOML deps parse there; on a 3.10 floor a
# `pyproject.toml`/`Cargo.toml` yields a partial/empty struct and `scan()` never raises.
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 — no stdlib tomllib
    tomllib = None  # type: ignore[assignment]

import degradation as dg
# `is_known_bad(name, version, db)` (malware_db.py:47) is the version-aware predicate the
# S8 matcher delegates to (sibling module, same package — imported via the conftest path
# like the tests' `import malware_db as mdb`; no defensive guard needed, it has no
# optional-stdlib dependency unlike tomllib above).
from malware_db import is_known_bad

KB_REF = "AISEC-SUPPLY-CHAIN-001"
_OWASP = ["A06:2021"]  # Vulnerable and Outdated Components
_CATEGORY = "supply-chain"

# Floor confidence per emitted severity (then capped by degradation.cap_floor_confidence).
_CONFIDENCE = {"HIGH": 0.7, "MEDIUM": 0.6, "LOW": 0.5}

# Install-time lifecycle hooks (S1). `test`/`build`/etc. are NOT install hooks.
_LIFECYCLE_HOOKS = ("preinstall", "install", "postinstall")

# S6 dangerous-API string patterns searched inside a referenced install script.
# These are recognition patterns quoted from public vendor advisories (spike-09 §F2/S6);
# this module RECOGNIZES them, it never authors any. Each is a literal substring or regex.
_DANGEROUS_API_PATTERNS = (
    r"eval\s*\(",
    r"new\s+Function\s*\(",
    r"child_process",
    r"\bexec\s*\(",
    r"\bspawn\s*\(",
    r"require\(\s*['\"](?:net|http|https|dns)['\"]\s*\)",
    r"\bfetch\s*\(",
    r"Buffer\.from\([^)]*,\s*['\"]base64['\"]\)",
    r"~/\.ssh",
    r"~/\.aws",
    r"~/\.npmrc",
    r"~/\.claude",
)
_DANGEROUS_API_RE = [re.compile(p) for p in _DANGEROUS_API_PATTERNS]

# S7 obfuscation markers.
_HEX_IDENT_RE = re.compile(r"_0x[0-9a-f]{4,}")
_OBFUSCATION_SINGLE_LINE_BYTES = 50_000  # >50 KB single line
_OBFUSCATION_HEX_DENSITY = 5  # ≥5 hex-identifier occurrences

# F4 remediation-ladder rungs (spike-09 §F4), keyed by the dominant signal.
_F4 = {
    "S5": ("Confirm intended vs actual name char-by-char against the official SDK docs / "
           "the allowlist; a separator/homoglyph mismatch (F4 rung 1) is treated as "
           "malicious — do not install, run `npm ci --ignore-scripts` during triage "
           "(F4 rung 0), then remove or replace by exact name (F4 rung 5)."),
    "S6": ("Do not install/build yet — run `npm ci --ignore-scripts` so lifecycle hooks "
           "cannot execute during triage (F4 rung 0); inspect the install script, then "
           "remove or replace the package (F4 rung 5) and rotate any exposed credentials "
           "if it already ran (F4 rung 6)."),
    "S8": ("Confirmed by the offline malware DB (F4 rung 2): escalate to removal "
           "immediately — delete the package, install the correct one by exact name, clear "
           "node_modules + the lockfile entry and reinstall with `--ignore-scripts` "
           "(F4 rung 5); rotate exposed credentials (F4 rung 6); report upstream "
           "(F4 rung 7)."),
    "S4": ("Confirm intended vs actual name against the allowlist / official docs "
           "(F4 rung 1); do not install — run `npm ci --ignore-scripts` during triage "
           "(F4 rung 0); if mistyped, remove and install the correct package by exact "
           "name (F4 rung 5)."),
    "S2": ("Verify the non-registry source (git/url/tarball) is the intended upstream; "
           "do not install — `npm ci --ignore-scripts` during triage (F4 rung 0); pin + "
           "commit the lockfile and prefer the registry package by exact version "
           "(F4 rung 4)."),
    "_default": ("Do not install/build yet — `npm ci --ignore-scripts` during triage "
                 "(F4 rung 0); pin + commit the lockfile and add a release-age cooldown "
                 "(F4 rung 4); remove or replace if unintended (F4 rung 5)."),
}

# Embedded fallback allowlist (so tests don't depend on the reference/ path resolving).
_FALLBACK_ALLOWLIST = (
    "@anthropic-ai/sdk", "openai", "langchain", "@langchain/core", "llamaindex",
    "@huggingface/inference", "@modelcontextprotocol/sdk", "react", "axios", "next",
    "express", "lodash", "vue", "typescript",
)

_ALLOWLIST_PATH = Path(__file__).resolve().parent.parent / "reference" / "ai-sdk-allowlist.json"


# --------------------------------------------------------------------------- #
# allowlist loading
# --------------------------------------------------------------------------- #
def load_allowlist(path: Path = _ALLOWLIST_PATH) -> list[str]:
    """The curated AI-SDK + popular names (S4/S5). Falls back to a small embedded list
    when `reference/ai-sdk-allowlist.json` is unreadable, so the floor still works.
    `/sec-kb-refresh` extends the on-disk list over time (ADR-015)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        names = data.get("names")
        if isinstance(names, list) and names:
            return [str(n) for n in names]
    except (OSError, ValueError):
        pass
    return list(_FALLBACK_ALLOWLIST)


# --------------------------------------------------------------------------- #
# S4 primitive — Damerau-Levenshtein (optimal string alignment)
# --------------------------------------------------------------------------- #
def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal-string-alignment edit distance (insert/delete/substitute + adjacent
    transposition). Distance 0 = identical = SAFE; 1–2 = typosquat candidate (S4)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev2: list[int] = []
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(
                cur[j - 1] + 1,          # insertion
                prev[j] + 1,             # deletion
                prev[j - 1] + cost,      # substitution
            )
            if (i > 1 and j > 1
                    and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]):
                cur[j] = min(cur[j], prev2[j - 2] + 1)  # transposition
        prev2, prev = prev, cur
    return prev[lb]


# --------------------------------------------------------------------------- #
# name folding (S5) — ASCII-fold homoglyphs + normalize separators
# --------------------------------------------------------------------------- #
def fold_name(name: str) -> str:
    """ASCII-fold non-ASCII homoglyphs (NFKD + strip combining) and normalize
    separators (`_`→`-`, collapse repeats) for S5 collision detection."""
    decomposed = unicodedata.normalize("NFKD", name)
    ascii_only = decomposed.encode("ascii", "ignore").decode("ascii").lower()
    # separator normalization: underscore -> hyphen, collapse doubled chars
    sep_norm = ascii_only.replace("_", "-")
    sep_norm = re.sub(r"-{2,}", "-", sep_norm)
    sep_norm = re.sub(r"(.)\1+", r"\1", sep_norm)  # collapse doubled chars
    return sep_norm


# --------------------------------------------------------------------------- #
# the npm ADAPTER — package.json + lockfile -> normalized struct
# --------------------------------------------------------------------------- #
_GIT_PREFIXES = ("git+", "git:", "github:", "gitlab:", "bitbucket:")
_URL_PREFIXES = ("http://", "https:", "http:")
_LOCKFILES = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "npm-shrinkwrap.json")


def _classify_source(spec: str) -> str:
    """Map an npm dep spec string to a source_type ∈ {registry, git, url, file, workspace}."""
    s = (spec or "").strip()
    low = s.lower()
    if low.startswith("workspace:"):
        return "workspace"
    if low.startswith("file:"):
        return "file"
    if low.startswith("npm:"):
        return "registry"  # explicit registry alias
    if any(low.startswith(p) for p in _GIT_PREFIXES):
        return "git"
    if any(low.startswith(p) for p in _URL_PREFIXES):
        # tarball over http(s) or a plain http(s) source
        return "url"
    return "registry"


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _resolved_npm(root: Path) -> dict[str, str]:
    """Extract `{name: resolved_version}` from a `package-lock.json` (wh-4k9).

    Supports lockfileVersion 2/3 (the `packages` map, keyed by node_modules path —
    strip everything up to the LAST `node_modules/` so nested deps resolve to their bare
    name) AND falls back to the legacy v1 `dependencies` map. pnpm-lock.yaml / yarn.lock
    are SKIPPED — stdlib has no YAML parser, so those stay presence-only (degrade, not
    crash). On a name collision across depths the SHALLOWEST path wins deterministically
    (the top-level install the manifest pins; fewest `node_modules/` segments — on a tie
    the first seen) so a nested copy listed first in a hand-ordered / tampered lockfile
    cannot shadow it (TL finding 2). NEVER raises: a missing/odd lockfile yields `{}`."""
    lock = _read_json(root / "package-lock.json")
    out: dict[str, str] = {}
    best_depth: dict[str, int] = {}
    packages = lock.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2/3
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue  # "" is the root project itself
            name = path.rsplit("node_modules/", 1)[-1]
            version = meta.get("version")
            if not name or not isinstance(version, str):
                continue
            depth = path.count("node_modules/")  # 1 = top-level, >1 = nested
            if name not in best_depth or depth < best_depth[name]:
                out[name] = version
                best_depth[name] = depth
    deps_map = lock.get("dependencies")
    if isinstance(deps_map, dict):  # legacy lockfileVersion 1 (or v2 back-compat block)
        for name, meta in deps_map.items():
            if name in out or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str):
                out[name] = version
    return out


def parse_npm(project_dir: str) -> dict:
    """npm ADAPTER: read package.json + any lockfile into the normalized struct.

    Returns `{deps:[{name,spec,source_type[,resolved]}], lifecycle_scripts:{...},
    lockfile_present:bool, script_files:[paths]}`. NEVER raises on a missing or odd
    manifest — degrades to an empty-but-well-formed struct (spike-09 floor semantics).
    The OPTIONAL `resolved` key (wh-4k9) carries the lockfile-resolved version when
    `package-lock.json` lists the dep — additive, never replaces name/spec/source_type."""
    root = Path(project_dir)
    pkg = _read_json(root / "package.json")
    resolved = _resolved_npm(root)

    deps: list[dict] = []
    for field in ("dependencies", "devDependencies", "optionalDependencies",
                  "peerDependencies"):
        block = pkg.get(field)
        if isinstance(block, dict):
            for name, spec in block.items():
                dep = {
                    "name": str(name),
                    "spec": str(spec),
                    "source_type": _classify_source(str(spec)),
                }
                if str(name) in resolved:  # additive optional key, only when known
                    dep["resolved"] = resolved[str(name)]
                deps.append(dep)

    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    lifecycle = {h: str(scripts[h]) for h in _LIFECYCLE_HOOKS if h in scripts}

    lockfile_present = any((root / lf).exists() for lf in _LOCKFILES)

    # Resolve install-script file paths referenced by the lifecycle hooks (e.g.
    # `node scripts/postinstall.js`). Only files that exist on disk are scanned (S6/S7).
    script_files: list[str] = []
    for cmd in lifecycle.values():
        for token in re.split(r"\s+|&&|\|\||;", cmd):
            token = token.strip().strip("'\"")
            if not token or not re.search(r"\.(js|cjs|mjs|ts|sh)$", token):
                continue
            cand = (root / token)
            if cand.is_file():
                script_files.append(str(cand))
    # de-dup, preserve order
    seen: set[str] = set()
    script_files = [p for p in script_files if not (p in seen or seen.add(p))]

    return {
        "deps": deps,
        "lifecycle_scripts": lifecycle,
        "lockfile_present": lockfile_present,
        "script_files": script_files,
    }


# --------------------------------------------------------------------------- #
# per-ecosystem ADAPTERS (spike-09 §F5) — same normalized struct as parse_npm.
# Each follows parse_npm's contract: NEVER raises on a missing/odd manifest, degrades
# to the empty-but-well-formed struct; classifies source_type per that ecosystem's
# conventions; resolves on-disk install/build-hook files into `script_files` (S6/S7).
# Stdlib only: tomllib (TOML), xml.etree (pom.xml), regex/line parsing otherwise.
# --------------------------------------------------------------------------- #
def _empty_norm() -> dict:
    """A fresh empty-but-well-formed normalized struct (floor degrade)."""
    return {"deps": [], "lifecycle_scripts": {}, "lockfile_present": False,
            "script_files": []}


def _read_toml(path: Path) -> dict:
    """Parse a TOML manifest, or `{}` when tomllib is unavailable (Python 3.10) / the
    file is missing or malformed. NEVER raises — the TOML adapters degrade to a partial
    or empty struct on a 3.10 floor (ADR-003), exactly like a missing manifest."""
    if tomllib is None:  # Python 3.10 — no stdlib TOML parser; degrade, don't crash.
        return {}
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, tomllib.TOMLDecodeError, ValueError):
        return {}


def _dedup(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    return [p for p in paths if not (p in seen or seen.add(p))]


# ----------------------------- PyPI / Python ------------------------------- #
_PYPI_LOCKFILES = ("poetry.lock", "uv.lock")
# PEP 508 / requirement line: leading name token, before any version/marker/url.
_PEP508_NAME_RE = re.compile(r"^([A-Za-z0-9._-]+)")
# `name @ <url>` direct reference (PEP 508 url spec).
_PEP508_URL_AT_RE = re.compile(r"^([A-Za-z0-9._-]+)\s*@\s*(.+)$")
# `#egg=<name>` fragment on a VCS/URL requirement.
_EGG_RE = re.compile(r"[#&]egg=([A-Za-z0-9._-]+)")


def _classify_pypi(spec: str) -> str:
    """Map a PyPI requirement spec to a source_type. `git+…`/url = remote; a local
    `file://` / `{path=…}` = file; otherwise the PyPI registry."""
    s = (spec or "").strip().lower()
    if s.startswith(("git+", "hg+", "bzr+", "svn+")):
        return "git"
    if s.startswith("file:") or s.startswith("file://"):
        return "file"
    if s.startswith(("http://", "https://")):
        return "url"
    return "registry"


def _pypi_dep(name: str, spec: str, source: str | None = None) -> dict:
    return {"name": str(name), "spec": str(spec),
            "source_type": source or _classify_pypi(spec)}


_VCS_URL_PREFIXES = ("git+", "hg+", "bzr+", "svn+", "http://", "https://", "file:")


def _parse_requirement_line(line: str) -> dict | None:
    """One requirements.txt / PEP 508 dependency line → a dep dict (None = skip)."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith("-"):
        return None  # blank, comment, or a pip option (-r / -e / --hash)
    low = stripped.lower()
    # A bare VCS/URL requirement keeps its `#egg=` fragment (NOT a line comment).
    if low.startswith(_VCS_URL_PREFIXES):
        egg = _EGG_RE.search(stripped)
        name = egg.group(1) if egg else stripped
        return _pypi_dep(name, stripped)
    # Otherwise an inline `# comment` is stripped before parsing.
    s = stripped.split("#", 1)[0].strip()
    if not s:
        return None
    # `name @ url` direct reference (PEP 508 url spec)
    m = _PEP508_URL_AT_RE.match(s)
    if m:
        return _pypi_dep(m.group(1), m.group(2).strip())
    # ordinary `name[extras]<op>version ; marker`
    nm = _PEP508_NAME_RE.match(s)
    if not nm:
        return None
    return _pypi_dep(nm.group(1), s)


def _resolved_pypi(root: Path) -> dict[str, str]:
    """Extract `{name: version}` from a poetry.lock / uv.lock (wh-4k9).

    Both are TOML with a `[[package]]` array of `{name, version}` tables — parsed via the
    package's EXISTING defensive tomllib import (supply_chain.py:32-34), so on a Python
    3.10 floor (no stdlib tomllib) this degrades to `{}` rather than crashing. NEVER
    raises. poetry.lock entries WIN over uv.lock on a name clash (poetry is read first)."""
    out: dict[str, str] = {}
    for lockname in _PYPI_LOCKFILES:  # ("poetry.lock", "uv.lock")
        data = _read_toml(root / lockname)
        packages = data.get("package")
        if not isinstance(packages, list):
            continue
        for entry in packages:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            version = entry.get("version")
            if isinstance(name, str) and isinstance(version, str):
                out.setdefault(name, version)
    return out


def parse_pypi(project_dir: str) -> dict:
    """PyPI ADAPTER: pyproject.toml (`[project].dependencies` PEP 508 list AND/OR
    `[tool.poetry.dependencies]` table) and/or requirements.txt → normalized struct.

    Lockfile: poetry.lock / uv.lock. `setup.py` present → arbitrary code runs at
    build/install time (S1 hook) — recorded in `lifecycle_scripts` + scanned (S6/S7).
    The OPTIONAL `resolved` key (wh-4k9) carries the lockfile-resolved version when a
    poetry.lock / uv.lock lists the dep — additive, never replaces name/spec/source_type."""
    root = Path(project_dir)
    resolved = _resolved_pypi(root)
    deps: list[dict] = []
    seen_names: set[str] = set()

    py = _read_toml(root / "pyproject.toml")
    project = py.get("project") if isinstance(py.get("project"), dict) else {}
    for req in project.get("dependencies", []) or []:
        if not isinstance(req, str):
            continue
        d = _parse_requirement_line(req)
        if d and d["name"] not in seen_names:
            deps.append(d)
            seen_names.add(d["name"])

    poetry = (py.get("tool", {}) or {}).get("poetry", {}) if isinstance(
        py.get("tool"), dict) else {}
    poetry_deps = poetry.get("dependencies") if isinstance(
        poetry.get("dependencies"), dict) else {}
    for name, val in poetry_deps.items():
        if name.lower() == "python":  # the interpreter constraint, not a dependency
            continue
        if isinstance(val, dict):
            if "git" in val:
                d = _pypi_dep(name, str(val.get("git", "")), "git")
            elif "url" in val:
                d = _pypi_dep(name, str(val.get("url", "")), "url")
            elif "path" in val:
                d = _pypi_dep(name, str(val.get("path", "")), "file")
            else:
                d = _pypi_dep(name, str(val.get("version", "*")), "registry")
        else:
            d = _pypi_dep(name, str(val), "registry")
        if d["name"] not in seen_names:
            deps.append(d)
            seen_names.add(d["name"])

    reqs = root / "requirements.txt"
    if reqs.is_file():
        for line in _read_text(str(reqs)).splitlines():
            d = _parse_requirement_line(line)
            if d and d["name"] not in seen_names:
                deps.append(d)
                seen_names.add(d["name"])

    # wh-4k9: attach the OPTIONAL lockfile-resolved version once, additively. Done after
    # collection (rather than per append-site) so all three dep sources are covered.
    for d in deps:
        if d["name"] in resolved:
            d["resolved"] = resolved[d["name"]]

    lifecycle: dict[str, str] = {}
    script_files: list[str] = []
    setup_py = root / "setup.py"
    if setup_py.is_file():
        lifecycle["setup.py"] = "python setup.py (build/install hook)"
        script_files.append(str(setup_py))

    lockfile_present = any((root / lf).exists() for lf in _PYPI_LOCKFILES)
    return {
        "deps": deps,
        "lifecycle_scripts": lifecycle,
        "lockfile_present": lockfile_present,
        "script_files": _dedup(script_files),
    }


# ------------------------------- RubyGems ---------------------------------- #
# `gem 'name', ...` line; capture the quoted gem name + the remainder (for git:/path:).
_GEM_RE = re.compile(r"""^\s*gem\s+['"]([^'"]+)['"]\s*(.*)$""")


def parse_gem(project_dir: str) -> dict:
    """RubyGems ADAPTER: Gemfile (`gem '...'` lines, incl. `git:`/`path:` sources) +
    Gemfile.lock. A native C extension (`extconf.rb` / an `ext/` dir) builds arbitrary
    code at install (S1 hook) — its `extconf.rb` files are scanned (S6/S7)."""
    root = Path(project_dir)
    deps: list[dict] = []
    for line in _read_text(str(root / "Gemfile")).splitlines():
        m = _GEM_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        rest = m.group(2)
        low = rest.lower()
        if "git:" in low or "github:" in low:
            source = "git"
        elif "path:" in low:
            source = "file"
        else:
            source = "registry"
        # spec = the version constraint if one is quoted right after the name, else rest.
        ver = re.search(r"""['"]([~^<>=!\d][^'"]*)['"]""", rest)
        spec = ver.group(1) if ver else (rest.strip() or "*")
        deps.append({"name": str(name), "spec": str(spec), "source_type": source})

    lifecycle: dict[str, str] = {}
    script_files: list[str] = []
    extconfs = sorted(root.glob("**/extconf.rb"))
    if extconfs:
        lifecycle["extconf.rb"] = "ruby extconf.rb (native extension build hook)"
        script_files.extend(str(p) for p in extconfs)

    lockfile_present = (root / "Gemfile.lock").exists()
    return {
        "deps": deps,
        "lifecycle_scripts": lifecycle,
        "lockfile_present": lockfile_present,
        "script_files": _dedup(script_files),
    }


# ---------------------------------- Go ------------------------------------- #
# `require module/path vX.Y.Z` (single or inside a `require ( ... )` block).
_GO_REQUIRE_RE = re.compile(r"^\s*([^\s()]+\.[^\s()/]+/\S+)\s+(v\S+)")
# `replace old => new [version]` — a local path or a fork makes it non-registry.
_GO_REPLACE_RE = re.compile(r"^\s*replace\s+(\S+)(?:\s+\S+)?\s+=>\s+(\S+)(?:\s+(\S+))?")


def _classify_go_replace(target: str) -> str:
    """A go.mod `replace` target: a relative/absolute path = file; a fork module = git."""
    t = target.strip()
    if t.startswith((".", "/")):  # ./  ../  /abs  — a local path
        return "file"
    return "git"  # replaced to a different (fork) module path — non-registry source


def parse_go(project_dir: str) -> dict:
    """Go ADAPTER: go.mod (`require` + `replace`) + go.sum (the lockfile). A `replace`
    to a local path or a fork module makes that dependency a non-registry source (S2).
    Go has NO install/build hook → empty `lifecycle_scripts` + `script_files`."""
    root = Path(project_dir)
    text = _read_text(str(root / "go.mod"))
    deps: dict[str, dict] = {}
    in_require = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0]  # strip a line comment
        stripped = line.strip()
        if stripped.startswith("require") and stripped.endswith("("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if in_require:
            m = _GO_REQUIRE_RE.match("    " + stripped)
            if m:
                deps[m.group(1)] = {"name": m.group(1), "spec": m.group(2),
                                    "source_type": "registry"}
            continue
        # single-line `require mod vX`
        if stripped.startswith("require "):
            m = _GO_REQUIRE_RE.match(line.replace("require ", "    ", 1))
            if m:
                deps[m.group(1)] = {"name": m.group(1), "spec": m.group(2),
                                    "source_type": "registry"}
    # apply replaces: re-classify the module's source (a known require, or add it).
    for raw in text.splitlines():
        m = _GO_REPLACE_RE.match(raw.split("//", 1)[0])
        if not m:
            continue
        old, target = m.group(1), m.group(2)
        ver = m.group(3) or ""
        source = _classify_go_replace(target)
        if old in deps:
            deps[old]["source_type"] = source
            deps[old]["spec"] = f"=> {target} {ver}".strip()
        else:
            deps[old] = {"name": old, "spec": f"=> {target} {ver}".strip(),
                         "source_type": source}

    lockfile_present = (root / "go.sum").exists()
    return {
        "deps": list(deps.values()),
        "lifecycle_scripts": {},   # Go has no install hook
        "lockfile_present": lockfile_present,
        "script_files": [],
    }


# --------------------------------- Cargo ----------------------------------- #
def _classify_cargo(val: object) -> tuple[str, str]:
    """A Cargo dependency value → (spec, source_type). A table with `git`/`path` is a
    non-registry source; a bare string or `version` table is the crates.io registry."""
    if isinstance(val, dict):
        if "git" in val:
            return (str(val.get("git", "")), "git")
        if "path" in val:
            return (str(val.get("path", "")), "file")
        return (str(val.get("version", "*")), "registry")
    return (str(val), "registry")


def parse_cargo(project_dir: str) -> dict:
    """Cargo ADAPTER: Cargo.toml (`[dependencies]`, incl. `git`/`path` tables) +
    Cargo.lock. `build.rs` runs arbitrary code at build time (S1 hook) — scanned
    for S6/S7."""
    root = Path(project_dir)
    cargo = _read_toml(root / "Cargo.toml")
    deps: list[dict] = []
    block = cargo.get("dependencies") if isinstance(
        cargo.get("dependencies"), dict) else {}
    for name, val in block.items():
        spec, source = _classify_cargo(val)
        deps.append({"name": str(name), "spec": spec, "source_type": source})

    lifecycle: dict[str, str] = {}
    script_files: list[str] = []
    build_rs = root / "build.rs"
    if build_rs.is_file():
        lifecycle["build.rs"] = "cargo build.rs (build script hook)"
        script_files.append(str(build_rs))

    lockfile_present = (root / "Cargo.lock").exists()
    return {
        "deps": deps,
        "lifecycle_scripts": lifecycle,
        "lockfile_present": lockfile_present,
        "script_files": _dedup(script_files),
    }


# --------------------------------- Maven ----------------------------------- #
def _strip_ns(tag: str) -> str:
    """Drop an `{namespace}` prefix from an ElementTree tag."""
    return tag.split("}", 1)[1] if "}" in tag else tag


def _mvn_child_text(dep: ET.Element, name: str) -> str:
    for child in dep:
        if _strip_ns(child.tag) == name:
            return (child.text or "").strip()
    return ""


def parse_maven(project_dir: str) -> dict:
    """Maven ADAPTER: pom.xml `<dependencies><dependency>` (groupId/artifactId/version)
    via xml.etree. The dep `name` is the `groupId:artifactId` coordinate. A `system`
    scope (a local jar via `systemPath`) is a non-registry (file) source. Maven has no
    standard committed lockfile (lockfile_present=False) and no install hook."""
    root = Path(project_dir)
    pom = root / "pom.xml"
    deps: list[dict] = []
    try:
        tree = ET.parse(pom)
        xroot = tree.getroot()
    except (OSError, ET.ParseError):
        return _empty_norm()

    for dep in xroot.iter():
        if _strip_ns(dep.tag) != "dependency":
            continue
        gid = _mvn_child_text(dep, "groupId")
        aid = _mvn_child_text(dep, "artifactId")
        if not aid:
            continue
        ver = _mvn_child_text(dep, "version")
        scope = _mvn_child_text(dep, "scope").lower()
        name = f"{gid}:{aid}" if gid else aid
        source = "file" if scope == "system" else "registry"
        deps.append({"name": name, "spec": ver or "*", "source_type": source})

    return {
        "deps": deps,
        "lifecycle_scripts": {},   # no standard install hook surfaced from pom.xml
        "lockfile_present": False,  # Maven has no standard committed resolved lockfile
        "script_files": [],
    }


# --------------------------------------------------------------------------- #
# ecosystem dispatch — marker manifest -> (adapter, lang, manifest filename)
# --------------------------------------------------------------------------- #
# Order matters: the FIRST marker found wins. npm stays first (the lead path).
_DISPATCH: tuple[tuple[str, object, str, str], ...] = (
    ("package.json", parse_npm, "javascript", "package.json"),
    ("pyproject.toml", parse_pypi, "python", "pyproject.toml"),
    ("requirements.txt", parse_pypi, "python", "requirements.txt"),
    ("Gemfile", parse_gem, "ruby", "Gemfile"),
    ("go.mod", parse_go, "go", "go.mod"),
    ("Cargo.toml", parse_cargo, "rust", "Cargo.toml"),
    ("pom.xml", parse_maven, "java", "pom.xml"),
)


def detect_ecosystem(project_dir: str) -> tuple[object, str, str] | None:
    """Detect the ecosystem by the first marker manifest present on disk.

    Returns `(adapter_fn, lang, manifest_filename)` or None when no known manifest
    exists (the caller degrades to an empty-but-valid result)."""
    root = Path(project_dir)
    for marker, adapter, lang, manifest in _DISPATCH:
        if (root / marker).exists():
            return (adapter, lang, manifest)
    return None


# --------------------------------------------------------------------------- #
# the GENERIC signal core (S1–S8) over the normalized struct
# --------------------------------------------------------------------------- #
def _unpinned(spec: str) -> bool:
    """A semver range that can silently pull a freshly-published version (S3)."""
    s = (spec or "").strip()
    return bool(re.search(r"[\^~*]|latest|x", s)) and _classify_source(s) == "registry"


# A PLAIN version literal: a numeric core with an OPTIONAL pre-release AND an OPTIONAL
# build-metadata segment (semver order: `core(-prerelease)?(+build)?`), e.g. `1.0.0`,
# `2.5.0-rc.1`, `1.0.0+build.7`, `1.0.0-beta+meta`. The two segments are matched SEPARATELY
# (a single `[-+]…` class wrongly accepted only one and excluded `+` — TL finding 1).
# Anything with a range operator (`^ ~ >= < =`), a wildcard (`* x`), a tag (`latest`), a
# hyphen RANGE, or a vcs/url/file spec is NOT this.
_EXACT_VERSION_RE = re.compile(
    r"^\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?$"
)


def _exact_pin(spec: str) -> str | None:
    """The settled EXACT-PIN rule (wh-4k9): a manifest spec that is a plain version
    literal counts as a resolved version when no lockfile entry exists — npm `1.0.0`,
    pypi `==1.0.0` / bare `1.0.0`. Returns the bare version, or None for any RANGE
    (`^`/`~`/`>=`/`*`/`latest`/hyphen ranges) or git/url/file spec. Conservative: when in
    doubt it returns None so an unresolved range NEVER matches a specific-version DB entry
    (that name-only match is exactly the false positive wh-4k9 removes)."""
    s = (spec or "").strip()
    if not s:
        return None
    if s.startswith("=="):  # pypi exact pin: `==1.0.0` / `== 1.0.0`
        s = s[2:].strip()
    if _EXACT_VERSION_RE.match(s):
        return s
    return None


def signal_s1(norm: dict) -> bool:
    """S1 — an install-time lifecycle hook is present (necessary-not-sufficient)."""
    return bool(norm.get("lifecycle_scripts"))


def signal_s2(norm: dict) -> list[str]:
    """S2 — deps specified as a remote git/http/tarball source (NOT registry).
    `workspace:`/`file:` (in-repo) are benign and excluded."""
    return [d["name"] for d in norm.get("deps", []) if d["source_type"] in {"git", "url"}]


def signal_s3(norm: dict) -> bool:
    """S3 — unpinned ranges AND no lockfile committed."""
    if norm.get("lockfile_present"):
        return False
    return any(_unpinned(d["spec"]) for d in norm.get("deps", []))


def signal_s4(norm: dict, allowlist: list[str]) -> list[tuple[str, str]]:
    """S4 — typosquat: Damerau-Levenshtein distance 1–2 to an allowlist entry
    (distance 0 = exact = SAFE). Returns (dep_name, nearest_allowlist_name)."""
    hits: list[tuple[str, str]] = []
    allow_set = set(allowlist)
    for d in norm.get("deps", []):
        name = d["name"]
        if name in allow_set:
            continue  # distance 0 = SAFE
        if d["source_type"] not in {"registry"}:
            continue
        for good in allowlist:
            dist = damerau_levenshtein(name, good)
            if 1 <= dist <= 2:
                hits.append((name, good))
                break
    return hits


def signal_s5(norm: dict, allowlist: list[str]) -> list[tuple[str, str]]:
    """S5 — homoglyph/separator collision: a dep whose ASCII-folded, separator-
    normalized form COLLIDES with an allowlist entry while the raw string DIFFERS (HIGH)."""
    folded_allow = {fold_name(g): g for g in allowlist}
    hits: list[tuple[str, str]] = []
    for d in norm.get("deps", []):
        name = d["name"]
        if name in allowlist:
            continue  # exact = safe
        folded = fold_name(name)
        good = folded_allow.get(folded)
        if good is not None and name != good:
            hits.append((name, good))
    return hits


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def signal_s6(norm: dict) -> dict:
    """S6 — dangerous-API strings inside a referenced install script. HIGH when ≥2
    distinct patterns hit in the same file. Returns {script_path: [matched_patterns]}."""
    out: dict[str, list[str]] = {}
    for path in norm.get("script_files", []):
        text = _read_text(path)
        if not text:
            continue
        matched = [pat.pattern for pat in _DANGEROUS_API_RE if pat.search(text)]
        if matched:
            out[path] = matched
    return out


def signal_s7(norm: dict) -> list[str]:
    """S7 — obfuscation markers in an install script: a single line >50 KB, or a high
    density of `_0x[0-9a-f]{4,}` identifiers. Returns the offending script paths."""
    hits: list[str] = []
    for path in norm.get("script_files", []):
        text = _read_text(path)
        if not text:
            continue
        longest_line = max((len(line) for line in text.splitlines()), default=0)
        hex_density = len(_HEX_IDENT_RE.findall(text))
        if longest_line > _OBFUSCATION_SINGLE_LINE_BYTES or hex_density >= _OBFUSCATION_HEX_DENSITY:
            hits.append(path)
    return hits


def signal_s8(norm: dict, malware_db: dict | None) -> list[str]:
    """S8 — VERSION-AWARE known-bad match against an OPTIONAL offline OSSF/GHSA snapshot.

    A HOOK that DEGRADES: `malware_db` is None/empty (no snapshot on disk) → return [] and
    the caller records `malware-db` unavailable. When present, `malware_db` is a mapping
    `{package_name: set/str of bad versions or '*'}` (e.g. from `load_malware_db`).

    wh-4k9 — match by name AND version (NOT name only, which flagged EVERY user of a
    popular compromised package, not just the bad versions):
      * the dep's version = `resolved` (lockfile) or `_exact_pin(spec)` (an exact manifest
        pin with no lockfile). Known → `is_known_bad(name, version, db)` (malware_db.py:47).
      * NO version known (a range with no lockfile) → flag ONLY when the DB entry is the
        wildcard `"*"` (the whole package is bad). NEVER flag a specific-version entry on
        an unresolved range — that name-only match is the false positive this removes.

    Accepted residual (wh-4k9): `resolved` comes from the target's OWN lockfile — the same
    trust domain as the manifest (attacker-controlled), so a tampered lockfile can suppress
    a specific-version hit; S8 stays a human-triaged candidate (never a block) and a `"*"`
    wildcard DB entry still fires regardless of the resolved version."""
    if not malware_db:
        return []
    hits: list[str] = []
    for d in norm.get("deps", []):
        name = d["name"]
        if name not in malware_db:
            continue
        version = d.get("resolved") or _exact_pin(d.get("spec", ""))
        if version is not None:
            if is_known_bad(name, version, malware_db):
                hits.append(name)
        elif "*" in malware_db[name]:  # unresolved range → only a wildcard entry flags
            hits.append(name)
    return hits


# --------------------------------------------------------------------------- #
# scoring (spike-09 F2)
# --------------------------------------------------------------------------- #
_HIGH_SIGNALS = {"S5", "S6", "S8"}


def score(hits: list[dict]) -> tuple[bool, str]:
    """Decide emit + severity for one dep's accumulated signal hits.

    `hits` = list of `{"signal": "Sn", "severity": "HIGH|MEDIUM|LOW"}`.
    Emit on ANY HIGH signal (S5/S6/S8) OR ≥2 corroborating signals; a lone S1/S3 is
    informational only (no emit). Severity = HIGH if any HIGH fired, else MEDIUM."""
    if not hits:
        return (False, "LOW")
    has_high = any(h["signal"] in _HIGH_SIGNALS or h.get("severity") == "HIGH" for h in hits)
    if has_high:
        return (True, "HIGH")
    if len(hits) >= 2:
        return (True, "MEDIUM")
    return (False, "LOW")


# --------------------------------------------------------------------------- #
# wh-7rk — out-of-tree kernel-module / DKMS pin-and-verify check (ADR-006).
#
# The DETECTION of kernel-module/DKMS PRESENCE is done elsewhere (sec-detect:
# detect_kernel_adjacency flags Kbuild/obj-m/*.ko/dkms.conf). This is the residual
# supply-chain pin-and-verify FLOOR: when a `dkms.conf` exists OR a `Makefile`
# contains `obj-m` (an out-of-tree module build), read it + any build scripts it
# references and flag UNPINNED source fetches as a supply-chain candidate. A pinned
# source (immutable ref / digest-verified) is clean. NEVER raises; NEVER blocks.
# Pure, stdlib, tool_assisted:false — capped via dg.cap_floor_confidence (Rule 5).
# --------------------------------------------------------------------------- #
_ADR006_REC = (
    "Pin the out-of-tree module / DKMS source by digest or an immutable ref and "
    "verify before build (ADR-006)."
)
_KERNEL_KB_REF = "AISEC-SUPPLY-CHAIN-001"

# An UNPINNED tarball/blob fetch: curl/wget of an http(s):// URL on one command line.
_UNPINNED_HTTP_FETCH_RE = re.compile(r"\b(?:curl|wget)\b[^\n;|&]*\bhttps?://", re.IGNORECASE)
# A `git clone` of an http(s)/git URL. Pinning is decided separately (a clone line is a
# candidate UNLESS it carries an immutable ref on the SAME line).
_GIT_CLONE_RE = re.compile(r"\bgit\s+clone\b[^\n;|&]*", re.IGNORECASE)
# Immutable-ref markers that make a `git clone` line PINNED: a `--branch <tag>` /
# `--branch=<tag>` (release tag), a `#<sha>` commit fragment (attached to the URL — a
# 7–40 hex run, distinguishing it from a spaced `# comment`), or `--revision`/`-b <tag>`.
_GIT_PINNED_RE = re.compile(
    r"--branch[=\s]\S+|--revision[=\s]\S+|#[0-9a-fA-F]{7,40}\b|\B-b\s+\S+",
)
# A digest/checksum verification on the SAME fetch line makes an http(s) fetch PINNED.
_DIGEST_VERIFY_RE = re.compile(r"sha256sum|sha512sum|sha1sum|sha256:|sha512:|\bgpg\b", re.IGNORECASE)


def _line_is_pinned(line: str) -> bool:
    """A build line that fetches a source is PINNED when it carries an immutable ref
    (`git clone --branch <tag>` / `#<sha>`) or a same-line digest/checksum verify."""
    return bool(_GIT_PINNED_RE.search(line) or _DIGEST_VERIFY_RE.search(line))


def _unpinned_fetch_lines(text: str) -> list[str]:
    """Return the source-fetch lines in `text` that are UNPINNED.

    An UNPINNED line is a `curl`/`wget` of an http(s) URL, or a `git clone`, that does
    NOT carry an immutable ref / same-line digest verification. Pinned fetches are
    excluded. Pure string scan over INERT on-disk text — never executes anything."""
    unpinned: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        is_fetch = bool(_UNPINNED_HTTP_FETCH_RE.search(line) or _GIT_CLONE_RE.search(line))
        if is_fetch and not _line_is_pinned(line):
            unpinned.append(line)
    return unpinned


def _kernel_build_files(root: Path) -> list[Path]:
    """The kernel-module/DKMS build files to read: `dkms.conf` + an `obj-m` `Makefile`,
    plus any in-repo build script (`*.sh`) those files reference. Empty when neither a
    `dkms.conf` nor an `obj-m` Makefile is present (so the check is out of scope)."""
    dkms = root / "dkms.conf"
    makefile = root / "Makefile"
    has_dkms = dkms.is_file()
    makefile_text = _read_text(str(makefile)) if makefile.is_file() else ""
    has_objm = "obj-m" in makefile_text
    if not has_dkms and not has_objm:
        return []  # no kernel-module / DKMS artifact → out of scope

    files: list[Path] = []
    if has_dkms:
        files.append(dkms)
    if has_objm:
        files.append(makefile)

    # Resolve referenced in-repo build scripts (e.g. `sh build.sh`) from the build text.
    combined = (_read_text(str(dkms)) if has_dkms else "") + "\n" + makefile_text
    for token in re.split(r"\s+|&&|\|\||;|\"|'", combined):
        token = token.strip()
        if not token or not token.endswith(".sh"):
            continue
        cand = root / token
        if cand.is_file() and cand not in files:
            files.append(cand)

    seen: set[Path] = set()
    return [p for p in files if not (p in seen or seen.add(p))]


def scan_kernel_module_sources(project_dir: str) -> list[dict]:
    """Flag UNPINNED out-of-tree kernel-module / DKMS source fetches (ADR-006).

    Triggered when a `dkms.conf` exists OR a `Makefile` contains `obj-m`. Reads those
    files + any build scripts they reference and emits an advisory supply-chain
    candidate per file that fetches an unpinned source (curl/wget of http(s), or a
    `git clone` without an immutable ref). Returns [] when no kernel-module/DKMS files
    exist OR every source is already pinned. NEVER raises; NEVER blocks; pure stdlib."""
    root = Path(project_dir)
    findings: list[dict] = []
    for path in _kernel_build_files(root):
        text = _read_text(str(path))
        if not text:
            continue
        unpinned = _unpinned_fetch_lines(text)
        if not unpinned:
            continue  # every source in this file is pinned → clean
        findings.append(_make_kernel_finding(str(path), unpinned))
    return findings


def _make_kernel_finding(build_file: str, unpinned_lines: list[str]) -> dict:
    """Advisory supply-chain finding for an unpinned kernel-module / DKMS source fetch.

    LOW severity (advisory floor): a single static heuristic, not a confirmed exploit.
    `tool_assisted:false` → confidence capped by dg.cap_floor_confidence."""
    n = len(unpinned_lines)
    scenario = (
        f"out-of-tree kernel-module / DKMS build {build_file} fetches "
        f"{n} UNPINNED source{'s' if n != 1 else ''} (curl/wget of an http(s) URL, or "
        f"`git clone` without an immutable ref) — a tampered or hijacked source builds "
        f"into the kernel at install time; static_review_only, triage decides (ADR-006)."
    )
    finding = {
        "id": "F-000",  # renumbered by scan() when merged into the document
        "canonical_of": None,
        "file": build_file,
        "line": 0,
        "severity": "LOW",
        "category": _CATEGORY,
        "owasp": list(_OWASP),
        "preconditions": [],
        "access_required": "unknown",
        "verified": "static_review_only",
        "confidence": _CONFIDENCE["LOW"],
        "exploit_scenario": scenario,
        "recommendation": _ADR006_REC,
        "first_link": build_file,
        "tool_assisted": False,  # this is the floor — never tool-backed
        "kb_refs": [_KERNEL_KB_REF],
    }
    return dg.cap_floor_confidence(finding)


# --------------------------------------------------------------------------- #
# scan — build a finding-schema.json-valid document
# --------------------------------------------------------------------------- #
def _dominant_signal(hits: list[dict]) -> str:
    """Pick the F4-ladder key: the highest-priority signal that fired."""
    for sig in ("S8", "S6", "S5", "S4", "S2"):
        if any(h["signal"] == sig for h in hits):
            return sig
    return "_default"


def _evidence(hits: list[dict]) -> str:
    return ", ".join(sorted({h["signal"] for h in hits}))


def scan(project_dir: str, scan_plan: dict | None = None,
         malware_db: dict | None = None, scoring_standard: str = "CVSS4.0",
         allowlist: list[str] | None = None) -> dict:
    """Detect the ecosystem, run its adapter + the shared S1–S8 core over `project_dir`,
    and emit a schema-valid findings document. NEVER raises on a missing/odd manifest —
    degrades to an empty valid result. Always `tool_assisted:false` (this is the floor),
    capped confidence.

    Dispatch (spike-09 §F5): the first marker manifest present picks the adapter + the
    `scanned_langs` lang + the `manifest_path` (npm leads — package.json is unchanged).
    `malware_db` None → S8 degrades; `summary.tools_unavailable` records `malware-db`.
    `allowlist` overrides the curated `reference/ai-sdk-allowlist.json` (S4/S5) — used to
    pass an ecosystem-specific allowlist (e.g. a module path / `groupId:artifactId`)."""
    # wh-7rk: the kernel-module / DKMS pin-and-verify pass is ECOSYSTEM-INDEPENDENT — a
    # bare out-of-tree module repo carries no package.json, so run it regardless of (and
    # before) the ecosystem dispatch. Findings are merged + renumbered into the document.
    kernel_findings = scan_kernel_module_sources(project_dir)

    detected = detect_ecosystem(project_dir)
    if detected is None:
        # no recognized manifest → only the kernel-module pass can contribute (floor
        # degrade, no lang). Renumber any kernel findings into a valid document.
        merged = _renumber(kernel_findings, start=1)
        return _build_doc(merged, _empty_norm(), scan_plan, malware_db,
                          scoring_standard, "")
    adapter, lang, manifest_name = detected
    norm = adapter(project_dir)  # type: ignore[operator]
    allowlist = load_allowlist() if allowlist is None else list(allowlist)
    manifest_path = str(Path(project_dir) / manifest_name)

    # collect per-dep signal hits
    s1 = signal_s1(norm)
    s2_names = set(signal_s2(norm))
    s3 = signal_s3(norm)
    s4_hits = {name: good for name, good in signal_s4(norm, allowlist)}
    s5_hits = {name: good for name, good in signal_s5(norm, allowlist)}
    s6_map = signal_s6(norm)
    s7_paths = signal_s7(norm)
    s8_names = set(signal_s8(norm, malware_db))

    # Install-script-level findings (S6/S7) are PROJECT-level: a dangerous postinstall
    # belongs to the project's own manifest, not to any one dep, so it is reported once
    # against the manifest (HIGH iff ≥2 distinct dangerous APIs in one script — spike-09
    # §S6) — NOT fanned out to every dep. It also CORROBORATES a name/source-suspicious
    # dep (S6/S7 as a LOW corroborator), so e.g. a typosquat + a dangerous script → HIGH.
    script_high_files = {p: pats for p, pats in s6_map.items() if len(pats) >= 2}
    script_corroborates = bool(s6_map) or bool(s7_paths)
    script_corr_sig = "S6" if s6_map else ("S7" if s7_paths else None)

    findings: list[dict] = []
    idx = 1

    # 1) per-dep findings from each dep's OWN name/source signals (+ corroboration).
    for d in norm.get("deps", []):
        name = d["name"]
        if d["source_type"] in {"workspace", "file"}:
            continue  # in-repo deps are benign (S2 exclusion)
        hits: list[dict] = []
        if name in s8_names:
            hits.append({"signal": "S8", "severity": "HIGH"})
        if name in s5_hits:
            hits.append({"signal": "S5", "severity": "HIGH"})
        if name in s2_names:
            hits.append({"signal": "S2", "severity": "MEDIUM"})
        if name in s4_hits:
            hits.append({"signal": "S4", "severity": "MEDIUM"})
        # corroborators (only attach when the dep already has a name/source signal so a
        # benign dep with a lone S1/S3 stays informational):
        has_name_signal = bool(hits)
        if has_name_signal and script_corroborates and script_corr_sig:
            hits.append({"signal": script_corr_sig, "severity": "LOW"})
        if has_name_signal and s1:
            hits.append({"signal": "S1", "severity": "LOW"})
        if has_name_signal and s3 and _unpinned(d["spec"]):
            hits.append({"signal": "S3", "severity": "LOW"})

        emit, severity = score(hits)
        if not emit:
            continue
        findings.append(_make_finding(idx, name, d, hits, severity, manifest_path,
                                      s4_hits.get(name), s5_hits.get(name)))
        idx += 1

    # 2) project-level dangerous-install-script finding (reported once, keyed to the
    # script path), independent of any dep — a HIGH script is a candidate on its own.
    for spath, pats in script_high_files.items():
        findings.append(_make_script_finding(idx, spath, pats, manifest_path))
        idx += 1

    # 3) wh-7rk: out-of-tree kernel-module / DKMS unpinned-source candidates (ADR-006),
    # appended after the ecosystem candidates and renumbered into the same id sequence.
    for kf in kernel_findings:
        kf = dict(kf)
        kf["id"] = f"F-{idx:03d}"
        findings.append(kf)
        idx += 1

    return _build_doc(findings, norm, scan_plan, malware_db, scoring_standard, lang)


def _renumber(findings: list[dict], start: int = 1) -> list[dict]:
    """Re-stamp `id` as a contiguous `F-NNN` sequence from `start` (copies each dict)."""
    out: list[dict] = []
    for offset, fnd in enumerate(findings):
        f = dict(fnd)
        f["id"] = f"F-{start + offset:03d}"
        out.append(f)
    return out


def _make_finding(idx: int, name: str, dep: dict, hits: list[dict], severity: str,
                  manifest_path: str, s4_target: str | None,
                  s5_target: str | None) -> dict:
    sig = _dominant_signal(hits)
    rec = _F4.get(sig, _F4["_default"])
    target = s5_target or s4_target
    detail = f" (looks like '{target}')" if target else ""
    scenario = (
        f"{name} @ {dep['spec']}{detail}: supply-chain-malware candidate "
        f"(signals: {_evidence(hits)}) — novel malware that CVE-based SCA misses; "
        f"static_review_only, triage decides."
    )
    finding = {
        "id": f"F-{idx:03d}",
        "canonical_of": None,
        "file": manifest_path,
        "line": 0,
        "severity": severity,
        "category": _CATEGORY,
        "owasp": list(_OWASP),
        "preconditions": [],
        "access_required": "unknown",
        "verified": "static_review_only",
        "confidence": _CONFIDENCE[severity],
        "exploit_scenario": scenario,
        "recommendation": rec,
        "first_link": manifest_path,
        "tool_assisted": False,  # this is the floor — never tool-backed
        "kb_refs": [KB_REF],
    }
    # cap floor confidence (degradation.py) — idempotent, lowers weak evidence.
    return dg.cap_floor_confidence(finding)


def _make_script_finding(idx: int, script_path: str, patterns: list[str],
                         manifest_path: str) -> dict:
    """Project-level S6 finding: a dangerous install script (≥2 dangerous APIs)."""
    scenario = (
        f"install script {script_path} contains ≥2 dangerous APIs "
        f"({', '.join(sorted(patterns))}): supply-chain-malware candidate (signal: S6) "
        f"— runs at `npm install` time before any test; static_review_only, triage decides."
    )
    finding = {
        "id": f"F-{idx:03d}",
        "canonical_of": None,
        "file": script_path,
        "line": 0,
        "severity": "HIGH",
        "category": _CATEGORY,
        "owasp": list(_OWASP),
        "preconditions": [],
        "access_required": "unknown",
        "verified": "static_review_only",
        "confidence": _CONFIDENCE["HIGH"],
        "exploit_scenario": scenario,
        "recommendation": _F4["S6"],
        "first_link": manifest_path,
        "tool_assisted": False,
        "kb_refs": [KB_REF],
    }
    return dg.cap_floor_confidence(finding)


def _counts(findings: list[dict]) -> dict:
    c = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        c[f["severity"].lower()] += 1
    return c


def _build_doc(findings: list[dict], norm: dict, scan_plan: dict | None,
               malware_db: dict | None, scoring_standard: str, lang: str = "") -> dict:
    # tools_unavailable: the floor is never tool-backed; the S8 snapshot is `malware-db`
    # and is recorded as unavailable whenever it's absent. Merge with any SCAN-PLAN-
    # derived degraded capabilities so a degraded run is fully recorded.
    unavailable: set[str] = set()
    if not malware_db:
        unavailable.add("malware-db")
    if scan_plan is not None:
        plan_tools = dg.summary_tools(scan_plan)
        tools_used = plan_tools["tools_used"]
        unavailable.update(plan_tools["tools_unavailable"])
    else:
        tools_used = []

    # The detected ecosystem's language is reported only when the manifest carried
    # something to scan (a dep or a lifecycle hook); an empty manifest reports no lang.
    scanned_langs = [lang] if lang and (norm.get("deps")
                                        or norm.get("lifecycle_scripts")) else []

    return {
        "summary": {
            "scanned_langs": scanned_langs,
            "tools_used": sorted(tools_used),
            "tools_unavailable": sorted(unavailable),
            "scoring_standard": scoring_standard,
            "counts": _counts(findings),
        },
        "findings": findings,
    }


if __name__ == "__main__":  # pragma: no cover
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(scan(target), indent=2))
