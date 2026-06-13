"""Gate-2 watchlist DATA validator (wh-hxt.5; ADR-026 §1).

The supply-chain **watchlist** (`known-compromised.osv.json`) and the tool-registry sidecar are
**DATA**, not review-quality KB. The eval keep-or-revert gate (Gate-1) **structurally cannot**
score a DATA edit (`evals/score.py` consumes findings-vs-`label.json`; a watchlist row has no
corpus-measurable merit) — reusing an eval KEEP to admit a DATA row would be a *false-merit merge*.
ADR-026 ratifies a SECOND deterministic gate — **Gate-2** — for watchlist/registry DATA.

This module is the **input arm** of Gate-2: a pure-function validator that checks, per entry —
  (1) **id-bound advisory provenance (SEC-Q4):** >=1 `references[].url` is on an advisory-host
      allow-list AND carries the entry's own `id`; the per-project github branch additionally
      requires host==github.com AND parsed-advisory-id == entry.id;
  (2) **`watchlist-1.0` schema validity** (Draft 2020-12) against the pinned
      `../reference/watchlist-entry-schema.json`;
  (3) **regression-green** (`--check-regression`): `malware_db.load_malware_db` + the version-aware
      `is_known_bad` predicate — a candidate's bad version flags True; a clean sibling flags False
      (exact-set, never substring).
On all-pass it MINTS a SEPARATE, content-bound `evals/data-verdict.json`
`{verdict,path,sha256,validated}` (the sha256 of the EXACT validated bytes). The *consumption* of
that verdict is the one-shot, content-bound `gate_data_edit.py` PreToolUse hook — **ticket (ii)
(wh-hxt.6), NOT this module**; this module MINTS only.

Policy 5: no LLM / no RNG / no network — provenance + schema + a regression predicate are pure
functions. Stdlib + jsonschema only. `malware_db` is imported via the `_shared/scripts/conftest.py`
sys.path shim (no cross-package install).

SEC-Q5 (value-plane guard): agent-facing stdout carries a FIXED reason vocabulary (check name +
the offending structural key / the entry's own id) — feed-derived strings (advisory urls, advisory
prose) are NEVER echoed.

SEC-Q12 (verdict-writer trust): this file AND the pinned schema are added to
`confine_self_writes.FROZEN_BASENAMES` so the outer loop cannot weaken the gate that admits its own
DATA edits.

CLI:
    uv run --with jsonschema python validate_watchlist.py <file-or-dir> \
        [--check-regression] [--mint-verdict <out.json>]

Exit code 0 = all valid, 1 = at least one invalid (per-entry reason), 2 = usage error.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator

# `malware_db` lives in the sibling deps-scan skill (its own uv project). The test harness adds it
# via `_shared/scripts/conftest.py:10-15`; replicate that sys.path shim here so the DOCUMENTED CLI
# (`uv run --with jsonschema python validate_watchlist.py <dir> --check-regression`) also resolves
# it standalone — no cross-package install (mirrors the conftest precedent; same _skills anchor).
# conftest anchors `_skills = <this dir>.parent.parent` (= plugins/white-hacker/skills); the same
# from here: scripts dir → _shared → skills.
_SKILLS_DIR = Path(__file__).resolve().parent.parent.parent
_DEPS_SCAN_SCRIPTS = _SKILLS_DIR / "deps-scan" / "scripts"
if _DEPS_SCAN_SCRIPTS.is_dir() and str(_DEPS_SCAN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_DEPS_SCAN_SCRIPTS))

from malware_db import _accumulate, is_known_bad, load_malware_db  # noqa: E402,F401  (re-exported; used as validate_watchlist.load_malware_db in tests)

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "reference" / "watchlist-entry-schema.json"

# Advisory-host allow-list for the id-bound provenance check (ADR-026 §1, SEC-Q4 + the B1-REVIEW
# finding). MUST include the OSV.dev malicious-packages feed + the vendor-advisory hosts
# socket.dev / stepsecurity.io — NOT GHSA-only: Hades (AISEC-SUPPLY-CHAIN-003) has no GHSA yet
# (20260610_hades_shai_hulud_pypi.md). Bare hosts; the URL host is normalized (leading `www.`
# stripped) before membership. github.com carries BOTH the GHSA-database branch (/advisories/<id>)
# and the per-project branch (/<owner>/<repo>/security/advisories/<id>).
ADVISORY_HOSTS = frozenset(
    {
        "github.com",
        "osv.dev",
        "nvd.nist.gov",
        "socket.dev",
        "stepsecurity.io",
    }
)

# Fixed reason vocabulary (SEC-Q5 / Policy 5): no per-feed interpolation. A reason names the failed
# CHECK and the offending STRUCTURAL key only — never a feed-derived value (url / advisory prose).
REASONS = {
    "provenance": (
        "provenance: no references[].url on the advisory-host allow-list carries the entry id "
        "(id-bound advisory provenance required; SEC-Q4)"
    ),
    "regression": (
        "regression: candidate failed the version-aware is_known_bad round-trip "
        "(bad version must flag True, clean sibling False)"
    ),
    "related_kb_dangling": (
        "related_kb: database_specific.related_kb does not resolve to a known "
        "ai-attack-kb/reference/*.md file (dangling reference fails Gate-2; wh-5ox.9)"
    ),
    "top_level_not_object": "top-level entry is not a JSON object",
    "unreadable": "could not read/parse JSON",
}

# The ai-attack-kb/reference directory, resolved relative to this file.
# _SKILLS_DIR = .../plugins/white-hacker/skills (computed above).
_KB_REFERENCE_DIR = _SKILLS_DIR / "ai-attack-kb" / "reference"


def load_schema(path: Path = SCHEMA_PATH) -> dict:
    return json.loads(path.read_text())


def _host(url: str) -> str:
    """Normalized lowercase host of `url` (leading `www.` stripped); '' if unparseable."""
    try:
        netloc = urlsplit(url).netloc.lower()
    except ValueError:
        return ""
    host = netloc.split("@")[-1].split(":")[0]
    return host[4:] if host.startswith("www.") else host


def _path_segments(url: str) -> list[str]:
    """The non-empty PATH segments of `url` ONLY — scheme/host/userinfo/query/fragment excluded.

    id-binding (SEC-Q4) is asserted against these segments, never the raw URL string: smuggling the
    entry id into a `?ref=<id>` query, a `#<id>` fragment, a `user@<id>@host` userinfo, or the host
    itself must NOT satisfy the binding. `urlsplit` isolates `.path`; splitting on `/` makes the
    match segment-anchored (an arbitrary `<id>` substring inside one segment also does not count).
    """
    try:
        path = urlsplit(url).path
    except ValueError:
        return []
    return [seg for seg in path.split("/") if seg]


def _is_id_bound(host: str, segments: list[str], entry_id: str) -> bool:
    """True iff `segments` carry `entry_id` as a PATH SEGMENT under a trusted provenance shape.

    * github.com → ONLY the curated GHSA-database path `github.com/advisories/<entry_id>`: the
      first two path segments must be exactly `["advisories", <entry_id>]`. The per-project branch
      (`github.com/<owner>/<repo>/security/advisories/<GHSA>`) is DELIBERATELY NOT trusted — that
      path is fully attacker-owned and the GHSA id there is self-minted (it IS their watchlist row),
      so id-matching it proves nothing (HIGH-1 decision (a): drop the per-project branch). Residual:
      a real advisory that exists ONLY as a repo draft (not yet in the GHSA database) must cite a
      vendor-host / osv.dev mirror instead; the human draft-PR review (ADR-012, never auto-merge) is
      the compensating control.
    * vendor / osv.dev / nvd hosts → `entry_id` may be ANY path segment (e.g.
      `osv.dev/vulnerability/<id>`, `socket.dev/npm/package/<id>`) — these hosts are themselves
      curated advisory authorities, so segment-membership under the allow-listed host is the binding.
    """
    if host == "github.com":
        return len(segments) >= 2 and segments[0] == "advisories" and segments[1] == entry_id
    return entry_id in segments


def provenance_error(entry: dict) -> str | None:
    """SEC-Q4 id-bound provenance. Returns a FIXED reason string if NO `references[].url` is on the
    advisory-host allow-list AND id-bound (per `_is_id_bound`); None if at least one qualifies.

    The binding is asserted against PATH SEGMENTS (`_path_segments`), never the raw URL — so the
    entry id smuggled into a query/fragment/userinfo/host, or as an arbitrary substring, does NOT
    pass (HIGH-1). The reason NEVER embeds the url value (value-plane guard, SEC-Q5).
    """
    entry_id = entry.get("id")
    refs = entry.get("references")
    if not isinstance(entry_id, str) or not entry_id or not isinstance(refs, list):
        return REASONS["provenance"]
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        url = ref.get("url")
        if not isinstance(url, str) or not url:
            continue
        host = _host(url)
        if host not in ADVISORY_HOSTS:
            continue
        if _is_id_bound(host, _path_segments(url), entry_id):
            return None
    return REASONS["provenance"]


def _normalize(obj):
    """YAML/JSON dates → ISO strings (defensive; OSV is JSON so this is mostly a no-op)."""
    if isinstance(obj, dict):
        return {k: _normalize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize(v) for v in obj]
    if isinstance(obj, _dt.datetime):
        return obj.date().isoformat()
    if isinstance(obj, _dt.date):
        return obj.isoformat()
    return obj


def _schema_error_line(e) -> str:
    """One agent-facing schema-error line that NEVER echoes the attacker's REJECTED value (SEC-Q5).

    jsonschema's `e.message` interpolates the offending instance value for `enum`/`pattern`/`type`
    (and the offending KEY for `additionalProperties`) — so prose / a `javascript:` url injected into
    a field would reach stdout, the channel the orchestrating agent reads (HIGH-2). Instead emit
    `<json-path>: schema:<keyword>` — the JSON-path (schema-defined key names) + the violated keyword.
    For `required`, additionally name the missing key(s) computed from schema+structure
    (`validator_value` minus the present instance keys) — that key name is the SCHEMA's, never an
    attacker value, so it is safe and keeps the line actionable.
    """
    path = "/".join(str(p) for p in e.path) or "<root>"
    line = f"{path}: schema:{e.validator}"
    if e.validator == "required" and isinstance(e.instance, dict):
        try:
            missing = [k for k in e.validator_value if k not in e.instance]
        except TypeError:
            missing = []
        if missing:
            line += f" (missing: {','.join(map(str, missing))})"
    return line


def _schema_errors(entry: dict, schema: dict) -> list[str]:
    """Draft-2020-12 schema errors (keyword + json-path only; NEVER the rejected value — SEC-Q5)."""
    validator = Draft202012Validator(schema)
    return [
        _schema_error_line(e)
        for e in sorted(validator.iter_errors(_normalize(entry)), key=lambda e: list(e.path))
    ]


def _related_kb_error(entry: dict, kb_reference_dir: Path | None = None) -> str | None:
    """SEC-Q5: check database_specific.related_kb resolves to a real ai-attack-kb/reference/*.md.

    Returns a FIXED reason string (structural key name only, never the feed value) if the
    field is present and dangling; None if absent or resolving. Path is computed deterministically
    relative to the skills root — no network, no LLM (Policy 5).
    """
    db_specific = entry.get("database_specific")
    if not isinstance(db_specific, dict):
        return None
    related_kb = db_specific.get("related_kb")
    if related_kb is None:
        return None  # field absent → no check needed
    if not isinstance(related_kb, str):
        return None  # type errors are caught by the schema; don't double-report here
    # related_kb must be a BARE filename (schema: 'Relative filename', e.g. 'supply-chain-2.md').
    # Reject any path component / traversal / absolute path BEFORE the resolve: the reference dir
    # is flat (ADR-005, one level deep) and an absolute path must never enter committed watchlist
    # data (public-repo, repo-relative-only rule). This also forecloses a basename-collision where
    # a misleading prefix (e.g. 'evil/supply-chain-1.md') would otherwise resolve by basename.
    if related_kb != Path(related_kb).name:
        return REASONS["related_kb_dangling"]
    kb_dir = kb_reference_dir if kb_reference_dir is not None else _KB_REFERENCE_DIR
    candidate = Path(kb_dir) / related_kb
    if not candidate.is_file():
        return REASONS["related_kb_dangling"]
    return None


def validate_entry(entry: dict, schema: dict | None = None,
                   kb_reference_dir: Path | None = None) -> list[str]:
    """Schema (2) + id-bound provenance (1) + related_kb resolve (4) errors for ONE entry.

    Regression (3) is a corpus/dir-level check (`regression_errors`) driven by --check-regression,
    not a single-entry property, so it is not folded in here.

    `kb_reference_dir` overrides the default `_KB_REFERENCE_DIR` (used in tests to point at a
    fixture dir or a real KB path without depending on a specific machine layout).
    """
    schema = schema if schema is not None else load_schema()
    errors = _schema_errors(entry, schema)
    prov = provenance_error(entry)
    if prov is not None:
        errors.append(prov)
    kb_err = _related_kb_error(entry, kb_reference_dir)
    if kb_err is not None:
        errors.append(kb_err)
    return errors


def validate_bytes(raw: bytes, schema: dict | None = None) -> tuple[str | None, list[str]]:
    """Validate ONE entry from its raw bytes. Returns (entry_id_or_None, errors).

    Parses `json.loads` from the SAME buffer the caller will hash for the verdict — so the sha256
    binds the EXACT bytes that were validated, with no second read that a swap could exploit (MED-3
    / SEC-Q2 TOCTOU). Never raises on bad input.
    """
    schema = schema if schema is not None else load_schema()
    try:
        entry = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None, [REASONS["unreadable"]]
    if not isinstance(entry, dict):
        return None, [REASONS["top_level_not_object"]]
    return entry.get("id"), validate_entry(entry, schema)


def validate_file(path: Path, schema: dict | None = None) -> tuple[str | None, list[str]]:
    """Validate one entry file (reads its bytes ONCE). Returns (entry_id_or_None, errors)."""
    schema = schema if schema is not None else load_schema()
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return None, [REASONS["unreadable"]]
    return validate_bytes(raw, schema)


def _regression_errors_from_buffers(
    buffers: list[tuple[Path, bytes]], schema: dict | None = None
) -> list[str]:
    """(3) regression-green over already-read (file, bytes) buffers — the SAME bytes that were
    validated and (on a mint) hashed (MED-3 / SEC-Q2 TOCTOU).

    Builds the candidate `{name: set[versions]}` db from the buffers via `malware_db._accumulate`
    (the deps-scan values-only fold — not re-implemented here) and asserts the version-aware
    `is_known_bad` round-trip: every explicit `affected[].versions` row → True; a fabricated clean
    sibling of the SAME package → False (exact-set, never substring). A package whose `versions` is
    absent/[] folds to the wildcard `"*"` — every version then flags True, so the clean-sibling
    assertion is skipped for that package (it is intentionally a "*"). FIXED reason strings only.
    """
    docs: list[tuple[Path, dict]] = []
    db: dict[str, set[str]] = {}
    for f, raw in buffers:
        try:
            entry = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(entry, dict):
            continue
        docs.append((f, entry))
        _accumulate(entry, db)  # deps-scan fold over the SAME validated bytes

    errors: list[str] = []
    for f, entry in docs:
        for aff in entry.get("affected", []) or []:
            if not isinstance(aff, dict):
                continue
            pkg = aff.get("package") or {}
            name = pkg.get("name")
            versions = aff.get("versions")
            if not isinstance(name, str) or not name:
                continue
            if isinstance(versions, list) and versions:
                for v in versions:
                    if not is_known_bad(name, str(v), db):
                        errors.append(f"{f.name}: {REASONS['regression']}")
                # a fabricated sibling NOT in the bad set must flag False (unless wildcard).
                sibling = _clean_sibling({str(x) for x in versions})
                if "*" not in db.get(name, set()) and is_known_bad(name, sibling, db):
                    errors.append(f"{f.name}: {REASONS['regression']}")
    return errors


def regression_errors(path: Path, schema: dict | None = None) -> list[str]:
    """(3) regression-green for a path (reads each file's bytes ONCE, then delegates to the buffer
    core). The db is folded via `malware_db._accumulate` — the SAME values-only fold
    `malware_db.load_malware_db` performs walking the dir — so the predicate the deps-scan loader
    feeds (the regression suite this gate asserts green against) is what is exercised here. Library
    entry point used by the tests.
    """
    path = Path(path)
    files = sorted(path.glob("*.json")) if path.is_dir() else ([path] if path.exists() else [])
    buffers: list[tuple[Path, bytes]] = []
    for f in files:
        try:
            buffers.append((f, f.read_bytes()))
        except OSError:
            continue
    return _regression_errors_from_buffers(buffers, schema)


def _clean_sibling(bad_versions: set[str]) -> str:
    """A version string guaranteed NOT in `bad_versions` (for the != regression assertion)."""
    candidate = "0.0.0-clean-sibling"
    while candidate in bad_versions:
        candidate += ".x"
    return candidate


def _validate_buffers(
    buffers: list[tuple[Path, bytes]], schema: dict | None = None
) -> list[str]:
    """Schema + provenance + cross-file unique-id over already-read (file, bytes) buffers.

    Validates each entry FROM its buffer (`validate_bytes`) — the same bytes `main` hashes for the
    verdict — so no file is re-read between validation and minting (MED-3 / SEC-Q2 TOCTOU).
    """
    schema = schema if schema is not None else load_schema()
    all_errors: list[str] = []
    seen: dict[str, str] = {}
    for f, raw in buffers:
        fid, errs = validate_bytes(raw, schema)
        all_errors.extend(f"{f.name}: {e}" for e in errs)
        if fid is not None:
            if fid in seen:
                all_errors.append(f"duplicate id {fid}: {f.name} and {seen[fid]}")
            else:
                seen[fid] = f.name
    return all_errors


def validate_dir(path: Path, schema: dict | None = None) -> list[str]:
    """Validate every *.json entry in a directory; add a cross-file unique-id check."""
    schema = schema if schema is not None else load_schema()
    path = Path(path)
    files = sorted(path.glob("*.json")) if path.is_dir() else ([path] if path.exists() else [])
    if not files:
        return [f"no *.json watchlist entries found under {path}"]
    buffers: list[tuple[Path, bytes]] = []
    errors: list[str] = []
    for f in files:
        try:
            buffers.append((f, f.read_bytes()))
        except OSError:
            errors.append(f"{f.name}: {REASONS['unreadable']}")
    return _validate_buffers(buffers, schema) + errors


def mint_verdict(target: Path, validated_bytes: bytes, verdict: str, out_path: Path) -> dict:
    """Write the content-bound DATA verdict (ADR-026 §3) and return it.

    Shape == {verdict, path, sha256, validated}: `sha256` is hashlib.sha256 of the EXACT bytes that
    were validated (content-bound — `gate_data_edit.py` recomputes the write-target's hash and
    blocks on mismatch/replay, so a KEEP for one candidate cannot admit a poisoned different one;
    SEC-Q2). `validated` is an ISO-8601 UTC timestamp. Consumption is wh-hxt.6 (this MINTS only).
    """
    record = {
        "verdict": verdict,
        "path": str(target),
        "sha256": hashlib.sha256(validated_bytes).hexdigest(),
        "validated": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }
    Path(out_path).write_text(json.dumps(record, indent=2) + "\n")
    return record


def _parse_args(argv: list[str]) -> tuple[list[str], bool, str | None]:
    """Return (targets, check_regression, mint_path). Handles `--mint-verdict <path>`."""
    targets: list[str] = []
    check_regression = False
    mint_path: str | None = None
    it = iter(argv)
    for a in it:
        if a == "--check-regression":
            check_regression = True
        elif a == "--mint-verdict":
            mint_path = next(it, None)
        elif a.startswith("--mint-verdict="):
            mint_path = a.split("=", 1)[1]
        elif a.startswith("-"):
            continue  # unknown flag: ignore
        else:
            targets.append(a)
    return targets, check_regression, mint_path


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    targets, check_regression, mint_path = _parse_args(argv)
    if not targets:
        print("usage: validate_watchlist.py <file-or-dir> [--check-regression] [--mint-verdict <out>]")
        return 2

    schema = load_schema()
    rc = 0
    for t in targets:
        tp = Path(t)
        # Read each candidate file's bytes ONCE; validate FROM those buffers and (on a mint) hash
        # the SAME buffers — no second read a swap could exploit (MED-3 / SEC-Q2 TOCTOU).
        files = sorted(tp.glob("*.json")) if tp.is_dir() else ([tp] if tp.exists() else [])
        buffers: list[tuple[Path, bytes]] = []
        read_errors: list[str] = []
        for f in files:
            try:
                buffers.append((f, f.read_bytes()))
            except OSError:
                read_errors.append(f"{f.name}: {REASONS['unreadable']}")

        errors = _validate_buffers(buffers, schema) + read_errors
        if not files:
            errors.append(f"no *.json watchlist entries found under {tp}")
        if check_regression:
            errors += _regression_errors_from_buffers(buffers, schema)

        if errors:
            rc = 1
            print(f"INVALID {t}:")
            for e in errors:
                print(f"  - {e}")
        else:
            print(f"OK {t}")
            if mint_path is not None:
                # content-bound verdict over the EXACT validated buffers (not a re-read).
                raw = b"".join(b for _, b in buffers)
                mint_verdict(tp, raw, "KEEP", Path(mint_path))
    return rc


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
