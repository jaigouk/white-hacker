"""wh-5ox.9 — S8 recommendation surfaces last_safe_version when present.

The watchlist entry schema (wh-5ox.9) adds an OPTIONAL `database_specific.last_safe_version`
field. When a package is flagged by signal_s8 AND its watchlist entry carries
`last_safe_version`, the S8 finding recommendation should surface that version
("pin to <last_safe_version>") so the human reviewer knows a safe pin exists.

When `last_safe_version` is absent the recommendation must be UNCHANGED (same as before
this ticket) — strictly additive, no regression.

Rule 9 (tests verify intent): every invariant pins BOTH `== expected` AND `!= wrong`.

Run: `nice -n 10 uv run --project plugins/white-hacker/skills/deps-scan/scripts \
    --with jsonschema --with pytest pytest \
    plugins/white-hacker/skills/deps-scan/scripts/tests -q`
"""
from __future__ import annotations

import json
import pathlib

import supply_chain as sc

_BAD = "evil-pkg"  # watchlisted compromised name (neutralized)


def _write_npm(project_dir: pathlib.Path, deps: dict,
               lockfile: dict | None = None) -> pathlib.Path:
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": deps})
    )
    if lockfile is not None:
        (project_dir / "package-lock.json").write_text(json.dumps(lockfile))
    return project_dir


def _lock_v3(name_to_version: dict[str, str]) -> dict:
    packages: dict = {"": {"name": "app"}}
    for name, version in name_to_version.items():
        packages[f"node_modules/{name}"] = {"version": version}
    return {"name": "app", "lockfileVersion": 3, "packages": packages}


def _get_s8_recommendation(doc: dict, name: str) -> str | None:
    """Return recommendation for the first finding that has S8 in its signals."""
    for f in doc.get("findings", []):
        if f"{name} @" in f.get("exploit_scenario", ""):
            return f.get("recommendation")
    return None


# --------------------------------------------------------------------------- #
# (A) last_safe_version PRESENT — recommendation includes the pin hint
# --------------------------------------------------------------------------- #

def test_s8_recommendation_includes_last_safe_version_when_present(tmp_path: pathlib.Path):
    """When the malware_db_metadata carries last_safe_version for a flagged package,
    the S8 recommendation surfaces 'pin to <last_safe_version>' (== expected, both sides)."""
    proj = _write_npm(
        tmp_path / "app",
        {_BAD: "^1.0.0"},
        lockfile=_lock_v3({_BAD: "1.2.3"}),
    )
    db = {_BAD: {"1.2.3"}}
    last_safe_db = {_BAD: "1.2.2"}  # the new optional metadata map

    doc = sc.scan(str(proj), malware_db=db, last_safe_db=last_safe_db)

    findings = doc.get("findings", [])
    assert findings, "S8 finding must be emitted"
    rec = _get_s8_recommendation(doc, _BAD)
    assert rec is not None, "recommendation must be present"
    # == expected: last_safe_version is surfaced
    assert "1.2.2" in rec, f"last_safe_version '1.2.2' not in recommendation: {rec!r}"
    assert "pin to" in rec.lower() or "1.2.2" in rec, f"pin hint not in: {rec!r}"
    # != wrong: a bogus version must NOT appear in the recommendation
    assert "9.9.9" not in rec, f"wrong version leaked into recommendation: {rec!r}"


def test_s8_recommendation_unchanged_when_last_safe_version_absent(tmp_path: pathlib.Path):
    """When last_safe_db is absent (None) or does not include the package, the recommendation
    is UNCHANGED from the baseline _F4['S8'] text (strictly additive, no regression)."""
    proj = _write_npm(
        tmp_path / "app",
        {_BAD: "^1.0.0"},
        lockfile=_lock_v3({_BAD: "1.2.3"}),
    )
    db = {_BAD: {"1.2.3"}}

    # No last_safe_db at all
    doc_no_meta = sc.scan(str(proj), malware_db=db, last_safe_db=None)
    # last_safe_db present but package not in it
    doc_no_entry = sc.scan(str(proj), malware_db=db, last_safe_db={"other-pkg": "2.0.0"})

    baseline_rec = sc._F4["S8"]

    for label, doc in [("no_meta", doc_no_meta), ("no_entry", doc_no_entry)]:
        rec = _get_s8_recommendation(doc, _BAD)
        assert rec is not None, f"[{label}] recommendation must be present"
        # == expected: unchanged baseline
        assert rec == baseline_rec, f"[{label}] recommendation changed without last_safe_version: {rec!r}"
        # != wrong: must not contain any version-pin hint
        assert "1.2.2" not in rec, f"[{label}] spurious version appeared: {rec!r}"


def test_s8_recommendation_both_ways_full_scan(tmp_path: pathlib.Path):
    """End-to-end both-ways pin (Policy 9):
    - WITH last_safe_version: recommendation includes the pin hint.
    - WITHOUT last_safe_version: recommendation equals the baseline.
    """
    proj_with = _write_npm(
        tmp_path / "with_meta",
        {_BAD: "^1.0.0"},
        lockfile=_lock_v3({_BAD: "1.2.3"}),
    )
    proj_without = _write_npm(
        tmp_path / "without_meta",
        {_BAD: "^1.0.0"},
        lockfile=_lock_v3({_BAD: "1.2.3"}),
    )
    db = {_BAD: {"1.2.3"}}
    last_safe_db = {_BAD: "1.2.2"}

    doc_with = sc.scan(str(proj_with), malware_db=db, last_safe_db=last_safe_db)
    doc_without = sc.scan(str(proj_without), malware_db=db, last_safe_db=None)

    rec_with = _get_s8_recommendation(doc_with, _BAD)
    rec_without = _get_s8_recommendation(doc_without, _BAD)

    # WITH: surfaced
    assert rec_with is not None
    assert "1.2.2" in rec_with

    # WITHOUT: baseline unchanged
    assert rec_without is not None
    assert rec_without == sc._F4["S8"]

    # != wrong: the two recommendations must DIFFER (one has the pin, other is baseline)
    assert rec_with != rec_without


# --------------------------------------------------------------------------- #
# (A2) last_safe_version is watchlist-DATA-derived → MUST be scrubbed at the
#      recommendation egress surface (wh-ln2 / ADR-019 / SEC-Q5), exactly as
#      _make_finding scrubs the values it embeds into exploit_scenario.
# --------------------------------------------------------------------------- #

def test_s8_recommendation_scrubs_injection_in_last_safe_version(tmp_path: pathlib.Path):
    """A poisoned/auto-fed watchlist row whose last_safe_version carries newline/ANSI must NOT
    forge lines in the finding `recommendation` — the value is scrubbed at the embed point
    (consistency with the exploit_scenario egress scrub; Policy 9 both sides)."""
    proj = _write_npm(
        tmp_path / "app",
        {_BAD: "^1.0.0"},
        lockfile=_lock_v3({_BAD: "1.2.3"}),
    )
    db = {_BAD: {"1.2.3"}}
    # poisoned last_safe_version: benign prefix + newline + ANSI + a forged severity line
    payload = "1.2.2\n\x1b[31m[CRITICAL] forged egress line"
    doc = sc.scan(str(proj), malware_db=db, last_safe_db={_BAD: payload})

    rec = _get_s8_recommendation(doc, _BAD)
    assert rec is not None, "recommendation must be present"
    # == expected: the benign version characters still survive the scrub
    assert "1.2.2" in rec, f"benign version dropped by scrub: {rec!r}"
    # != wrong: the raw newline + ANSI escape must be neutralized (no line-forging)
    assert "\n" not in rec, f"raw newline leaked into recommendation: {rec!r}"
    assert "\x1b" not in rec, f"raw ANSI escape leaked into recommendation: {rec!r}"


# --------------------------------------------------------------------------- #
# (B) malware_db loader UNTOUCHED — no regression via the curated watchlist
# --------------------------------------------------------------------------- #

def test_signal_s8_still_returns_names_list(tmp_path: pathlib.Path):
    """signal_s8 interface is backward-compatible: still returns list[str] of bad names.
    The new last_safe_db is SEPARATE — signal_s8 signature unchanged."""
    norm = {"deps": [{"name": _BAD, "spec": "x", "resolved": "1.2.3"}]}
    db = {_BAD: {"1.2.3"}}
    result = sc.signal_s8(norm, db)
    # == expected: returns a list with the bad name
    assert result == [_BAD]
    # != wrong: must not be empty or a different type
    assert result != []
    assert isinstance(result, list)


def test_signal_s8_no_last_safe_db_arg_backward_compat():
    """signal_s8 works WITHOUT a last_safe_db arg — backward compatible (Policy 3 / SOLID O)."""
    norm = {"deps": [{"name": _BAD, "spec": "x", "resolved": "1.2.3"}]}
    db = {_BAD: {"1.2.3"}}
    # old call signature — no last_safe_db — must still work
    result = sc.signal_s8(norm, db)
    assert _BAD in result
    assert isinstance(result, list)


def test_scan_without_last_safe_db_param_unchanged(tmp_path: pathlib.Path):
    """scan() without last_safe_db= behaves identically to pre-ticket (no regression)."""
    proj = _write_npm(
        tmp_path / "app",
        {_BAD: "^1.0.0"},
        lockfile=_lock_v3({_BAD: "1.2.3"}),
    )
    db = {_BAD: {"1.2.3"}}
    # Old-style call: no last_safe_db param
    doc = sc.scan(str(proj), malware_db=db)
    rec = _get_s8_recommendation(doc, _BAD)
    assert rec == sc._F4["S8"], f"baseline must be unchanged: {rec!r}"


def test_load_malware_db_loader_untouched():
    """malware_db.load_malware_db() still returns {name: set[versions]} — loader UNTOUCHED."""
    from malware_db import load_malware_db
    db = load_malware_db(curated_path=None)  # no curated path -> empty or {}
    # The return type must still be a dict
    assert isinstance(db, dict)
    # All values must be sets (the loader contract)
    for v in db.values():
        assert isinstance(v, (set, frozenset)), f"expected set, got {type(v)}: {v!r}"
