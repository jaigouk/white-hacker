"""wh-4k9 — S8 version-aware match (fix the name-only false-positive bomb).

Before this ticket `signal_s8` matched a dependency by NAME ONLY
(`if d["name"] in malware_db`), so a watchlist entry for a popular compromised package
(LiteLLM, @tanstack/*) flagged EVERY user — not just the bad versions. This module pins
the version-aware behavior:

  * a dep at a SAFE resolved version (from the lockfile) + a SPECIFIC-version db entry
    must NOT flag (the FP fix), while a wildcard "*" entry in the SAME project still does;
  * a dep at the BAD resolved version flags;
  * a RANGE spec with no lockfile flags ONLY against a wildcard entry, never a specific
    version (that is exactly the FP we are removing);
  * an EXACT manifest pin with no lockfile counts as resolved (npm "1.2.3";
    pypi "==1.2.3" / bare "1.2.3");
  * resolved-version extraction from package-lock.json (v2/v3 + legacy), poetry.lock,
    uv.lock attaches an OPTIONAL `"resolved"` key; an absent lockfile leaves it off.

Rule 9 (tests verify intent): every invariant pins BOTH `== expected` AND `!= wrong`.

Run: `nice -n 10 uv run --project plugins/white-hacker/skills/deps-scan/scripts \
    --with jsonschema --with pytest pytest \
    plugins/white-hacker/skills/deps-scan/scripts/tests -q`
"""
from __future__ import annotations

import json
import pathlib

import supply_chain as sc

_BAD = "evil-pkg"            # the watchlisted compromised name
_CLEAN = "react"            # allowlisted control — must never fire on S8


def _scenarios(doc: dict) -> list[str]:
    return [f["exploit_scenario"] for f in doc["findings"]]


def _fired_s8(doc: dict, name: str) -> bool:
    return any(f"{name} @" in s and "S8" in s for s in _scenarios(doc))


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
    """A package-lock.json lockfileVersion 3 (`packages` map keyed by node_modules path)."""
    packages: dict = {"": {"name": "app"}}
    for name, version in name_to_version.items():
        packages[f"node_modules/{name}"] = {"version": version}
    return {"name": "app", "lockfileVersion": 3, "packages": packages}


# --------------------------------------------------------------------------- #
# (a) bad pkg at a SAFE resolved version (lockfile present) + specific-version
#     db entry → S8 does NOT flag (the FP fix); a wildcard entry in the SAME
#     project DOES flag (the != pair).
# --------------------------------------------------------------------------- #
def test_safe_resolved_version_with_specific_db_entry_does_not_flag(tmp_path):
    proj = _write_npm(
        tmp_path / "app",
        {_BAD: "^1.0.0"},
        lockfile=_lock_v3({_BAD: "2.5.0"}),  # resolved to a version NOT in {"1.2.3"}
    )
    db = {_BAD: {"1.2.3"}}  # only 1.2.3 is bad
    doc = sc.scan(str(proj), malware_db=db)
    # == expected: a safe resolved version of a watchlisted name does NOT flag
    assert _fired_s8(doc, _BAD) is False


def test_wildcard_db_entry_flags_even_at_a_safe_looking_version(tmp_path):
    proj = _write_npm(
        tmp_path / "app",
        {_BAD: "^1.0.0"},
        lockfile=_lock_v3({_BAD: "2.5.0"}),
    )
    db = {_BAD: {"*"}}  # the WHOLE package is bad
    doc = sc.scan(str(proj), malware_db=db)
    # != wrong pair: a wildcard entry flags regardless of the resolved version
    assert _fired_s8(doc, _BAD) is True


# --------------------------------------------------------------------------- #
# (b) bad pkg at the BAD resolved version (lockfile) → flags.
# --------------------------------------------------------------------------- #
def test_bad_resolved_version_flags(tmp_path):
    proj = _write_npm(
        tmp_path / "app",
        {_BAD: "^1.0.0"},
        lockfile=_lock_v3({_BAD: "1.2.3"}),  # resolved to the exact bad version
    )
    db = {_BAD: {"1.2.3"}}
    doc = sc.scan(str(proj), malware_db=db)
    assert _fired_s8(doc, _BAD) is True           # == expected
    # != wrong: the clean control is never dragged in
    assert _fired_s8(doc, _CLEAN) is False


# --------------------------------------------------------------------------- #
# (c) RANGE spec, NO lockfile, specific-version entry → does NOT flag;
#     wildcard entry → flags.
# --------------------------------------------------------------------------- #
def test_range_without_lockfile_specific_entry_does_not_flag(tmp_path):
    proj = _write_npm(tmp_path / "app", {_BAD: "^1.0.0"})  # no lockfile at all
    db = {_BAD: {"1.2.3"}}
    doc = sc.scan(str(proj), malware_db=db)
    # == expected: an unresolved range must NOT flag against a specific-version entry
    assert _fired_s8(doc, _BAD) is False


def test_range_without_lockfile_wildcard_entry_flags(tmp_path):
    proj = _write_npm(tmp_path / "app", {_BAD: "^1.0.0"})
    db = {_BAD: {"*"}}
    doc = sc.scan(str(proj), malware_db=db)
    # != wrong pair: a wildcard entry still flags an unresolved range
    assert _fired_s8(doc, _BAD) is True


# --------------------------------------------------------------------------- #
# (d) EXACT manifest pin with no lockfile + db {"1.2.3"} → flags;
#     same pin + db {"9.9.9"} → does not.
# --------------------------------------------------------------------------- #
def test_exact_npm_pin_no_lockfile_flags_on_matching_db(tmp_path):
    proj = _write_npm(tmp_path / "app", {_BAD: "1.2.3"})  # plain literal = resolved
    db = {_BAD: {"1.2.3"}}
    doc = sc.scan(str(proj), malware_db=db)
    assert _fired_s8(doc, _BAD) is True            # == expected


def test_exact_npm_pin_no_lockfile_does_not_flag_on_other_version(tmp_path):
    proj = _write_npm(tmp_path / "app", {_BAD: "1.2.3"})
    db = {_BAD: {"9.9.9"}}
    doc = sc.scan(str(proj), malware_db=db)
    # != wrong: the pinned version is NOT the bad one → no flag
    assert _fired_s8(doc, _BAD) is False


# --------------------------------------------------------------------------- #
# _exact_pin — the settled exact-pin rule (npm literal / pypi ==/bare).
# --------------------------------------------------------------------------- #
def test_exact_pin_recognizes_plain_literals_and_rejects_ranges():
    # npm plain version literal → resolved
    assert sc._exact_pin("1.0.0") == "1.0.0"
    assert sc._exact_pin("2.5.0-rc.1") == "2.5.0-rc.1"
    # pypi == pin and bare version → resolved (strip the ==)
    assert sc._exact_pin("==1.0.0") == "1.0.0"
    assert sc._exact_pin("== 1.0.0") == "1.0.0"
    # != wrong: every range / wildcard / vcs spec is NOT an exact pin
    assert sc._exact_pin("^1.0.0") is None
    assert sc._exact_pin("~1.0.0") is None
    assert sc._exact_pin(">=1.0.0") is None
    assert sc._exact_pin("*") is None
    assert sc._exact_pin("latest") is None
    assert sc._exact_pin("1.0.0 - 2.0.0") is None
    assert sc._exact_pin("git+https://example.com/x.git") is None
    assert sc._exact_pin("") is None


# --------------------------------------------------------------------------- #
# (e) lockfile extraction unit tests — resolved attached; absent → no "resolved".
# --------------------------------------------------------------------------- #
def test_parse_npm_attaches_resolved_from_lockfile_v3(tmp_path):
    proj = _write_npm(
        tmp_path / "app",
        {_BAD: "^1.0.0", _CLEAN: "^18.0.0"},
        lockfile=_lock_v3({_BAD: "1.2.3", _CLEAN: "18.2.0"}),
    )
    norm = sc.parse_npm(str(proj))
    by_name = {d["name"]: d for d in norm["deps"]}
    assert by_name[_BAD]["resolved"] == "1.2.3"    # == expected
    assert by_name[_CLEAN]["resolved"] == "18.2.0"
    # != wrong: the additive key does not corrupt the pinned dep shape
    assert by_name[_BAD]["name"] == _BAD
    assert by_name[_BAD]["spec"] == "^1.0.0"
    assert by_name[_BAD]["source_type"] == "registry"


def test_parse_npm_legacy_dependencies_lockfile_v1(tmp_path):
    # lockfileVersion 1 has no `packages` map — fall back to the legacy `dependencies`.
    lock = {"name": "app", "lockfileVersion": 1,
            "dependencies": {_BAD: {"version": "3.1.4"}}}
    proj = _write_npm(tmp_path / "app", {_BAD: "^3.0.0"}, lockfile=lock)
    norm = sc.parse_npm(str(proj))
    by_name = {d["name"]: d for d in norm["deps"]}
    assert by_name[_BAD]["resolved"] == "3.1.4"    # == expected from legacy map
    assert by_name[_BAD]["resolved"] != "^3.0.0"   # != wrong (not the manifest spec)


def test_parse_npm_no_lockfile_leaves_resolved_absent(tmp_path):
    proj = _write_npm(tmp_path / "app", {_BAD: "^1.0.0"})  # no lockfile
    norm = sc.parse_npm(str(proj))
    by_name = {d["name"]: d for d in norm["deps"]}
    # == expected: an absent lockfile means NO resolved key (additive, optional)
    assert "resolved" not in by_name[_BAD]


def test_parse_pypi_attaches_resolved_from_poetry_lock(tmp_path):
    proj = tmp_path / "app"
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "app"\ndependencies = ["evil-pkg >=1.0.0"]\n'
    )
    (proj / "poetry.lock").write_text(
        '[[package]]\nname = "evil-pkg"\nversion = "1.2.3"\n'
        'description = ""\noptional = false\n'
    )
    norm = sc.parse_pypi(str(proj))
    by_name = {d["name"]: d for d in norm["deps"]}
    assert by_name["evil-pkg"]["resolved"] == "1.2.3"   # == expected
    assert by_name["evil-pkg"]["resolved"] != ">=1.0.0"  # != wrong


def test_parse_pypi_attaches_resolved_from_uv_lock(tmp_path):
    proj = tmp_path / "app"
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "app"\ndependencies = ["evil-pkg >=1.0.0"]\n'
    )
    (proj / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "evil-pkg"\nversion = "4.5.6"\n'
    )
    norm = sc.parse_pypi(str(proj))
    by_name = {d["name"]: d for d in norm["deps"]}
    assert by_name["evil-pkg"]["resolved"] == "4.5.6"   # == expected
    assert by_name["evil-pkg"]["resolved"] != ">=1.0.0"  # != wrong


def test_parse_pypi_no_lockfile_leaves_resolved_absent(tmp_path):
    proj = tmp_path / "app"
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "app"\ndependencies = ["evil-pkg >=1.0.0"]\n'
    )
    norm = sc.parse_pypi(str(proj))
    by_name = {d["name"]: d for d in norm["deps"]}
    # == expected: no poetry.lock / uv.lock → no resolved key
    assert "resolved" not in by_name["evil-pkg"]


# --------------------------------------------------------------------------- #
# TL finding 1 — `_exact_pin` recall gap: a semver carrying BOTH a pre-release AND
# a build-metadata segment (`1.0.0-beta+meta`) is still an EXACT pin, not a range.
# --------------------------------------------------------------------------- #
def test_exact_pin_accepts_prerelease_and_build_metadata():
    # pre-release + build-metadata together → still an exact pin (== expected)
    assert sc._exact_pin("1.0.0-beta+meta") == "1.0.0-beta+meta"
    assert sc._exact_pin("1.0.0-rc.1+build.7") == "1.0.0-rc.1+build.7"
    # build-metadata alone is also exact
    assert sc._exact_pin("1.0.0+build.7") == "1.0.0+build.7"
    # != wrong: a range/operator with a pre-release tail is NOT an exact pin
    assert sc._exact_pin("^1.0.0-beta+meta") is None
    assert sc._exact_pin(">=1.0.0-rc.1") is None


def test_exact_npm_pin_prerelease_build_flags_on_matching_db(tmp_path):
    pin = "1.0.0-beta+meta"
    proj = _write_npm(tmp_path / "app", {_BAD: pin})  # exact pin, no lockfile
    doc = sc.scan(str(proj), malware_db={_BAD: {pin}})
    assert _fired_s8(doc, _BAD) is True            # == expected: exact pin matches


def test_exact_npm_pin_prerelease_build_does_not_flag_on_other_version(tmp_path):
    proj = _write_npm(tmp_path / "app", {_BAD: "1.0.0-beta+meta"})
    doc = sc.scan(str(proj), malware_db={_BAD: {"9.9.9"}})
    # != wrong: the pinned pre-release+build version is NOT the bad one → no flag
    assert _fired_s8(doc, _BAD) is False


# --------------------------------------------------------------------------- #
# TL finding 2 — `_resolved_npm` v3 collision: the same bare name at two depths must
# resolve to the SHALLOWEST (top-level) path, so a nested SAFE copy listed FIRST in a
# hand-ordered / tampered lockfile cannot shadow the top-level BAD pin.
# --------------------------------------------------------------------------- #
def _lock_v3_packages(packages: dict) -> dict:
    return {"name": "app", "lockfileVersion": 3, "packages": packages}


def test_resolved_npm_prefers_shallowest_path_on_name_collision(tmp_path):
    # nested SAFE copy (9.9.9) listed BEFORE the top-level BAD pin (1.2.3) on disk.
    lock = _lock_v3_packages({
        "": {"name": "app"},
        f"node_modules/other/node_modules/{_BAD}": {"version": "9.9.9"},  # deep, first
        f"node_modules/{_BAD}": {"version": "1.2.3"},                     # top-level
    })
    proj = _write_npm(tmp_path / "app", {_BAD: "^1.0.0"}, lockfile=lock)
    norm = sc.parse_npm(str(proj))
    by_name = {d["name"]: d for d in norm["deps"]}
    # == expected: the shallowest path wins, not the first-seen nested copy
    assert by_name[_BAD]["resolved"] == "1.2.3"
    assert by_name[_BAD]["resolved"] != "9.9.9"    # != wrong (no nested shadowing)


def test_s8_flags_top_level_bad_despite_nested_safe_copy_listed_first(tmp_path):
    lock = _lock_v3_packages({
        "": {"name": "app"},
        f"node_modules/other/node_modules/{_BAD}": {"version": "9.9.9"},  # safe, first
        f"node_modules/{_BAD}": {"version": "1.2.3"},                     # bad, top-level
    })
    proj = _write_npm(tmp_path / "app", {_BAD: "^1.0.0"}, lockfile=lock)
    doc = sc.scan(str(proj), malware_db={_BAD: {"1.2.3"}})
    # == expected: the tampered ordering cannot suppress the top-level bad-version hit
    assert _fired_s8(doc, _BAD) is True
