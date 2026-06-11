"""wh-2v5 — fully-offline S8 end-to-end smoke test.

The OTHER S8 tests cover the pieces in isolation:
  * `test_malware_db.py` exercises `load_malware_db` over a fixture;
  * `test_supply_chain.py:test_s8_known_bad_match_when_snapshot_present` scans with a
    HAND-BUILT `db = {"evil-pkg": "*"}`.
Neither wires the REAL operator flow end-to-end. This smoke test does: it builds an
on-disk snapshot shaped exactly like `ossf/malicious-packages` (the wh-8qw target) —
`osv/malicious/<ecosystem>/<pkg>/MAL-*.json` OSV docs — points the real
`load_malware_db` at it, and scans a manifest that names those packages. It proves the
S8 path the operator will wire (`scan(project, malware_db=load_malware_db("<snapshot>/osv"))`)
fires offline, AND that it degrades cleanly when the snapshot is absent.

Fully offline, stdlib-only, NO network (the inputs are SYNTHETIC inert OSV metadata —
package NAMES only, never real malware). Rule 9: every invariant pins BOTH `== expected`
AND `!= wrong`.

This smoke test targets the SNAPSHOT path only, so every `load_malware_db` call pins
`curated_path=None` to opt out of the bundled curated watchlist (wh-k6l) — otherwise the
`set(db) == {...}` exact-equality probe would fold the canonical seed once it lands.

Run: `uv run --project plugins/white-hacker/skills/deps-scan/scripts --with pytest \
    pytest plugins/white-hacker/skills/deps-scan/scripts/tests/test_s8_offline_smoke.py -q`
"""
from __future__ import annotations

import json
import pathlib

import malware_db as mdb
import supply_chain as sc
import validate_findings as vf

# Two SYNTHETIC known-bad npm package names (never real packages). One is recorded with
# an explicit `versions` list, the other range-only (no `versions`) → wildcard "*".
_BAD_EXPLICIT = "evil-flatmap-stream-smoke"   # versions: ["1.2.3"]
_BAD_WILDCARD = "slopsquat-smoke-pkg"         # no versions → "*"
_CLEAN = "react"                              # allowlisted control — must never fire


def _osv_doc(mal_id: str, name: str, versions: list[str] | None) -> dict:
    """One OSV document in the exact ossf/malicious-packages shape consumed by the loader."""
    affected: dict = {"package": {"ecosystem": "npm", "name": name}}
    if versions is not None:
        affected["versions"] = versions
    return {
        "schema_version": "1.6.0",
        "id": mal_id,
        "summary": "SYNTHETIC smoke-test fixture — inert detection metadata, not a real advisory.",
        "modified": "2026-06-08T00:00:00Z",
        "affected": [affected],
    }


def _write_ossf_snapshot(root: pathlib.Path) -> pathlib.Path:
    """Materialize an `osv/malicious/npm/<pkg>/MAL-*.json` tree (the real ossf layout) and
    return the dir the operator points `load_malware_db` at (the snapshot's `osv/`)."""
    osv = root / "osv" / "malicious" / "npm"
    cases = [
        ("MAL-2026-9001", _BAD_EXPLICIT, ["1.2.3"]),
        ("MAL-2026-9002", _BAD_WILDCARD, None),
    ]
    for mal_id, name, versions in cases:
        d = osv / name
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{mal_id}.json").write_text(json.dumps(_osv_doc(mal_id, name, versions), indent=2))
    return root / "osv"


def _write_project(project_dir: pathlib.Path, deps: dict) -> pathlib.Path:
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "package.json").write_text(json.dumps({"name": "app", "dependencies": deps}))
    (project_dir / "package-lock.json").write_text("{}\n")  # lockfile present → no S3 noise
    return project_dir


def _scenarios(doc: dict) -> list[str]:
    return [f["exploit_scenario"] for f in doc["findings"]]


# --------------------------------------------------------------------------- #
# 1) the loader builds {name: set[versions]} from the on-disk OSSF-shaped tree
# --------------------------------------------------------------------------- #
def test_loader_builds_db_from_ossf_shaped_snapshot(tmp_path):
    osv_dir = _write_ossf_snapshot(tmp_path / "malicious-packages")
    db = mdb.load_malware_db(osv_dir, curated_path=None)

    assert db[_BAD_EXPLICIT] == {"1.2.3"}          # explicit list → exactly those versions
    assert db[_BAD_WILDCARD] == {"*"}              # range-only → whole package bad
    assert set(db) == {_BAD_EXPLICIT, _BAD_WILDCARD}
    # != wrong: no over-eager wildcard, no empty set, no leakage of a clean name
    assert db[_BAD_EXPLICIT] != {"*"}
    assert db[_BAD_EXPLICIT] != set()
    assert _CLEAN not in db


# --------------------------------------------------------------------------- #
# 2) THE SMOKE TEST — load -> scan -> S8 fires end-to-end, offline
# --------------------------------------------------------------------------- #
def test_s8_fires_end_to_end_from_on_disk_snapshot(tmp_path):
    osv_dir = _write_ossf_snapshot(tmp_path / "malicious-packages")
    db = mdb.load_malware_db(osv_dir, curated_path=None)              # the REAL loader, not a hand-built dict
    proj = _write_project(
        tmp_path / "app",
        {_BAD_EXPLICIT: "1.2.3", _BAD_WILDCARD: "0.0.1", _CLEAN: "18.2.0"},
    )

    doc = sc.scan(str(proj), malware_db=db)
    findings = doc["findings"]

    # both known-bad deps fire as HIGH S8 supply-chain candidates (== expected)
    for bad in (_BAD_EXPLICIT, _BAD_WILDCARD):
        hit = next((f for f in findings if f"{bad} @" in f["exploit_scenario"]), None)
        assert hit is not None, f"S8 did not fire for {bad}"
        assert hit["severity"] == "HIGH"
        assert hit["category"] == "supply-chain"
        assert "S8" in hit["exploit_scenario"]

    # != wrong: the clean control never fires, and S8 is no longer degraded
    assert not any(f"{_CLEAN} @" in s for s in _scenarios(doc))
    assert "malware-db" not in doc["summary"]["tools_unavailable"]
    # the emitted document is schema-valid
    assert vf.validate(doc) == []


# --------------------------------------------------------------------------- #
# 3) S8 is VERSION-AWARE (wh-4k9) — a specific-version watchlist entry must NOT
#    flag a user pinned to a DIFFERENT, safe version (the name-only FP fix). A
#    wildcard "*" entry in the SAME project still flags (the != pair).
# --------------------------------------------------------------------------- #
def test_s8_version_mismatch_does_not_flag(tmp_path):
    osv_dir = _write_ossf_snapshot(tmp_path / "malicious-packages")
    db = mdb.load_malware_db(osv_dir, curated_path=None)
    # _BAD_EXPLICIT is bad ONLY at {"1.2.3"}; _BAD_WILDCARD is bad at any version ("*").
    # Pin _BAD_EXPLICIT to 9.9.9 (a SAFE version not in its set) — under version-aware
    # matching it must NOT flag — while _BAD_WILDCARD in the same project still flags.
    proj = _write_project(
        tmp_path / "app", {_BAD_EXPLICIT: "9.9.9", _BAD_WILDCARD: "0.0.1"}
    )

    doc = sc.scan(str(proj), malware_db=db)
    scens = _scenarios(doc)
    # == expected: the safe-version pin of a specific-version entry does NOT flag
    assert not any(f"{_BAD_EXPLICIT} @" in s for s in scens)
    # != wrong pair: the wildcard entry in the SAME project DOES still flag
    assert any(f"{_BAD_WILDCARD} @" in s and "S8" in s for s in scens)


# --------------------------------------------------------------------------- #
# 4) degraded contrast — no snapshot -> S8 silent + records malware-db, never raises
# --------------------------------------------------------------------------- #
def test_s8_degrades_without_snapshot(tmp_path):
    proj = _write_project(
        tmp_path / "app",
        {_BAD_EXPLICIT: "1.2.3", _BAD_WILDCARD: "0.0.1", _CLEAN: "18.2.0"},
    )

    doc = sc.scan(str(proj))  # no malware_db passed → S8 degrades

    # == expected: the known-bad deps do NOT fire (S8 had no snapshot to match against)
    assert not any(f"{_BAD_EXPLICIT} @" in s for s in _scenarios(doc))
    assert not any(f"{_BAD_WILDCARD} @" in s for s in _scenarios(doc))
    # and the degradation is recorded (!= wrong: not silently dropped)
    assert "malware-db" in doc["summary"]["tools_unavailable"]
    assert doc["summary"]["tools_unavailable"] != []
    assert vf.validate(doc) == []


# --------------------------------------------------------------------------- #
# 5) the SAME project flips bad->clean purely on snapshot presence (the operator switch)
# --------------------------------------------------------------------------- #
def test_snapshot_presence_is_the_only_difference(tmp_path):
    osv_dir = _write_ossf_snapshot(tmp_path / "malicious-packages")
    proj = _write_project(tmp_path / "app", {_BAD_EXPLICIT: "1.2.3"})

    without = sc.scan(str(proj))
    with_db = sc.scan(str(proj), malware_db=mdb.load_malware_db(osv_dir, curated_path=None))

    fired_without = any(f"{_BAD_EXPLICIT} @" in s for s in _scenarios(without))
    fired_with = any(f"{_BAD_EXPLICIT} @" in s for s in _scenarios(with_db))
    # the ONLY change is the snapshot: absent -> silent, present -> S8 fires
    assert fired_without is False
    assert fired_with is True
