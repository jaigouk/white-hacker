"""wh-07w — deps-scan supply-chain-malware floor (S1–S8) tests.

TDD, RED first. The floor is OFFLINE + static: it reads a manifest + lockfile + the
referenced install scripts and emits low/medium-confidence `tool_assisted:false`
candidates for NOVEL malware that CVE-based SCA structurally misses (spike-09 F2). It
NEVER blocks — triage + a human decide.

Rule 9 (tests verify intent): every invariant pins BOTH `== expected` AND `!= wrong`.

Key guards required by the ticket:
  * a benign native-build pkg (`postinstall:"node-gyp rebuild"` + a pinned registry dep)
    must produce NO finding (the headline false-positive guard);
  * the degraded path (no malware-db snapshot) must list `malware-db` in
    `tools_unavailable` and NEVER raise;
  * every emitted document must validate via `validate_findings.validate(doc) == []`.

Run: `uv run --with jsonschema --with pytest pytest \
    plugins/white-hacker/skills/deps-scan/scripts/tests -q`
"""
from __future__ import annotations

import json
import pathlib

import pytest

import supply_chain as sc
import validate_findings as vf


# --------------------------------------------------------------------------- #
# helpers — write a tiny npm project into tmp_path
# --------------------------------------------------------------------------- #
def _write(project_dir: pathlib.Path, package_json: dict,
           lockfile: str | None = "package-lock.json",
           scripts_files: dict[str, str] | None = None) -> pathlib.Path:
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "package.json").write_text(json.dumps(package_json))
    if lockfile is not None:
        (project_dir / lockfile).write_text("{}\n" if lockfile.endswith(".json") else "\n")
    for rel, body in (scripts_files or {}).items():
        p = project_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return project_dir


def _emitted(doc: dict) -> list[dict]:
    return doc["findings"]


# A clearly INERT, commented, non-functional install script that nonetheless
# contains the detection-trigger *strings* (S6). This is detection test data, the
# same discipline as the eval corpus's neutralized filenames — NEVER functional.
_INERT_DANGEROUS_POSTINSTALL = (
    "// SAMPLE (inert) — detection test data only, does nothing.\n"
    "// would call child_process.exec(...) to run a shell\n"
    "// would eval(...) a remote string and fetch( ) it over the network\n"
    "// would read ~/.npmrc and ~/.ssh and Buffer.from(x,'base64')\n"
    "module.exports = function () { /* no-op: see comments above */ };\n"
)


# --------------------------------------------------------------------------- #
# damerau_levenshtein — the S4 distance primitive
# --------------------------------------------------------------------------- #
def test_damerau_levenshtein_distances():
    # exact match = 0 (SAFE), single edits = 1, transposition = 1, two edits = 2
    assert sc.damerau_levenshtein("react", "react") == 0
    assert sc.damerau_levenshtein("react", "raect") == 1   # transposition
    assert sc.damerau_levenshtein("axios", "axois") == 1   # transposition
    assert sc.damerau_levenshtein("openai", "0penai") == 1  # substitution
    assert sc.damerau_levenshtein("express", "expres") == 1  # deletion
    assert sc.damerau_levenshtein("react", "reactt") == 1   # insertion
    # NOT the wrong value: distinct names are far apart, identical names are not "1"
    assert sc.damerau_levenshtein("react", "react") != 1
    assert sc.damerau_levenshtein("react", "lodash") >= 3


# --------------------------------------------------------------------------- #
# the npm ADAPTER — parse_npm
# --------------------------------------------------------------------------- #
def test_parse_npm_normalizes_struct(tmp_path):
    proj = _write(tmp_path / "p", {
        "dependencies": {"react": "18.2.0"},
        "devDependencies": {"local-tool": "file:../local-tool"},
        "scripts": {"postinstall": "node scripts/postinstall.js", "test": "jest"},
    }, scripts_files={"scripts/postinstall.js": "// inert\n"})
    norm = sc.parse_npm(str(proj))

    assert norm["lockfile_present"] is True
    assert norm["lockfile_present"] != False  # noqa: E712 — pin the wrong value too
    # S1: only install-lifecycle scripts are surfaced, NOT `test`
    assert norm["lifecycle_scripts"].get("postinstall") == "node scripts/postinstall.js"
    assert "test" not in norm["lifecycle_scripts"]
    names = {d["name"]: d for d in norm["deps"]}
    assert names["react"]["source_type"] == "registry"
    assert names["local-tool"]["source_type"] == "file"
    # the referenced install script resolved onto disk
    assert any(p.endswith("scripts/postinstall.js") for p in norm["script_files"])


def test_parse_npm_source_types(tmp_path):
    proj = _write(tmp_path / "p", {
        "dependencies": {
            "reg": "^1.0.0",
            "gitdep": "git+https://example.test/x.git#deadbeef",
            "urldep": "https://example.test/x.tgz",
            "ws": "workspace:*",
        },
    })
    by = {d["name"]: d["source_type"] for d in sc.parse_npm(str(proj))["deps"]}
    assert by["reg"] == "registry"
    assert by["gitdep"] == "git"
    assert by["urldep"] == "url"
    assert by["ws"] == "workspace"
    assert by["gitdep"] != "registry"  # the wrong classification


def test_parse_npm_never_raises_on_missing_or_odd_manifest(tmp_path):
    # no package.json at all → empty-but-well-formed struct, NO exception
    empty = tmp_path / "empty"
    empty.mkdir()
    norm = sc.parse_npm(str(empty))
    assert norm["deps"] == []
    assert norm["lockfile_present"] is False
    # junk package.json → still no raise
    junk = tmp_path / "junk"
    junk.mkdir()
    (junk / "package.json").write_text("{ not json ]")
    norm2 = sc.parse_npm(str(junk))
    assert norm2["deps"] == []


# --------------------------------------------------------------------------- #
# S4 — typosquat → MEDIUM candidate
# --------------------------------------------------------------------------- #
def test_typosquat_name_emits_medium_candidate(tmp_path):
    # "lodahs" is a distance-1 TRANSPOSITION of the allowlisted "lodash" — a pure S4
    # typosquat that does NOT fold-collide (so it is NOT the higher-signal S5). Pinned
    # versions + a lockfile keep S3 quiet; the inert benign script keeps S6/S7 quiet,
    # so S4 (MEDIUM) corroborates with S1 (lifecycle present) → a MEDIUM candidate.
    # (Contrast: a *doubled-char* squat like "expresss" folds onto "express" → S5 HIGH,
    # which the demo project exercises. "doubled chars" is an S5 tell per spike-09 §S5.)
    proj = _write(tmp_path / "p", {
        "dependencies": {"lodahs": "1.0.0"},
        "scripts": {"postinstall": "node scripts/postinstall.js"},
    }, scripts_files={"scripts/postinstall.js": "// inert\n"})
    doc = sc.scan(str(proj))
    f = _emitted(doc)
    assert len(f) >= 1
    cand = next(x for x in f if "lodahs" in x["exploit_scenario"])
    assert cand["severity"] == "MEDIUM"
    assert cand["severity"] != "HIGH"      # a pure-S4 typosquat is not HIGH
    assert cand["category"] == "supply-chain"
    assert cand["tool_assisted"] is False
    assert vf.validate(doc) == []


# --------------------------------------------------------------------------- #
# S5 — homoglyph / separator scope confusion → HIGH
# --------------------------------------------------------------------------- #
def test_homoglyph_separator_scope_emits_high(tmp_path):
    # "@anthropic_ai/sdk" folds (underscore→hyphen) onto the allowlisted
    # "@anthropic-ai/sdk" but the raw string DIFFERS → S5 HIGH.
    proj = _write(tmp_path / "p", {
        "dependencies": {"@anthropic_ai/sdk": "1.0.0"},
    })
    doc = sc.scan(str(proj))
    f = _emitted(doc)
    cand = next(x for x in f if "@anthropic_ai/sdk" in x["exploit_scenario"])
    assert cand["severity"] == "HIGH"
    assert cand["severity"] != "MEDIUM"    # homoglyph/separator collisions are HIGH
    assert vf.validate(doc) == []


def test_exact_allowlist_match_is_safe(tmp_path):
    # distance 0 = exact = SAFE: the real "@anthropic-ai/sdk" must NOT trip S4/S5.
    proj = _write(tmp_path / "p", {
        "dependencies": {"@anthropic-ai/sdk": "1.0.0", "react": "18.2.0"},
    })
    doc = sc.scan(str(proj))
    assert _emitted(doc) == []
    assert vf.validate(doc) == []


# --------------------------------------------------------------------------- #
# S6 — inert dangerous postinstall → HIGH
# --------------------------------------------------------------------------- #
def test_inert_dangerous_postinstall_emits_high(tmp_path):
    proj = _write(tmp_path / "p", {
        "dependencies": {"react": "18.2.0"},
        "scripts": {"postinstall": "node scripts/postinstall.js"},
    }, scripts_files={"scripts/postinstall.js": _INERT_DANGEROUS_POSTINSTALL})
    doc = sc.scan(str(proj))
    f = _emitted(doc)
    assert len(f) >= 1
    high = [x for x in f if x["severity"] == "HIGH"]
    assert high, "≥2 dangerous-API strings in an install script → S6 HIGH"
    # the recommendation routes to an F4 ladder rung (offline, do-not-build-yet)
    assert "ignore-scripts" in high[0]["recommendation"].lower()
    assert high[0]["tool_assisted"] is False
    # the dangerous script is reported PROJECT-LEVEL (keyed to the script file), NOT
    # fanned out as a per-dep finding against the clean `react` control dep.
    script_findings = [x for x in f if x["file"].endswith("postinstall.js")]
    assert len(script_findings) == 1
    assert not any("react @" in x["exploit_scenario"] for x in f)  # react stays clean
    assert vf.validate(doc) == []


# --------------------------------------------------------------------------- #
# THE HEADLINE FALSE-POSITIVE GUARD — benign native build must NOT trip
# --------------------------------------------------------------------------- #
def test_benign_native_build_pkg_yields_no_finding(tmp_path):
    # `node-gyp rebuild` is the canonical legit native-build postinstall (esbuild,
    # sharp, bcrypt). With a PINNED registry dep + a committed lockfile, S1 is the
    # ONLY signal — and a lone S1 is informational, never a candidate.
    proj = _write(tmp_path / "p", {
        "name": "native-thing",
        "dependencies": {"bcrypt": "5.1.1"},
        "scripts": {"postinstall": "node-gyp rebuild"},
    })
    doc = sc.scan(str(proj))
    assert _emitted(doc) == []            # NO finding — the key FP guard
    assert _emitted(doc) != [{}]          # (sanity: truly empty, not a stub)
    assert doc["summary"]["counts"] == {"high": 0, "medium": 0, "low": 0}
    assert vf.validate(doc) == []


# --------------------------------------------------------------------------- #
# S3 / scoring — lone signal is informational only (no finding)
# --------------------------------------------------------------------------- #
def test_missing_lockfile_alone_is_informational_only(tmp_path):
    # Unpinned ranges + NO lockfile = S3 alone. A lone S3 must NOT emit a candidate.
    proj = _write(tmp_path / "p", {
        "dependencies": {"react": "^18.0.0"},
    }, lockfile=None)
    doc = sc.scan(str(proj))
    assert _emitted(doc) == []            # lone S3 is informational, not a finding
    assert doc["summary"]["counts"]["medium"] == 0
    assert vf.validate(doc) == []


def test_lone_lifecycle_script_is_informational_only(tmp_path):
    # S1 with a totally benign script body + pinned dep + lockfile = lone S1.
    proj = _write(tmp_path / "p", {
        "dependencies": {"react": "18.2.0"},
        "scripts": {"postinstall": "node scripts/postinstall.js"},
    }, scripts_files={"scripts/postinstall.js": "console.log('built ok');\n"})
    doc = sc.scan(str(proj))
    assert _emitted(doc) == []            # lone S1 is informational
    assert vf.validate(doc) == []


# --------------------------------------------------------------------------- #
# scoring rule directly (HIGH-any OR ≥2 corroborating; lone S1/S3 → no emit)
# --------------------------------------------------------------------------- #
def test_score_rule():
    # any HIGH fires
    emit, sev = sc.score([{"signal": "S6", "severity": "HIGH"}])
    assert emit is True and sev == "HIGH"
    emit, sev = sc.score([{"signal": "S5", "severity": "HIGH"}])
    assert emit is True and sev == "HIGH"
    # ≥2 corroborating lower signals → emit MEDIUM
    emit, sev = sc.score([{"signal": "S1", "severity": "LOW"},
                          {"signal": "S4", "severity": "MEDIUM"}])
    assert emit is True and sev == "MEDIUM"
    # lone S1 → no emit; lone S3 → no emit
    assert sc.score([{"signal": "S1", "severity": "LOW"}]) == (False, "LOW")
    assert sc.score([{"signal": "S3", "severity": "LOW"}]) == (False, "LOW")
    # the wrong value: a lone low signal must NOT claim emit
    assert sc.score([{"signal": "S1", "severity": "LOW"}]) != (True, "LOW")


# --------------------------------------------------------------------------- #
# S2 — non-registry source dep (git) corroborates
# --------------------------------------------------------------------------- #
def test_git_source_dep_with_lifecycle_corroborates(tmp_path):
    # S2 (git URL) + S1 (lifecycle) = 2 corroborating signals → MEDIUM candidate.
    proj = _write(tmp_path / "p", {
        "dependencies": {"router": "git+https://example.test/router.git#deadbeef"},
        "scripts": {"preinstall": "node scripts/preinstall.js"},
    }, scripts_files={"scripts/preinstall.js": "// inert\n"})
    doc = sc.scan(str(proj))
    f = _emitted(doc)
    assert any(x["severity"] in {"MEDIUM", "HIGH"} for x in f)
    assert vf.validate(doc) == []


def test_workspace_and_file_deps_are_benign(tmp_path):
    # workspace:/file: to in-repo paths are benign per spike-09 S2 — even WITH a
    # lifecycle script they must not corroborate into a finding.
    proj = _write(tmp_path / "p", {
        "dependencies": {"pkg-a": "workspace:*", "pkg-b": "file:../pkg-b"},
        "scripts": {"postinstall": "node scripts/postinstall.js"},
    }, scripts_files={"scripts/postinstall.js": "console.log('ok');\n"})
    doc = sc.scan(str(proj))
    assert _emitted(doc) == []
    assert vf.validate(doc) == []


# --------------------------------------------------------------------------- #
# DEGRADED — no malware-db snapshot (S8) → records it, never raises
# --------------------------------------------------------------------------- #
def test_degraded_no_malware_db_lists_it_and_never_raises(tmp_path, monkeypatch):
    # wh-ezc: scan now loads the bundled curated watchlist by default (always-on).
    # Degrade = the curated file is absent/odd → load_malware_db returns {} → S8
    # still degrades cleanly and malware-db is recorded in tools_unavailable.
    monkeypatch.setattr(sc, "load_malware_db", lambda **_kw: {})
    proj = _write(tmp_path / "p", {"dependencies": {"react": "18.2.0"}})
    doc = sc.scan(str(proj))
    assert "malware-db" in doc["summary"]["tools_unavailable"]
    assert doc["summary"]["tools_unavailable"] != []  # the wrong value
    assert vf.validate(doc) == []


def test_s8_known_bad_match_when_snapshot_present(tmp_path):
    # When an offline OSSF/GHSA snapshot IS provided, an exact name match = HIGH (S8)
    # and `malware-db` is NO LONGER in tools_unavailable (the non-degraded path).
    proj = _write(tmp_path / "p", {"dependencies": {"evil-pkg": "1.0.0", "react": "18.2.0"}})
    db = {"evil-pkg": "*"}
    doc = sc.scan(str(proj), malware_db=db)
    f = _emitted(doc)
    evil = next(x for x in f if "evil-pkg @" in x["exploit_scenario"])
    assert evil["severity"] == "HIGH"
    assert "S8" in evil["exploit_scenario"]
    assert "malware-db" not in doc["summary"]["tools_unavailable"]  # not degraded now
    assert not any("react @" in x["exploit_scenario"] for x in f)   # control stays clean
    assert vf.validate(doc) == []


def test_scan_never_raises_on_missing_manifest(tmp_path):
    # wh-ezc: scan loads the bundled curated watchlist even on missing-manifest paths.
    # An empty dir has no manifest → degrade to empty findings (no ecosystem recognized).
    # malware-db is NOT in tools_unavailable when the curated file loads successfully.
    empty = tmp_path / "nothing"
    empty.mkdir()
    doc = sc.scan(str(empty))            # must degrade, not raise
    assert _emitted(doc) == []
    assert vf.validate(doc) == []


# --------------------------------------------------------------------------- #
# every emitted document validates + finding-field invariants
# --------------------------------------------------------------------------- #
def test_emitted_findings_carry_required_invariants(tmp_path):
    proj = _write(tmp_path / "p", {
        "dependencies": {"@anthropic_ai/sdk": "1.0.0"},
    })
    doc = sc.scan(str(proj))
    assert vf.validate(doc) == []
    assert vf.duplicate_ids(doc) == []
    for fnd in _emitted(doc):
        assert fnd["category"] == "supply-chain"
        assert fnd["owasp"] == ["A06:2021"]
        assert fnd["access_required"] == "unknown"
        assert fnd["verified"] == "static_review_only"
        assert fnd["tool_assisted"] is False
        assert fnd["confidence"] <= 0.8            # floor cap (degradation.py)
        assert fnd["kb_refs"] == ["AISEC-SUPPLY-CHAIN-001"]
        assert fnd["id"].startswith("F-")
        assert fnd["canonical_of"] is None
        assert fnd["line"] == 0
        assert fnd["preconditions"] == []
        # the wrong values:
        assert fnd["tool_assisted"] is not True
        assert fnd["access_required"] != "unauth-remote"


def test_emitted_findings_carry_kb_mitre_attribution(tmp_path):
    # wh-5ox.10: a supply-chain candidate matches AISEC-SUPPLY-CHAIN-001, so its MITRE
    # attribution is COPIED from that KB entry's xref (the verbatim supply-chain-1.md:21
    # subset). Pinned both ways: the right ids ARE present AND no dispute is fabricated.
    proj = _write(tmp_path / "p", {
        "dependencies": {"@anthropic_ai/sdk": "1.0.0"},   # S5 HIGH
    })
    doc = sc.scan(str(proj))
    f = _emitted(doc)
    cand = next(x for x in f if "@anthropic_ai/sdk" in x["exploit_scenario"])
    assert cand["att_ck"] == ["T1195.002", "T1552.005"]   # == the ATT&CK subset of the xref
    assert cand["atlas"] == ["AML.T0010"]                 # == the ATLAS subset
    assert cand["att_ck"] != []                           # != the no-match (empty) case
    assert "disputed" not in cand                         # the entry carries no dispute
    assert cand["kb_refs"] == ["AISEC-SUPPLY-CHAIN-001"]  # attribution didn't disturb kb_refs
    assert vf.validate(doc) == []


def test_demo_poc_scans_and_validates():
    """The committed demo project under docs/research/poc-supply-chain emits a
    valid candidate via the same scan() path the gate runs."""
    for cand in (pathlib.Path(__file__).resolve(), *pathlib.Path(__file__).resolve().parents):
        if (cand / ".git").exists():
            repo_root = cand
            break
    else:
        repo_root = pathlib.Path(__file__).resolve().parents[-1]
    demo = repo_root / "docs" / "research" / "poc-supply-chain"
    # wh-8lx: the committed demo lives in the repo (found via a `.git` walk); a minimal package
    # checkout / the Docker sandbox lacks it, so SKIP (not fail) when absent — keeps the suite portable.
    if not demo.exists():
        pytest.skip(f"repo demo fixture absent ({demo}) — e.g. the minimal deps-scan sandbox image")
    doc = sc.scan(str(demo))
    assert vf.validate(doc) == []
    assert _emitted(doc), "the demo's bad package must surface ≥1 candidate"


# --------------------------------------------------------------------------- #
# wh-7rk — out-of-tree kernel-module / DKMS pin-and-verify check (ADR-006).
#
# The DETECTION of kernel-module/DKMS PRESENCE is already done (wh-a49:
# detect_kernel_adjacency). This residual check is the supply-chain pin-and-verify
# floor: a `dkms.conf` OR an `obj-m` Makefile whose build FETCHES UNPINNED sources
# (curl/wget of an http(s) URL, or `git clone` without a pinned ref) is a
# supply-chain candidate; a PINNED source (immutable ref / digest-verified) is clean.
#
# The curl/wget/git strings below are INERT detection data — same discipline as the
# eval corpus's neutralized filenames. They are NEVER executed.
# --------------------------------------------------------------------------- #
_ADR006_REC = (
    "Pin the out-of-tree module / DKMS source by digest or an immutable ref and "
    "verify before build (ADR-006)."
)


def test_dkms_conf_unpinned_tarball_emits_supply_chain_candidate(tmp_path):
    # A dkms.conf whose POST_BUILD fetches an UNPINNED tarball over https → candidate.
    proj = tmp_path / "mod"
    proj.mkdir()
    (proj / "dkms.conf").write_text(
        'PACKAGE_NAME="acme-drv"\n'
        'PACKAGE_VERSION="1.0"\n'
        "# inert detection data — never executed:\n"
        "MAKE[0]=\"curl https://example.test/blob/acme-drv.tar.gz -o src.tgz && make\"\n"
    )
    doc = sc.scan(str(proj))
    f = _emitted(doc)
    assert len(f) >= 1, "an unpinned DKMS source fetch must surface a candidate"
    cand = next(x for x in f if "dkms.conf" in x["file"])
    assert cand["category"] == "supply-chain"
    assert cand["category"] != "injection"          # the wrong category
    assert cand["recommendation"] == _ADR006_REC
    assert "ADR-006" in cand["recommendation"]
    assert cand["severity"] in {"LOW", "MEDIUM"}
    assert cand["severity"] != "HIGH"               # advisory, not HIGH
    assert cand["access_required"] == "unknown"
    assert cand["verified"] == "static_review_only"
    assert cand["tool_assisted"] is False
    assert cand["tool_assisted"] is not True        # the wrong value
    assert cand["confidence"] <= 0.8                # floor cap
    assert vf.validate(doc) == []


def test_objm_makefile_unpinned_wget_emits_candidate(tmp_path):
    # An out-of-tree module Makefile (`obj-m`) whose recipe wgets an unpinned URL.
    proj = tmp_path / "mod"
    proj.mkdir()
    (proj / "Makefile").write_text(
        "obj-m += acme.o\n"
        "fetch:\n"
        "\t# inert detection data — never executed:\n"
        "\twget http://example.test/vendor/firmware.bin\n"
    )
    doc = sc.scan(str(proj))
    f = _emitted(doc)
    assert len(f) >= 1
    cand = next(x for x in f if x["file"].endswith("Makefile"))
    assert cand["category"] == "supply-chain"
    assert cand["recommendation"] == _ADR006_REC
    assert cand["severity"] != "HIGH"
    assert vf.validate(doc) == []


def test_objm_makefile_referenced_build_script_unpinned_git_clone(tmp_path):
    # The Makefile references a build script that does an UNPINNED `git clone`
    # (no `#<sha>` / `--branch <tag>` / immutable ref) → candidate against the script.
    proj = tmp_path / "mod"
    proj.mkdir()
    (proj / "Makefile").write_text(
        "obj-m += acme.o\n"
        "prepare:\n"
        "\tsh build.sh\n"
    )
    (proj / "build.sh").write_text(
        "#!/bin/sh\n"
        "# inert detection data — never executed:\n"
        "git clone https://example.test/acme/driver.git\n"
    )
    doc = sc.scan(str(proj))
    f = _emitted(doc)
    assert len(f) >= 1
    cand = next(x for x in f if x["file"].endswith("build.sh"))
    assert cand["category"] == "supply-chain"
    assert cand["recommendation"] == _ADR006_REC
    assert vf.validate(doc) == []


def test_dkms_conf_pinned_source_is_clean(tmp_path):
    # A PINNED source: `git clone --branch v1.2.3` (immutable tag) + a sha256-verified
    # tarball fetch → NO kernel-module finding (the headline false-positive guard).
    proj = tmp_path / "mod"
    proj.mkdir()
    (proj / "dkms.conf").write_text(
        'PACKAGE_NAME="acme-drv"\n'
        'PACKAGE_VERSION="1.0"\n'
        "# inert detection data — never executed:\n"
        "PRE_BUILD=\"git clone --branch v1.2.3 https://example.test/acme/driver.git\"\n"
        "MAKE[0]=\"curl https://example.test/x.tar.gz -o s.tgz && "
        "echo 'abc123...  s.tgz' | sha256sum -c - && make\"\n"
    )
    doc = sc.scan(str(proj))
    assert not any(x["recommendation"] == _ADR006_REC for x in _emitted(doc))
    assert vf.validate(doc) == []


def test_objm_makefile_pinned_git_clone_is_clean(tmp_path):
    # `git clone ... #<sha>` style pin (commit pinned) → NO finding.
    proj = tmp_path / "mod"
    proj.mkdir()
    (proj / "Makefile").write_text(
        "obj-m += acme.o\n"
        "prepare:\n"
        "\t# inert detection data — never executed:\n"
        "\tgit clone --branch v2.0.0 https://example.test/acme/driver.git\n"
    )
    doc = sc.scan(str(proj))
    assert not any(x["recommendation"] == _ADR006_REC for x in _emitted(doc))
    assert vf.validate(doc) == []


def test_no_kernel_or_dkms_files_yields_no_kernel_finding(tmp_path):
    # A repo with NO kernel-module / dkms files must produce NO kernel-module finding,
    # even if an ordinary Makefile (without `obj-m`) fetches an unpinned URL.
    proj = tmp_path / "mod"
    proj.mkdir()
    (proj / "Makefile").write_text(
        "all:\n"
        "\tcurl https://example.test/x.tar.gz -o s.tgz\n"  # not obj-m → out of scope
    )
    doc = sc.scan(str(proj))
    assert not any(x["recommendation"] == _ADR006_REC for x in _emitted(doc))
    assert vf.validate(doc) == []


def test_scan_kernel_module_sources_pure_fn_returns_list(tmp_path):
    # The recognizer is a pure function returning a list[findings]; clean repo → [].
    empty = tmp_path / "empty"
    empty.mkdir()
    out = sc.scan_kernel_module_sources(str(empty))
    assert out == []
    assert out is not None                          # the wrong value (None)
    # an unpinned obj-m Makefile → exactly one ADR-006 candidate from the pure fn
    proj = tmp_path / "mod"
    proj.mkdir()
    (proj / "Makefile").write_text(
        "obj-m += acme.o\n"
        "fetch:\n"
        "\twget https://example.test/x.tar.gz\n"
    )
    hits = sc.scan_kernel_module_sources(str(proj))
    assert len(hits) == 1
    assert hits[0]["recommendation"] == _ADR006_REC
    assert hits[0]["category"] == "supply-chain"


def test_kernel_module_finding_does_not_break_existing_npm_path(tmp_path):
    # A project that has BOTH a package.json (npm ecosystem) AND an unpinned obj-m
    # Makefile: the npm path still works AND the kernel-module candidate appears.
    proj = tmp_path / "mod"
    proj.mkdir()
    (proj / "package.json").write_text(json.dumps({"dependencies": {"react": "18.2.0"}}))
    (proj / "package-lock.json").write_text("{}\n")
    (proj / "Makefile").write_text(
        "obj-m += acme.o\n"
        "fetch:\n"
        "\tcurl https://example.test/x.tar.gz -o s.tgz\n"
    )
    doc = sc.scan(str(proj))
    f = _emitted(doc)
    assert any(x["recommendation"] == _ADR006_REC for x in f), "kernel candidate present"
    # ids are unique across the merged finding set
    assert vf.duplicate_ids(doc) == []
    assert vf.validate(doc) == []


# --------------------------------------------------------------------------- #
# repo-relative paths — public-repo invariant (finding-schema `^[^/~]`)
# --------------------------------------------------------------------------- #
def test_findings_emit_repo_relative_paths_not_absolute(tmp_path):
    # Scanning an ABSOLUTE project_dir must NOT leak that path into file / first_link /
    # prose — finding-schema rejects a leading '/' or '~'. Rule 9: pin BOTH directions
    # (relative kept == expected AND the absolute root != emitted anywhere).
    proj = _write(
        tmp_path / "proj",
        {"name": "app", "dependencies": {"expresss": "1.0.0"},  # S4/S5 typosquat of express
         "scripts": {"postinstall": "node scripts/postinstall.js"}},
        scripts_files={"scripts/postinstall.js": _INERT_DANGEROUS_POSTINSTALL},
    )
    doc = sc.scan(str(proj))
    findings = _emitted(doc)
    assert findings, "expected >=1 finding (typosquat + dangerous postinstall)"
    abs_root = str(proj)
    for f in findings:
        assert not f["file"].startswith(("/", "~")), f"absolute file leaked: {f['file']}"
        assert abs_root not in f["file"], f"absolute project_dir leaked: {f['file']}"
        assert abs_root not in f.get("first_link", ""), "absolute path leaked in first_link"
        assert abs_root not in f.get("exploit_scenario", ""), "absolute path leaked in prose"
    # the manifest-keyed finding is the bare repo-relative name, not an absolute path
    assert any(f["file"] == "package.json" for f in findings)
    # the script-keyed finding keeps its repo-relative subpath
    assert any(f["file"] == "scripts/postinstall.js" for f in findings)
    assert vf.validate(doc) == []


# --------------------------------------------------------------------------- #
# wh-ezc — always-on bundled watchlist (scan loads curated floor by default)
# --------------------------------------------------------------------------- #

def _write_pypi(project_dir: pathlib.Path, requirements: str) -> pathlib.Path:
    """Write a minimal PyPI project with only a requirements.txt."""
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "requirements.txt").write_text(requirements)
    return project_dir


def test_s8_always_on_no_malware_db_arg_flags_curated_entry(tmp_path):
    """(a) Always-on: scan(project_dir) with NO malware_db arg and NO snapshot
    flags litellm==1.82.7 (bundled watchlist seed) via S8 HIGH.
    A sibling pinning litellm==1.82.6 (clean version) is NOT flagged.

    Policy 9: pin both == expected AND != the wrong value.
    """
    # positive case: litellm 1.82.7 is in the bundled curated watchlist (GHSA-5mg7-485q-xm76)
    proj_bad = _write_pypi(
        tmp_path / "bad",
        "litellm==1.82.7\n",
    )
    doc_bad = sc.scan(str(proj_bad))
    bad_findings = _emitted(doc_bad)
    s8_hits = [x for x in bad_findings if "S8" in x.get("exploit_scenario", "")]
    assert len(s8_hits) >= 1, "litellm@1.82.7 must be flagged via S8 (bundled watchlist)"
    assert s8_hits[0]["severity"] == "HIGH"
    assert s8_hits[0]["severity"] != "MEDIUM"  # S8 is always HIGH, not MEDIUM
    assert "litellm" in s8_hits[0]["exploit_scenario"]
    # malware-db should NOT be in tools_unavailable (curated file is loaded)
    assert "malware-db" not in doc_bad["summary"]["tools_unavailable"]
    assert vf.validate(doc_bad) == []

    # negative case: litellm 1.82.6 (clean version — NOT in the watchlist) must NOT be flagged
    proj_clean = _write_pypi(
        tmp_path / "clean",
        "litellm==1.82.6\n",
    )
    doc_clean = sc.scan(str(proj_clean))
    clean_s8 = [x for x in _emitted(doc_clean) if "S8" in x.get("exploit_scenario", "")]
    assert clean_s8 == [], "litellm@1.82.6 (clean version) must NOT be flagged by S8"
    assert clean_s8 != [{"severity": "HIGH"}]  # the wrong value: clean sibling is not flagged


def test_s8_degrade_when_curated_file_absent(tmp_path, monkeypatch):
    """(b) Degrade: when load_malware_db returns {} (e.g. curated file missing),
    scan returns empty S8, tools_unavailable records 'malware-db', and never raises.

    Policy 9: pin both the empty finding list AND the tools_unavailable presence.
    """
    # monkeypatch load_malware_db in supply_chain to return an empty db (simulates
    # missing curated file — load_malware_db never raises, so this is the degrade path)
    monkeypatch.setattr(sc, "load_malware_db", lambda **_kw: {})

    proj = _write_pypi(tmp_path / "p", "litellm==1.82.7\n")
    doc = sc.scan(str(proj))
    s8_hits = [x for x in _emitted(doc) if "S8" in x.get("exploit_scenario", "")]
    assert s8_hits == [], "empty malware-db → S8 must return [] (degrade, not raise)"
    assert s8_hits != [{"severity": "HIGH"}]  # the wrong value: degrade path is never HIGH S8
    # tools_unavailable records malware-db so the caller knows S8 was degraded
    assert "malware-db" in doc["summary"]["tools_unavailable"]
    assert doc["summary"]["tools_unavailable"] != []   # the wrong value: must be recorded
    assert vf.validate(doc) == []


def test_s8_caller_db_unioned_with_bundled_floor(tmp_path):
    """(c) Union: a caller-supplied malware_db dict is honored AND unioned with the
    bundled curated floor — not silently replaced.

    The curated floor seeds litellm@1.82.7/1.82.8.  The caller adds evil-extra@1.0.0.
    Both must appear as S8 findings; react (control) must stay clean.

    Policy 9: assert both present == expected AND react != flagged.
    """
    proj = _write_pypi(
        tmp_path / "p",
        "litellm==1.82.7\nevil-extra==1.0.0\nrequests==2.31.0\n",
    )
    caller_db: dict = {"evil-extra": {"1.0.0"}}
    doc = sc.scan(str(proj), malware_db=caller_db)
    findings = _emitted(doc)

    # the bundled floor entry (litellm@1.82.7) must still be present
    litellm_hits = [x for x in findings if "litellm" in x.get("exploit_scenario", "")
                    and "S8" in x.get("exploit_scenario", "")]
    assert litellm_hits, "bundled floor entry litellm@1.82.7 must survive union with caller db"
    assert litellm_hits[0]["severity"] == "HIGH"

    # the caller-supplied entry (evil-extra@1.0.0) must also be present
    evil_hits = [x for x in findings if "evil-extra" in x.get("exploit_scenario", "")]
    assert evil_hits, "caller-supplied evil-extra@1.0.0 must be flagged by S8"
    assert evil_hits[0]["severity"] == "HIGH"
    assert evil_hits[0]["severity"] != "MEDIUM"  # S8 is always HIGH

    # malware-db must NOT be in tools_unavailable (non-empty union db)
    assert "malware-db" not in doc["summary"]["tools_unavailable"]

    # control: requests is benign (not in watchlist)
    requests_hits = [x for x in findings if "requests @" in x.get("exploit_scenario", "")]
    assert requests_hits == []   # clean dep must stay clean
    assert vf.validate(doc) == []


def test_s8_caller_db_list_typed_value_unions_without_raise(tmp_path):
    """wh-ezc N-1 regression: a caller db whose value is a LIST/TUPLE (not a set or a
    scalar) must UNION with the bundled floor WITHOUT raising — the union loop must
    normalize list/tuple/set/frozenset/scalar values to a hashable set.

    Before the fix, `{["1.0.0"]}` raised `TypeError: unhashable type: 'list'`, crashing
    scan() and breaking the "never raises" contract.

    Policy 9: assert caller-evil@1.0.0 IS flagged (== flagged) AND a clean control
    package is NOT flagged (!= flagged), AND scan() does not raise.
    """
    proj = _write_pypi(
        tmp_path / "p",
        "caller-evil==1.0.0\nrequests==2.31.0\n",
    )
    # LIST-typed value (the N-1 crash trigger) — must be normalized, not wrapped in a set
    caller_db: dict = {"caller-evil": ["1.0.0"]}
    doc = sc.scan(str(proj), malware_db=caller_db)  # must NOT raise TypeError
    findings = _emitted(doc)

    # the list-typed caller entry is flagged via S8 HIGH
    evil_hits = [x for x in findings if "caller-evil" in x.get("exploit_scenario", "")
                 and "S8" in x.get("exploit_scenario", "")]
    assert evil_hits, "caller-evil@1.0.0 (list-typed value) must be flagged by S8"
    assert evil_hits[0]["severity"] == "HIGH"
    assert evil_hits[0]["severity"] != "MEDIUM"  # S8 is always HIGH

    # the bundled floor survives the union (litellm seed still present in the db, though
    # not pinned in THIS manifest) — malware-db is NOT recorded unavailable
    assert "malware-db" not in doc["summary"]["tools_unavailable"]

    # control: requests is benign (not in watchlist nor caller db)
    requests_hits = [x for x in findings if "requests @" in x.get("exploit_scenario", "")]
    assert requests_hits == []   # clean dep must stay clean (!= flagged)
    assert vf.validate(doc) == []


def test_s8_union_tolerates_unhashable_caller_value_no_raise(tmp_path):
    """wh-5ox.18 NIT 2: a malformed caller-db value that is UNHASHABLE (a dict) must NOT
    raise — `_as_set` str()-coerces every value, so the "union never raises" contract holds
    on the bundled-present path too. Before the fix `_as_set`'s `{v}` raised
    `TypeError: unhashable type: 'dict'`, crashing scan() for the whole project.

    Policy 9: scan() does not raise AND a real string-valued sibling entry still flags
    (== flagged) AND a clean control stays clean (!= flagged).
    """
    proj = _write_pypi(tmp_path / "p", "evil-extra==1.0.0\nrequests==2.31.0\n")
    # the union loop runs `_as_set` over EVERY caller entry, so the unhashable `weird-pkg`
    # value trips the crash regardless of the manifest — the N-2 trigger.
    caller_db: dict = {"evil-extra": {"1.0.0"}, "weird-pkg": {"meta": {"nested": 1}}}
    doc = sc.scan(str(proj), malware_db=caller_db)  # must NOT raise TypeError
    findings = _emitted(doc)

    evil_hits = [x for x in findings if "evil-extra" in x.get("exploit_scenario", "")
                 and "S8" in x.get("exploit_scenario", "")]
    assert evil_hits, "string-valued evil-extra@1.0.0 still flagged despite the unhashable sibling"
    assert evil_hits[0]["severity"] == "HIGH"
    assert "malware-db" not in doc["summary"]["tools_unavailable"]
    requests_hits = [x for x in findings if "requests @" in x.get("exploit_scenario", "")]
    assert requests_hits == []   # clean dep stays clean (!= flagged)
    assert vf.validate(doc) == []


def test_s8_bundled_empty_path_normalizes_caller_db(tmp_path, monkeypatch):
    """wh-5ox.18 NIT 1: when the bundled floor is empty (curated file absent/odd), the caller
    db must STILL be normalized + honored — pre-fix the `elif bundled:` branch was skipped, so
    the caller db's handling depended on which path ran. This pins the symmetry: a list-typed
    caller value still flags on the bundled-empty path (and scan stays raise-free + schema-valid).
    """
    monkeypatch.setattr(sc, "load_malware_db", lambda: {})  # force the degraded (empty) floor
    proj = _write_pypi(tmp_path / "p", "caller-evil==1.0.0\nrequests==2.31.0\n")
    caller_db: dict = {"caller-evil": ["1.0.0"]}  # list-typed value, bundled-empty path
    doc = sc.scan(str(proj), malware_db=caller_db)  # must NOT raise; caller db normalized
    findings = _emitted(doc)

    evil_hits = [x for x in findings if "caller-evil" in x.get("exploit_scenario", "")
                 and "S8" in x.get("exploit_scenario", "")]
    assert evil_hits, "caller-evil@1.0.0 flagged even with an empty bundled floor (symmetric path)"
    assert evil_hits[0]["severity"] == "HIGH"
    requests_hits = [x for x in findings if "requests @" in x.get("exploit_scenario", "")]
    assert requests_hits == []   # clean dep stays clean (!= flagged)
    assert vf.validate(doc) == []


# --------------------------------------------------------------------------- #
# wh-8ci — S3 `_unpinned` 'x'-in-name false positive (BOTH fix (a) AND fix (b))
#
# `_unpinned` (supply_chain.py:866) matched a literal 'x' ANYWHERE, and the pypi
# adapter stores the FULL PEP 508 line as `spec` (name embedded). So a fully-pinned
# `xlrd==1.2.0` — the 'x' lives in the NAME — false-flagged as an unpinned range at the
# S3 call sites: signal_s3 (:942) and the per-dep S3 corroborator (:1339).
#
# The fix is BOTH (neither alone is complete — white-hacker dogfood finding):
#   (a) feed `_unpinned(_constraint(d))` at both call sites — strips the leading bare name,
#       aligning S3 with S8 (signal_s8 already uses `_exact_pin(_constraint(d))` at :1045).
#       But `_constraint` strips ONLY the bare name, so PEP 508 `[extras]` and `; markers`
#       survive (`pkg[x]==1` → `[x]==1`; `foo==1; sys_platform == "linux"` → the 'x' in
#       "linux") — fix (a) alone leaves those residual FPs.
#   (b) anchor the regex so a bare 'x'/'*' counts ONLY as a version segment. This kills the
#       extras/markers residue — but on the RAW name-embedded spec a dotted name like `x.y`
#       (leading 'x' followed by '.') still matches the anchored token, so (a) is still
#       needed on top. Together: every genuine range stays True, every FP becomes False.
# Under fix (b) `_unpinned` IS changed → direct `_unpinned(...) is False` asserts are valid.
# --------------------------------------------------------------------------- #

def test_signal_s3_pinned_name_with_x_no_false_positive(tmp_path):
    """signal_s3 must read the version CONSTRAINT, not the name-embedded pypi spec.
    A fully-pinned `xlrd==1.2.0` (the 'x' is in the NAME) is NOT an unpinned range.

    RED at HEAD: signal_s3 calls `_unpinned(d["spec"])` → `_unpinned('xlrd==1.2.0')`
    matches the literal 'x' → True (the FP). Fix (a) feeds `_constraint(d)` → '==1.2.0'
    → False. Policy 9 — pin BOTH directions in one invariant test.
    """
    pinned = sc.parse_pypi(str(_write_pypi(tmp_path / "pinned", "xlrd==1.2.0\n")))
    assert sc.signal_s3(pinned) is False          # == expected: pinned 'x'-named dep → no S3
    # != the wrong value: a genuine unpinned range (no lockfile) STILL fires S3 (no FN)
    ranged = sc.parse_pypi(str(_write_pypi(tmp_path / "ranged", "boto3^1.0.0\n")))
    assert sc.signal_s3(ranged) is True


def test_scan_pinned_name_with_x_does_not_corroborate_s3(tmp_path):
    """The per-dep S3 corroborator (supply_chain.py:1339) must also read the constraint,
    not the name-embedded spec — else a watchlisted, FULLY-PINNED dep whose NAME contains
    'x' wrongly picks up an S3 'unpinned' corroborator on its finding.

    RED at HEAD: `_unpinned('xpkg-evil==1.2.0')` matches the 'x' → S3 attaches. After fix
    (a) `_unpinned(_constraint(d))` == `_unpinned('==1.2.0')` == False → no S3.
    Policy 9 — pin BOTH: the S8 name signal IS present (==), the S3 corroborator is NOT (!=).
    `allowlist=[]` isolates the S8+S3 path (no incidental S4/S5).
    """
    proj = _write_pypi(tmp_path / "p", "xpkg-evil==1.2.0\n")          # pinned, no lockfile
    doc = sc.scan(str(proj), malware_db={"xpkg-evil": {"1.2.0"}}, allowlist=[])
    hits = [f for f in _emitted(doc) if "xpkg-evil" in f.get("exploit_scenario", "")]
    assert len(hits) == 1, "watchlisted xpkg-evil@1.2.0 must emit exactly one S8 finding"
    scenario = hits[0]["exploit_scenario"]
    assert "S8" in scenario        # == expected: the name signal is present
    assert "S3" not in scenario    # != the wrong value: a pinned dep must NOT corroborate S3
    assert vf.validate(doc) == []


def test_scan_genuine_range_still_corroborates_s3(tmp_path):
    """Control (no FN): a watchlisted dep with a GENUINE unpinned range + no lockfile STILL
    picks up the S3 corroborator after the fix — the alignment must not suppress real ranges.
    Policy 9 — the `!=` direction for the corroborator path.
    """
    proj = _write_pypi(tmp_path / "p", "xpkg-evil^1.0.0\n")          # genuine range, no lock
    doc = sc.scan(str(proj), malware_db={"xpkg-evil": {"*"}}, allowlist=[])
    hits = [f for f in _emitted(doc) if "xpkg-evil" in f.get("exploit_scenario", "")]
    assert len(hits) == 1, "watchlisted xpkg-evil must emit exactly one finding"
    scenario = hits[0]["exploit_scenario"]
    assert "S8" in scenario        # name signal present
    assert "S3" in scenario        # == expected: a real range + no lockfile → S3 corroborates
    assert vf.validate(doc) == []


def test_unpinned_no_false_negative_on_ranges_and_tags():
    """Guard (fix b, no FN): the ANCHORED regex still flags every genuine range/wildcard/tag
    — a bare 'x'/'*' AS A VERSION SEGMENT (`1.x`, `1.2.x`, `1.x.x`, `1.0.*`), plus the
    `^`/`~` range operators and the `latest` tag. Policy 9 both directions.
    """
    for spec in ("1.x", "1.2.x", "1.x.x", "^1.0.0", "~1.0", "*", "1.0.*", "latest"):
        assert sc._unpinned(spec) is True, f"{spec!r} must read as an unpinned range"
    # != the wrong value: a bare exact version / pypi '==' pin is NOT unpinned
    assert sc._unpinned("1.2.0") is False
    assert sc._unpinned("==1.2.0") is False


def test_unpinned_anchored_kills_name_extras_and_marker_false_positives():
    """Fix (b): the anchored regex makes a bare 'x'/'*'/`latest` count ONLY as a version
    segment — never a stray letter in a NAME, a PEP 508 `[extra]`, or a `; marker`. These
    are the residual FPs that fix (a)'s name-strip alone cannot reach (extras/markers
    survive `_constraint`). RED before fix (b): the old `[\\^~*]|latest|x` matched the 'x'
    anywhere. Policy 9 — the FP-killed (==False) direction; the no-FN (!=True) direction is
    pinned in test_unpinned_no_false_negative_on_ranges_and_tags.
    """
    # the headline name-embedded FP (the 'x' in 'xlrd')
    assert sc._unpinned("xlrd==1.2.0") is False
    # PEP 508 extras residue: `_constraint` strips only the bare name, leaving `[x]==1.0`
    assert sc._unpinned("[x]==1.0") is False
    # environment-marker residue: the 'x' inside the VERY common `sys_platform == "linux"`
    assert sc._unpinned('==1.0; sys_platform == "linux"') is False
    assert sc._unpinned('==1.0; extra == "test"') is False
    # `latest` must be a whole token, not a substring of a name
    assert sc._unpinned("mypackagelatest==1.0") is False
    # plain exact pins (incl. build metadata) stay pinned
    assert sc._unpinned("boto3==1.0.0") is False
    assert sc._unpinned("1.0.0+exotic") is False


def test_both_fixes_needed_constraint_strip_under_anchored_regex():
    """Why BOTH (a) AND (b): the anchored regex (b) treats a leading 'x' followed by '.' as
    a version segment, so a DOTTED pypi NAME like `x.y` still matches on the name-embedded
    raw spec — fix (a)'s `_constraint` name-strip closes that residual. (Conversely, (b) is
    what kills the extras/markers residue that (a) alone leaves.) Policy 9 both directions.
    """
    dep = {"name": "x.y", "spec": "x.y==1.0", "source_type": "registry"}
    # (b)'s anchored regex is still fooled by the dotted NAME on the RAW spec ...
    assert sc._unpinned(dep["spec"]) is True
    # ... (a) strips the name so only the constraint is read → not unpinned
    assert sc._unpinned(sc._constraint(dep)) is False     # == expected: pinned → not unpinned
    # != the wrong value: a genuine range survives the strip and still reads unpinned
    ranged = {"name": "x.y", "spec": "x.y^1.0.0", "source_type": "registry"}
    assert sc._unpinned(sc._constraint(ranged)) is True


# --------------------------------------------------------------------------- #
# wh-ln2 — _scrub: findings text is an egress surface (ADR-019; Agents Rule of
# Two). A hostile manifest must not inject newlines/ANSI into exploit_scenario to
# visually FORGE severity lines; a legitimate spec must survive byte-identical.
# Tests pin BOTH `== scrubbed` AND `!= over-scrubbed` (Policy 9).
# --------------------------------------------------------------------------- #
# The wave-1a PoC3 string: a leading newline + an ANSI SGR red sequence that, raw,
# would render a forged "FAKE-CRITICAL" line in red in the human's report.
_POC_SCRUB_SPEC = "\n\x1b[31mFAKE-CRITICAL"


def test_scrub_drops_control_chars_and_ansi():
    out = sc._scrub(_POC_SCRUB_SPEC)
    # == expected: the C0 newline and the ANSI ESC are gone; the visible residue is
    # the literal letters, never a control byte that could forge a line.
    assert "\n" not in out
    assert "\x1b" not in out
    assert "\r" not in out
    assert "\t" not in out
    assert "[31m" not in out          # the CSI body went with the ESC
    assert "FAKE-CRITICAL" in out     # legible letters are kept (not nuked wholesale)
    # != the wrong value: the raw injectable string never passes through verbatim.
    assert out != _POC_SCRUB_SPEC


def test_scrub_keeps_benign_specs_byte_identical():
    # Legitimate version specs carry no control/ANSI bytes → must be byte-identical
    # (== expected). The != pair guards against over-scrubbing that would mangle a
    # real spec (e.g. stripping `^`, `=`, `:`, `/`, `+` or `.`).
    for benign in ("^1.0.0", "==1.2.3", "~>2.1", "1.2.3",
                   "git+https://github.com/acme/lib.git#v1.2.3",
                   "file:../local-tool", ">=1.0.0,<2.0.0"):
        assert sc._scrub(benign) == benign          # survives untouched
        assert sc._scrub(benign) != ""              # not nuked to empty


def test_scrub_collapses_newline_and_tab_runs_to_single_space():
    # A run of newlines/tabs collapses to ONE space (== expected) — the attacker
    # cannot reflow the report by padding whitespace; != the original multi-line form.
    multi = "a\n\n\t\nb"
    assert sc._scrub(multi) == "a b"
    assert sc._scrub(multi) != multi


def test_scrub_caps_length_with_ellipsis_marker():
    # A pathologically long value is capped (~200 chars) with an ellipsis marker so a
    # manifest cannot flood the report. == expected: short output, ends in the marker;
    # != the wrong value: the full 5000-char payload is not echoed.
    payload = "A" * 5000
    out = sc._scrub(payload)
    assert len(out) <= 210                # capped near ~200 (+ the marker)
    assert out != payload                 # not the full flood
    assert out.endswith("…")              # ellipsis marker present


def test_scrub_never_raises_on_odd_input():
    # degrade-never-raise (ADR-003): _scrub tolerates empty + lone-ESC + stray C1.
    assert sc._scrub("") == ""
    assert "\x1b" not in sc._scrub("\x1b")          # a bare ESC with no CSI body
    assert "\x9b" not in sc._scrub("x\x9by")        # a lone C1 control byte


def test_make_finding_poc_spec_cannot_inject_newline_or_ansi(tmp_path):
    """End-to-end through scan(): a hostile dep `spec` (the PoC3 string) reaches
    _make_finding's exploit_scenario but renders INERT — no newline, no ANSI ESC —
    and the document stays schema-valid. `lodahs` (dist-1 of `lodash`) + a lifecycle
    script trips S4 so a finding is actually emitted to carry the payload."""
    proj = _write(tmp_path / "p", {
        "dependencies": {"lodahs": _POC_SCRUB_SPEC},
        "scripts": {"postinstall": "node scripts/postinstall.js"},
    }, scripts_files={"scripts/postinstall.js": "// inert\n"})
    doc = sc.scan(str(proj))
    cand = next(x for x in _emitted(doc) if "lodahs" in x["exploit_scenario"])
    scen = cand["exploit_scenario"]
    # == scrubbed: the injected newline + ANSI are gone from the rendered scenario.
    assert "\n" not in scen
    assert "\x1b" not in scen
    assert "[31m" not in scen
    # != the wrong value: the raw payload substring never survives verbatim.
    assert _POC_SCRUB_SPEC not in scen
    # the dep NAME is still legible in the scenario (we scrub, not nuke).
    assert "lodahs" in scen
    assert vf.validate(doc) == []


def test_make_finding_benign_spec_survives_in_scenario(tmp_path):
    """The != over-scrub pair end-to-end: a legitimate git+https spec on a flagged
    dep survives byte-identical inside the rendered scenario."""
    benign = "git+https://github.com/acme/lodahs.git#v1.2.3"
    proj = _write(tmp_path / "p", {
        "dependencies": {"lodahs": benign},
        "scripts": {"postinstall": "node scripts/postinstall.js"},
    }, scripts_files={"scripts/postinstall.js": "// inert\n"})
    doc = sc.scan(str(proj))
    cand = next(x for x in _emitted(doc) if "lodahs" in x["exploit_scenario"])
    assert benign in cand["exploit_scenario"]          # == expected: untouched
    assert vf.validate(doc) == []


def test_make_kernel_finding_scrubs_build_file_path():
    """_make_kernel_finding interpolates `build_file` into its scenario. Driven directly
    (the kernel build-file lookup is top-level-only, so a hostile path can't arrive via
    scan() without fighting the parser — the unit contract is what we pin, matching the
    file's `_unpinned`/`_constraint` direct-test style). A control/ANSI byte in the path
    must not reach the rendered scenario (== scrubbed); the legible name survives, and
    the finding stays schema-valid when wrapped in a document (!= over-scrubbed)."""
    hostile = "drivers/a\x1b[31m\nb/Makefile"
    f = sc._make_kernel_finding(hostile, ["wget http://example.test/x.bin"])
    scen = f["exploit_scenario"]
    assert "\x1b" not in scen          # == scrubbed: no ANSI ESC in the scenario
    assert "\n" not in scen
    assert "[31m" not in scen
    assert "Makefile" in scen          # != over-scrubbed: the legible name survives
    # the embedded raw path never survives verbatim in the rendered scenario.
    assert hostile not in scen
    # still schema-valid once wrapped in a findings document.
    doc = sc._build_doc([f], {"deps": [], "lifecycle_scripts": {}}, None, {}, "CVSS4.0")
    assert vf.validate(doc) == []


def test_make_script_finding_scrubs_script_path():
    """_make_script_finding interpolates `script_path` into its scenario. Driven directly
    (a real on-disk script path with embedded `\\n` can't round-trip the whitespace-
    splitting command parser — the unit contract is what we pin). A control/ANSI byte in
    the path renders inert (== scrubbed) yet the legible `.js` basename survives, and the
    finding stays schema-valid wrapped in a document (!= over-scrubbed)."""
    hostile = "bad\x1b[31m\ndir/postinstall.js"
    f = sc._make_script_finding(0, hostile, ["child_process.exec", "eval"],
                                "package.json")
    scen = f["exploit_scenario"]
    assert "\x1b" not in scen          # == scrubbed
    assert "\n" not in scen
    assert "[31m" not in scen
    assert "postinstall.js" in scen    # != over-scrubbed: basename legible
    assert hostile not in scen
    doc = sc._build_doc([f], {"deps": [], "lifecycle_scripts": {}}, None, {}, "CVSS4.0")
    assert vf.validate(doc) == []


# --------------------------------------------------------------------------- #
# wh-ln2 D1 — ASCII C0/C1 + ANSI is NOT enough: attacker-controlled UNICODE
# codepoints re-enable the same forge/Trojan-Source attack and must also be
# neutralized (QA + white-hacker round-1 MEDIUM). `_scrub` must treat:
#   * U+2028 LINE SEP (Zl) / U+2029 PARA SEP (Zp) → a single space (many
#     terminals/editors render them as a NEWLINE → forged severity line);
#   * Cf format chars — bidi overrides/isolates U+202A–202E / U+2066–2069 and
#     zero-width/BOM U+200B/200C/200D/FEFF → dropped (Trojan-Source reorder).
# Legit non-ASCII (`é`, `カ`) + URL/spec punctuation carry NO Zl/Zp/Cf → survive.
# Categories grounded via unicodedata (Zl/Zp/Cf) — Policy 9 pins BOTH directions.
# --------------------------------------------------------------------------- #
_U_LINE_SEP = " "   # Zl — newline-like
_U_PARA_SEP = " "   # Zp — newline-like
_U_RLO = "‮"        # Cf — bidi right-to-left override (Trojan-Source)
_U_ZWSP = "​"       # Cf — zero-width space (token-splitting)
_U_BOM = "﻿"        # Cf — zero-width no-break space / BOM


def test_scrub_neutralizes_unicode_line_and_para_separators():
    # Zl/Zp collapse to a single space (== expected — mirrors the \n handling), so a
    # manifest can't open a forged line; the surrounding letters stay legible.
    out = sc._scrub(f"a{_U_LINE_SEP}{_U_PARA_SEP}b")
    assert _U_LINE_SEP not in out                 # the line separator is gone
    assert _U_PARA_SEP not in out                 # the para separator is gone
    assert out == "a b"                            # == expected: collapsed to one space
    # != the wrong value: the raw newline-like form never survives verbatim.
    assert out != f"a{_U_LINE_SEP}{_U_PARA_SEP}b"
    assert "a" in out and "b" in out               # letters kept (not nuked)


def test_scrub_drops_unicode_format_chars_bidi_and_zero_width():
    # Cf chars (bidi override, zero-width, BOM) are dropped outright (== the control
    # handling) so a Trojan-Source visual reorder / token-split can't render.
    out = sc._scrub(f"safe{_U_RLO}{_U_ZWSP}{_U_BOM}name")
    assert _U_RLO not in out                        # bidi override gone
    assert _U_ZWSP not in out                       # zero-width space gone
    assert _U_BOM not in out                        # BOM gone
    assert out == "safename"                        # == expected: Cf removed, no gap
    assert out != f"safe{_U_RLO}{_U_ZWSP}{_U_BOM}name"   # != the raw payload


def test_scrub_keeps_legit_non_ascii_and_urls_byte_identical():
    # The != over-scrub guard: legit non-ASCII letters (é, カ) carry no Zl/Zp/Cf, and
    # URL/spec punctuation is untouched → every value survives byte-identical.
    for benign in ("café-utils", "日本語パッケージ", "^1.0.0", "==1.2.3",
                   "git+https://github.com/acmé/lib.git#v1.2.3",
                   "=> ../local/fork v1.2.3"):
        assert sc._scrub(benign) == benign          # == expected: untouched
        assert sc._scrub(benign) != ""              # not nuked to empty


def test_scrub_unicode_pass_never_raises():
    # degrade-never-raise (ADR-003): the category pass tolerates lone Cf / Zl / Zp +
    # an astral codepoint without raising.
    assert sc._scrub(_U_RLO) == ""                  # a lone Cf → empty, no raise
    assert sc._scrub(_U_LINE_SEP) == " "            # a lone Zl → single space
    assert "\U0001F4A9" in sc._scrub("x\U0001F4A9y")  # astral So char survives, no raise


def test_make_finding_unicode_payload_cannot_inject_line_or_reorder(tmp_path):
    """End-to-end through scan() (mirrors the ASCII PoC e2e test): a hostile dep `spec`
    carrying U+2028 (newline-like) + U+202E (bidi override) reaches _make_finding's
    exploit_scenario but renders INERT — neither codepoint survives — and the document
    stays schema-valid. `lodahs` (dist-1 of `lodash`) + a lifecycle script trips S4."""
    payload = f"1.0.0{_U_LINE_SEP}{_U_RLO}FAKE-CRITICAL"
    proj = _write(tmp_path / "p", {
        "dependencies": {"lodahs": payload},
        "scripts": {"postinstall": "node scripts/postinstall.js"},
    }, scripts_files={"scripts/postinstall.js": "// inert\n"})
    doc = sc.scan(str(proj))
    cand = next(x for x in _emitted(doc) if "lodahs" in x["exploit_scenario"])
    scen = cand["exploit_scenario"]
    # == scrubbed: the newline-like separator + bidi override are gone.
    assert _U_LINE_SEP not in scen
    assert _U_RLO not in scen
    # != the wrong value: the raw payload substring never survives verbatim.
    assert payload not in scen
    assert "lodahs" in scen                          # name still legible
    assert vf.validate(doc) == []


# --------------------------------------------------------------------------- #
# wh-5ox.2 — STRUCTURAL bun-runtime-dropper markers in S6 (no campaign filenames)
#
# A clean-looking install script that fetches the bun RUNTIME from the official
# release host + verifies the ZIP local-file-header magic + extracts into the bun
# install dir + names the bun binary — with NO same-line eval/exec — must still
# reach S6's >=2-pattern HIGH on the STRUCTURAL shape alone. Markers re-derived
# from PRIMARY sources (DO-NOT-COPY the community YARA):
#   * release host  github.com/oven-sh/bun/releases/(latest/)?download  — bun's
#     official installer `bun_uri` (https://bun.com/install, install.sh).
#   * env var       BUN_INSTALL(_DIR/_BIN)  — `install_env=BUN_INSTALL` (ibid.);
#     pattern covers the documented var AND a renamed `_DIR`/`_BIN` campaign form.
#   * binary name   bun-(linux|darwin)-(x64|aarch64)(-musl)?(-baseline)?  — the
#     release asset `bun-$target.zip` (ibid.).
#   * ZIP magic     PK\x03\x04 / 504b0304 / 04034b50  — the local-file-header
#     signature 0x04034b50 (PKWARE APPNOTE.TXT §4.3.7), in the source forms a
#     manual-unzip dropper uses to test magic bytes.
# NO `[example-unverified]` campaign filename (ai_init.js/router_runtime.js) and
# NO /tmp/.bun_ran runtime IOC are hardcoded — the structural spine carries it.
# --------------------------------------------------------------------------- #

# Clearly INERT detection test data (same discipline as _INERT_DANGEROUS_POSTINSTALL
# and the eval corpus's neutralized filenames — NEVER functional): a no-op module
# whose TEXT carries the structural bun-dropper marker strings. NO eval/exec/spawn/
# child_process — proves detection on the SHAPE, not on an obvious dangerous-API tell.
_BUN_DROPPER_FETCH_UNZIP = (
    "// SAMPLE (inert) — detection test data only, does nothing.\n"
    "// Structural bun-runtime dropper SHAPE: fetch the bun runtime from the\n"
    "// official release host, verify the ZIP local-file-header magic, extract\n"
    "// into the bun install dir, run the named bun binary. NO eval/exec here.\n"
    "const url = 'https://github.com/oven-sh/bun/releases/download"
    "/bun-v1.1.0/bun-linux-x64.zip';\n"
    "async function drop() {\n"
    "  const res = await fetch(url);\n"
    "  const buf = Buffer.from(await res.arrayBuffer());\n"
    "  // ZIP local-file-header magic PK\\x03\\x04 (PKWARE APPNOTE 4.3.7)\n"
    "  if (buf.subarray(0, 4).toString('hex') === '504b0304') {\n"
    "    const dir = process.env.BUN_INSTALL_DIR || (process.env.HOME + '/.bun');\n"
    "    // manual extraction of bun-linux-x64 into dir ... (no-op in this sample)\n"
    "  }\n"
    "}\n"
    "module.exports = function () { /* no-op: see comments above */ };\n"
)

# Benign control: a legit prebuild-install / node-pre-gyp-style postinstall that
# fetches + extracts a prebuilt native addon from its OWN (NON-bun) GitHub release.
# It legitimately hits the generic `\bfetch\s*\(`, but must NOT reach >=2 via the
# bun-SPECIFIC structural patterns (no oven-sh host, no BUN_INSTALL, no bun binary
# name, tar.gz not a manual ZIP-magic check) — the meaningful negative proving the
# new patterns are bun-specific, not "any binary fetcher".
_BENIGN_PREBUILT_FETCH = (
    "// SAMPLE (inert) — a legit prebuild-install-style native-addon fetcher.\n"
    "// Fetches a prebuilt binding tarball from its OWN GitHub release, via tar.\n"
    "const url = 'https://github.com/acme-corp/acme-native/releases/download"
    "/v2.1.0/acme-native-linux-x64.tar.gz';\n"
    "async function getPrebuilt() {\n"
    "  const res = await fetch(url);\n"
    "  // tarball is unpacked with the system tar; a prebuilt C++ binding.\n"
    "}\n"
    "module.exports = function () { /* no-op */ };\n"
)


def _s6_patterns_for(script_path: str) -> list[str]:
    """Matched-pattern strings S6 collects for one script (Policy 9 — assert on the
    matched set, not just severity). signal_s6 returns {path: [pattern.pattern, ...]}."""
    return sc.signal_s6({"script_files": [script_path]}).get(script_path, [])


def test_structural_bun_dropper_fetch_unzip_emits_s6_high(tmp_path):
    # RED→GREEN: the fetch-bun-runtime + verify-ZIP-magic + BUN_INSTALL + bun binary
    # SHAPE (no eval/exec) reaches S6 HIGH via >=2 NEW structural patterns.
    proj = _write(tmp_path / "p", {
        "dependencies": {"react": "18.2.0"},
        "scripts": {"postinstall": "node scripts/postinstall.js"},
    }, scripts_files={"scripts/postinstall.js": _BUN_DROPPER_FETCH_UNZIP})
    doc = sc.scan(str(proj))
    f = _emitted(doc)
    high = [x for x in f if x["severity"] == "HIGH"]
    assert high, "structural bun-runtime fetch+unzip shape → S6 HIGH"
    assert high[0]["tool_assisted"] is False          # floor, never tool-backed
    # project-level, keyed to the script (NOT fanned out to the clean react dep)
    script_findings = [x for x in f if x["file"].endswith("postinstall.js")]
    assert len(script_findings) == 1
    assert not any("react @" in x["exploit_scenario"] for x in f)

    # == expected: >=2 of the NEW structural bun patterns matched the SAME script.
    spath = str(proj / "scripts" / "postinstall.js")
    matched = set(_s6_patterns_for(spath))
    new_hits = matched & set(sc._BUN_DROPPER_PATTERNS)
    assert len(new_hits) >= 2, (
        "detection must be STRUCTURAL — >=2 distinct bun-dropper patterns, not the "
        f"lone generic fetch(. got new_hits={sorted(new_hits)}"
    )
    # != the wrong reason: NOT reached via an obvious dangerous-API tell — the shape
    # carries it, so eval/exec/spawn/child_process never fire on this fixture.
    assert r"eval\s*(" not in matched
    assert r"\bexec\s*(" not in matched
    assert r"\bspawn\s*(" not in matched
    assert "child_process" not in matched
    assert vf.validate(doc) == []


def test_benign_non_bun_prebuilt_fetcher_yields_no_s6_high(tmp_path):
    # REQUIRED negative (Policy 9): a generic NON-bun binary fetcher must NOT reach
    # S6 HIGH — it may trip the generic fetch( but < 2 of the bun-specific patterns.
    proj = _write(tmp_path / "p", {
        "name": "native-thing",
        "dependencies": {"react": "18.2.0"},
        "scripts": {"postinstall": "node scripts/postinstall.js"},
    }, scripts_files={"scripts/postinstall.js": _BENIGN_PREBUILT_FETCH})
    doc = sc.scan(str(proj))
    f = _emitted(doc)
    # == expected: no S6 HIGH finding (no >=2-pattern script).
    assert not any(x["severity"] == "HIGH" for x in f)
    assert not any(x["file"].endswith("postinstall.js") for x in f)
    assert doc["summary"]["counts"]["high"] == 0

    # != the wrong reason: the bun-specific patterns did NOT reach >=2 on a legit
    # non-bun fetcher (proving the spine is bun-specific, not "any binary fetcher").
    spath = str(proj / "scripts" / "postinstall.js")
    matched = set(_s6_patterns_for(spath))
    new_hits = matched & set(sc._BUN_DROPPER_PATTERNS)
    assert len(new_hits) < 2, f"non-bun fetcher tripped bun patterns: {sorted(new_hits)}"
    assert vf.validate(doc) == []


def test_signal_s6_degrades_on_unreadable_or_binary_script_no_raise(tmp_path):
    # ADR-003 degrade-never-raise: the new pure-regex patterns run over text read by
    # the OSError-safe _read_text — a missing / binary / odd script must NOT raise.
    missing = str(tmp_path / "nope" / "ghost.js")
    out = sc.signal_s6({"script_files": [missing]})
    assert out == {}                     # unreadable → skipped, never raised
    assert out != {missing: []}          # (sanity: not a stub entry)
    # a binary blob (embedded NULs / raw ZIP bytes) is read errors='ignore', no raise
    blob = tmp_path / "blob.js"
    blob.write_bytes(b"\x00\xff\xfe" + b"PK\x03\x04" * 4 + b"\x00bun-linux-x64")
    out2 = sc.signal_s6({"script_files": [str(blob)]})
    assert isinstance(out2, dict)        # returns cleanly, never raises


def test_read_toml_degrades_to_empty_on_untrusted_input_classes(tmp_path):
    # wh-0uy / F-001 (AC3): _read_toml NEVER raises on untrusted input -> the whole degrade class maps to {}
    # so the TOML adapters (gradle/pypi/cargo) COMPLETE rather than abort scan() (ADR-003). RecursionError (a
    # RuntimeError subclass tomllib raises on a deeply-NESTED manifest) was the MISSED except member.
    # both-ways (Policy 9): a VALID TOML still parses to its dict.
    valid = tmp_path / "valid.toml"
    valid.write_text('[versions]\ncommons = "3.12.0"\n', encoding="utf-8")
    assert sc._read_toml(valid) == {"versions": {"commons": "3.12.0"}}
    bad = tmp_path / "bad.toml"
    bad.write_text("this is not = valid toml [[[\n", encoding="utf-8")
    assert sc._read_toml(bad) == {}
    assert sc._read_toml(tmp_path) == {}  # a directory is not openable -> OSError -> {}
    nonutf8 = tmp_path / "binary.toml"
    nonutf8.write_bytes(b"\xff\xfe\x00\x01key = 1\n")
    assert sc._read_toml(nonutf8) == {}  # non-UTF8 -> UnicodeDecodeError (a ValueError subclass) -> {}
    deep = tmp_path / "deep.toml"
    deep.write_text("a = " + "[" * 6000 + "]" * 6000 + "\n", encoding="utf-8")
    assert sc._read_toml(deep) == {}  # RecursionError -> {} (the bug this fixes)
