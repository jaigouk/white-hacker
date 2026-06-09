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
def test_degraded_no_malware_db_lists_it_and_never_raises(tmp_path):
    proj = _write(tmp_path / "p", {"dependencies": {"react": "18.2.0"}})
    # no OSSF snapshot path passed → S8 degrades cleanly
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
    empty = tmp_path / "nothing"
    empty.mkdir()
    doc = sc.scan(str(empty))            # must degrade, not raise
    assert _emitted(doc) == []
    assert "malware-db" in doc["summary"]["tools_unavailable"]
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
