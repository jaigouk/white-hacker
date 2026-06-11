"""wh-5ox.1 — inert campaign-IOC grep-pack tests (deterministic floor scan).

`ioc_scan.scan(project_dir, iocs_path=...)` walks a reviewed tree, greps file
contents for FIXED campaign literals loaded from `campaign-iocs.json` (the DATA/value
plane), and emits `tool_assisted:false` finding-schema candidates on an EXACT match. It
NEVER blocks and NEVER raises (unreadable/binary files are skipped). A missing/empty/
malformed data file degrades clean: zero findings + `ioc-scan` in `summary.tools_unavailable`.

DO-NOT-COPY: every literal here is a SYNTHETIC, neutralized placeholder PLANTED by the
test — never a real community beacon string / C2 host / marker. The shipped
`campaign-iocs.json` carries NO real literals (see test_shipped_data_file_has_no_real_literals).

Rule 9 (tests verify intent): every invariant pins BOTH `== expected` AND `!= wrong`.

Run: `uv run --project plugins/white-hacker/skills/deps-scan/scripts \
    --with jsonschema --with pytest pytest \
    plugins/white-hacker/skills/deps-scan/scripts/tests -q`
"""
from __future__ import annotations

import json
import pathlib

import ioc_scan
import validate_findings as vf

# A SYNTHETIC, neutralized literal — NOT a real campaign string. Planted by the tests
# only; it never ships in campaign-iocs.json.
_SYNTH_LITERAL = "EXAMPLE_NEUTRALIZED_BEACON_DO_NOT_COPY_zzz123"

# A campaign-iocs.json document that MATCHES the planted literal above (test data plane).
_SYNTH_IOCS = {
    "schema_version": 1,
    "iocs": [
        {
            "id": "TEST-IOC-001",
            "literal": _SYNTH_LITERAL,
            "kind": "beacon",
            "severity": "HIGH",
            "primary_source": "https://example.test/advisory/TEST-IOC-001",
            "low_durability": False,
        }
    ],
}

_SHIPPED_DATA = (
    pathlib.Path(__file__).resolve().parent.parent.parent
    / "reference"
    / "campaign-iocs.json"
)


def _write_iocs(tmp_path: pathlib.Path, doc: object) -> pathlib.Path:
    p = tmp_path / "campaign-iocs.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# EXACT match in a planted tree → a finding with a REPO-RELATIVE file path
# --------------------------------------------------------------------------- #
def test_exact_match_emits_repo_relative_finding(tmp_path):
    iocs = _write_iocs(tmp_path, _SYNTH_IOCS)
    project = tmp_path / "proj"
    (project / "src").mkdir(parents=True)
    hit = project / "src" / "loader.js"
    hit.write_text(f"const x = '{_SYNTH_LITERAL}';\n", encoding="utf-8")

    doc = ioc_scan.scan(str(project), iocs_path=str(iocs))

    assert len(doc["findings"]) == 1  # == expected: exactly one hit
    f = doc["findings"][0]
    # REPO-RELATIVE path (POSIX separators), relative to the scanned project root.
    assert f["file"] == "src/loader.js"          # == expected
    assert f["first_link"] == "src/loader.js"
    # != wrong: never an absolute or home path (finding-schema `file` is `^[^/~]`).
    assert not f["file"].startswith("/")
    assert "/Users" not in f["file"]
    assert "~" not in f["file"]
    assert f["file"] != str(hit)                 # != wrong: not the absolute path


def test_exact_match_finding_fields(tmp_path):
    iocs = _write_iocs(tmp_path, _SYNTH_IOCS)
    project = tmp_path / "proj"
    project.mkdir()
    (project / "beacon.txt").write_text(_SYNTH_LITERAL, encoding="utf-8")

    doc = ioc_scan.scan(str(project), iocs_path=str(iocs))
    f = doc["findings"][0]

    assert f["tool_assisted"] is False           # == expected: this is the floor
    assert f["tool_assisted"] != True            # != wrong (explicit, Policy 9)
    assert f["severity"] == "HIGH"               # == expected (from the IOC entry)
    assert f["severity"] != "LOW"                # != wrong
    assert f["confidence"] <= 0.8                # floor cap (degradation.cap_floor_confidence)
    assert f["category"] == "supply-chain"
    assert "AISEC-SUPPLY-CHAIN-003" in f["kb_refs"]
    # the schema-required shape is present
    assert f["verified"] == "static_review_only"
    assert f["canonical_of"] is None


def test_finding_document_validates_against_schema(tmp_path):
    iocs = _write_iocs(tmp_path, _SYNTH_IOCS)
    project = tmp_path / "proj"
    project.mkdir()
    (project / "beacon.txt").write_text(_SYNTH_LITERAL, encoding="utf-8")

    doc = ioc_scan.scan(str(project), iocs_path=str(iocs))
    # The keystone contract: the emitted document is finding-schema-valid.
    assert vf.validate(doc) == []                # == expected: no schema errors


def test_summary_counts_match_emitted_severity(tmp_path):
    iocs = _write_iocs(tmp_path, _SYNTH_IOCS)
    project = tmp_path / "proj"
    project.mkdir()
    (project / "beacon.txt").write_text(_SYNTH_LITERAL, encoding="utf-8")

    doc = ioc_scan.scan(str(project), iocs_path=str(iocs))
    assert doc["summary"]["counts"]["high"] == 1   # == expected
    assert doc["summary"]["counts"]["medium"] == 0
    assert doc["summary"]["counts"]["low"] == 0
    # ioc-scan is the bound capability here → NOT in tools_unavailable
    assert "ioc-scan" not in doc["summary"]["tools_unavailable"]  # != wrong


# --------------------------------------------------------------------------- #
# CLEAN tree → zero findings (no false trip)
# --------------------------------------------------------------------------- #
def test_clean_tree_yields_no_findings(tmp_path):
    iocs = _write_iocs(tmp_path, _SYNTH_IOCS)
    project = tmp_path / "proj"
    (project / "src").mkdir(parents=True)
    # benign content that does NOT contain the literal
    (project / "src" / "app.js").write_text("console.log('hello world');\n", encoding="utf-8")
    (project / "README.md").write_text("nothing suspicious here\n", encoding="utf-8")

    doc = ioc_scan.scan(str(project), iocs_path=str(iocs))
    assert doc["findings"] == []                 # == expected: clean
    assert len(doc["findings"]) != 1             # != wrong (no spurious trip)
    assert doc["summary"]["counts"]["high"] == 0


def test_substring_of_literal_does_not_trip(tmp_path):
    iocs = _write_iocs(tmp_path, _SYNTH_IOCS)
    project = tmp_path / "proj"
    project.mkdir()
    # a PROPER SUBSTRING of the literal must NOT match (exact-literal match only)
    (project / "near.txt").write_text("EXAMPLE_NEUTRALIZED_BEACON\n", encoding="utf-8")

    doc = ioc_scan.scan(str(project), iocs_path=str(iocs))
    assert doc["findings"] == []                 # == expected: no partial match


# --------------------------------------------------------------------------- #
# Excluded directories are NOT walked (resource discipline + ADR scoping)
# --------------------------------------------------------------------------- #
def test_excluded_dirs_are_not_scanned(tmp_path):
    iocs = _write_iocs(tmp_path, _SYNTH_IOCS)
    project = tmp_path / "proj"
    for excluded in (".git", "node_modules", ".venv", "dist", "build"):
        d = project / excluded
        d.mkdir(parents=True)
        (d / "planted.txt").write_text(_SYNTH_LITERAL, encoding="utf-8")

    doc = ioc_scan.scan(str(project), iocs_path=str(iocs))
    # == expected: literals buried in excluded dirs never trip
    assert doc["findings"] == []
    assert len(doc["findings"]) != 5             # != wrong (none of the 5 planted hits)


def test_excluded_dir_does_not_mask_real_hit(tmp_path):
    iocs = _write_iocs(tmp_path, _SYNTH_IOCS)
    project = tmp_path / "proj"
    (project / "node_modules").mkdir(parents=True)
    (project / "node_modules" / "x.js").write_text(_SYNTH_LITERAL, encoding="utf-8")
    (project / "src").mkdir()
    (project / "src" / "real.js").write_text(_SYNTH_LITERAL, encoding="utf-8")

    doc = ioc_scan.scan(str(project), iocs_path=str(iocs))
    # only the in-scope hit is reported; the node_modules one is excluded
    files = sorted(f["file"] for f in doc["findings"])
    assert files == ["src/real.js"]              # == expected
    assert "node_modules/x.js" not in files      # != wrong


# --------------------------------------------------------------------------- #
# NEVER raises — unreadable / binary files are skipped, not fatal
# --------------------------------------------------------------------------- #
def test_binary_file_is_skipped_not_fatal(tmp_path):
    iocs = _write_iocs(tmp_path, _SYNTH_IOCS)
    project = tmp_path / "proj"
    project.mkdir()
    # invalid utf-8 bytes → undecodable; must be skipped, not raise
    (project / "blob.bin").write_bytes(b"\xff\xfe\x00\x80\x81 garbage")
    (project / "ok.txt").write_text(_SYNTH_LITERAL, encoding="utf-8")

    doc = ioc_scan.scan(str(project), iocs_path=str(iocs))
    # the readable file still trips; the binary one is silently skipped
    assert [f["file"] for f in doc["findings"]] == ["ok.txt"]


# --------------------------------------------------------------------------- #
# DEGRADE CLEAN — missing / empty / malformed data file → tools_unavailable, no raise
# --------------------------------------------------------------------------- #
def test_missing_data_file_degrades_clean(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "beacon.txt").write_text(_SYNTH_LITERAL, encoding="utf-8")
    missing = tmp_path / "does-not-exist.json"

    doc = ioc_scan.scan(str(project), iocs_path=str(missing))
    assert doc["findings"] == []                              # == expected: no findings
    assert "ioc-scan" in doc["summary"]["tools_unavailable"]  # == expected: degraded
    assert vf.validate(doc) == []                             # still schema-valid
    # != wrong: a missing data file must not surface a finding
    assert len(doc["findings"]) != 1


def test_empty_iocs_list_degrades_clean(tmp_path):
    iocs = _write_iocs(tmp_path, {"schema_version": 1, "iocs": []})
    project = tmp_path / "proj"
    project.mkdir()
    (project / "beacon.txt").write_text(_SYNTH_LITERAL, encoding="utf-8")

    doc = ioc_scan.scan(str(project), iocs_path=str(iocs))
    assert doc["findings"] == []                              # == expected
    assert "ioc-scan" in doc["summary"]["tools_unavailable"]  # empty pack = no coverage
    assert vf.validate(doc) == []


def test_malformed_data_file_degrades_clean(tmp_path):
    bad = tmp_path / "campaign-iocs.json"
    bad.write_text("{ this is not valid json", encoding="utf-8")
    project = tmp_path / "proj"
    project.mkdir()
    (project / "beacon.txt").write_text(_SYNTH_LITERAL, encoding="utf-8")

    doc = ioc_scan.scan(str(project), iocs_path=str(bad))
    assert doc["findings"] == []                              # == expected: no raise
    assert "ioc-scan" in doc["summary"]["tools_unavailable"]
    assert vf.validate(doc) == []


def test_placeholder_entries_without_literal_are_ignored(tmp_path):
    # an EXAMPLE_PLACEHOLDER entry with no usable literal must not match anything
    iocs = _write_iocs(
        tmp_path,
        {
            "schema_version": 1,
            "iocs": [
                {
                    "id": "EXAMPLE_PLACEHOLDER",
                    "literal": "",
                    "kind": "beacon",
                    "severity": "HIGH",
                    "primary_source": "TODO-primary-source-required",
                    "low_durability": True,
                }
            ],
        },
    )
    project = tmp_path / "proj"
    project.mkdir()
    (project / "f.txt").write_text("anything at all\n", encoding="utf-8")

    doc = ioc_scan.scan(str(project), iocs_path=str(iocs))
    assert doc["findings"] == []                              # == expected: empty literal never trips
    # a pack with no usable literal provides no coverage → degraded
    assert "ioc-scan" in doc["summary"]["tools_unavailable"]


# --------------------------------------------------------------------------- #
# DO-NOT-COPY — the SHIPPED data file carries NO real community literals
# --------------------------------------------------------------------------- #
def test_shipped_data_file_has_no_real_literals():
    doc = json.loads(_SHIPPED_DATA.read_text(encoding="utf-8"))
    assert isinstance(doc.get("iocs"), list)
    for entry in doc["iocs"]:
        # every shipped entry is an empty/placeholder with the TODO primary source and
        # is marked low_durability — DO-NOT-COPY: no real literal ships.
        assert entry.get("low_durability") is True
        assert entry.get("primary_source") == "TODO-primary-source-required"
        assert entry.get("id", "").startswith("EXAMPLE_PLACEHOLDER")


def test_shipped_data_file_yields_no_findings(tmp_path):
    # running the SHIPPED pack over a tree (even one with the synthetic literal)
    # must produce zero findings — it has no real literals to match.
    project = tmp_path / "proj"
    project.mkdir()
    (project / "f.txt").write_text(_SYNTH_LITERAL, encoding="utf-8")

    doc = ioc_scan.scan(str(project), iocs_path=str(_SHIPPED_DATA))
    assert doc["findings"] == []                 # == expected: inert by design


# --------------------------------------------------------------------------- #
# HIGH-1 (symlink-FILE escape): a symlink in `filenames` is read-confined — its
# out-of-tree target content is NEVER read / mis-attributed to the in-tree locator.
# --------------------------------------------------------------------------- #
def test_symlink_file_to_out_of_tree_secret_is_not_read(tmp_path):
    iocs = _write_iocs(tmp_path, _SYNTH_IOCS)
    # an out-of-tree "secret" containing the literal, OUTSIDE the scanned project
    secret = tmp_path / "outside" / "id_rsa"
    secret.parent.mkdir(parents=True)
    secret.write_text(_SYNTH_LITERAL, encoding="utf-8")

    project = tmp_path / "proj"
    project.mkdir()
    link = project / "innocent.txt"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):
        import pytest

        pytest.skip("symlinks unsupported on this platform")

    doc = ioc_scan.scan(str(project), iocs_path=str(iocs))
    # == expected: the symlinked out-of-tree secret content is NOT read → no finding
    assert doc["findings"] == []
    # != wrong: the locator must never be mis-attributed the secret's matching content
    assert "innocent.txt" not in [f["file"] for f in doc["findings"]]


def test_symlink_file_to_in_tree_match_is_also_skipped(tmp_path):
    # confinement is by realpath: a symlink whose target is IN-tree is still skipped
    # (defense-in-depth — we read regular files only), but the REAL in-tree file trips.
    iocs = _write_iocs(tmp_path, _SYNTH_IOCS)
    project = tmp_path / "proj"
    project.mkdir()
    real = project / "real.txt"
    real.write_text(_SYNTH_LITERAL, encoding="utf-8")
    link = project / "alias.txt"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        import pytest

        pytest.skip("symlinks unsupported on this platform")

    doc = ioc_scan.scan(str(project), iocs_path=str(iocs))
    files = [f["file"] for f in doc["findings"]]
    # the real regular file trips; the symlink alias is not separately read
    assert files == ["real.txt"]                 # == expected
    assert "alias.txt" not in files              # != wrong (no double-count via the link)


# --------------------------------------------------------------------------- #
# MED-1 (`..` defense-in-depth): no emitted `file` ever contains a `..` segment.
# --------------------------------------------------------------------------- #
def test_no_emitted_file_path_contains_dotdot(tmp_path):
    iocs = _write_iocs(tmp_path, _SYNTH_IOCS)
    project = tmp_path / "proj"
    (project / "a" / "b").mkdir(parents=True)
    (project / "a" / "b" / "deep.txt").write_text(_SYNTH_LITERAL, encoding="utf-8")

    doc = ioc_scan.scan(str(project), iocs_path=str(iocs))
    assert doc["findings"][0]["file"] == "a/b/deep.txt"   # == expected: clean rel path
    for f in doc["findings"]:
        # != wrong: a path that escaped the tree (== ".." or "../…") is never emitted
        assert ".." not in f["file"].split("/")
        assert not f["file"].startswith("../")


# --------------------------------------------------------------------------- #
# LOW-1 (unbounded-read DoS): each file read is capped (~2 MB); oversize files are
# scanned on a truncated head, never loaded whole / raised on.
# --------------------------------------------------------------------------- #
def test_oversize_file_is_read_capped_not_fatal(tmp_path):
    iocs = _write_iocs(tmp_path, _SYNTH_IOCS)
    project = tmp_path / "proj"
    project.mkdir()
    big = project / "huge.txt"
    # literal near the HEAD, then >2 MB of filler → a head-capped read still trips
    big.write_text(_SYNTH_LITERAL + "\n" + ("A" * 3_000_000), encoding="utf-8")

    doc = ioc_scan.scan(str(project), iocs_path=str(iocs))
    assert [f["file"] for f in doc["findings"]] == ["huge.txt"]   # == expected: head match trips


def test_literal_only_past_read_cap_is_not_loaded(tmp_path):
    # a literal that sits ONLY beyond the ~2 MB cap is not read → no finding (the cap is
    # real, not cosmetic). Pins the bound in BOTH directions with the head-match test above.
    iocs = _write_iocs(tmp_path, _SYNTH_IOCS)
    project = tmp_path / "proj"
    project.mkdir()
    big = project / "tail.txt"
    big.write_text(("A" * 3_000_000) + "\n" + _SYNTH_LITERAL, encoding="utf-8")

    doc = ioc_scan.scan(str(project), iocs_path=str(iocs))
    assert doc["findings"] == []                 # == expected: beyond-cap literal not loaded


# --------------------------------------------------------------------------- #
# G1 (project_dir contract): a missing / non-dir project_dir is a DEGRADE signal,
# never a silent "clean" — ioc-scan must land in tools_unavailable.
# --------------------------------------------------------------------------- #
def test_missing_project_dir_degrades_not_silent_clean(tmp_path):
    iocs = _write_iocs(tmp_path, _SYNTH_IOCS)
    missing = tmp_path / "no-such-dir"          # never created

    doc = ioc_scan.scan(str(missing), iocs_path=str(iocs))
    assert doc["findings"] == []                                 # == expected: nothing scanned
    assert "ioc-scan" in doc["summary"]["tools_unavailable"]     # == expected: DEGRADE, not clean
    assert vf.validate(doc) == []                                # still schema-valid


def test_project_dir_is_a_file_degrades(tmp_path):
    iocs = _write_iocs(tmp_path, _SYNTH_IOCS)
    not_a_dir = tmp_path / "afile.txt"
    not_a_dir.write_text(_SYNTH_LITERAL, encoding="utf-8")

    doc = ioc_scan.scan(str(not_a_dir), iocs_path=str(iocs))
    assert doc["findings"] == []                                 # == expected
    # != wrong: a file path passed as project_dir must NOT be reported as a clean scan
    assert "ioc-scan" in doc["summary"]["tools_unavailable"]


def test_existing_empty_dir_is_clean_not_degraded(tmp_path):
    # contrast with G1: a VALID empty dir is genuinely clean — NOT degraded (the data
    # pack has coverage, the tree just has no hits). Pins G1 != over-degrading.
    iocs = _write_iocs(tmp_path, _SYNTH_IOCS)
    project = tmp_path / "proj"
    project.mkdir()

    doc = ioc_scan.scan(str(project), iocs_path=str(iocs))
    assert doc["findings"] == []                                 # == expected: clean
    assert "ioc-scan" not in doc["summary"]["tools_unavailable"] # != wrong: NOT degraded
