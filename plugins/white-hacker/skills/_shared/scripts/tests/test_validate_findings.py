"""Tests for the findings-schema validator (T-1.1).

TDD per ADR-013: a valid contract sample passes; malformed docs (bad enum, missing
required field, out-of-range confidence, unknown field, negative line) are rejected;
enum membership is exact; duplicate ids are detected.

Run: uv run --with jsonschema --with pytest pytest plugins/white-hacker/skills/_shared/scripts/
"""
from __future__ import annotations

import copy

import validate_findings as vf

# The agent output-contract sample (one HIGH finding), known-valid.
VALID = {
    "summary": {
        "scanned_langs": ["go", "python", "typescript"],
        "tools_used": ["builtin-floor: Read/Grep/Glob"],
        "tools_unavailable": ["Opengrep (SAST)", "Trivy (SCA)"],
        "scoring_standard": "CVSS4.0",
        "counts": {"high": 1, "medium": 0, "low": 0},
    },
    "findings": [
        {
            "id": "F-001",
            "canonical_of": None,
            "file": "go-vuln/main.go",
            "line": 13,
            "severity": "HIGH",
            "category": "injection",
            "owasp": ["A03:2025"],
            "preconditions": [],
            "access_required": "unauth-remote",
            "verified": "static_review_only",
            "confidence": 0.95,
            "exploit_scenario": "shell metacharacters in host param",
            "recommendation": "use argv array; validate input",
            "first_link": "go-vuln/main.go:13",
            "tool_assisted": False,
            "kb_refs": [],
        }
    ],
}


def test_valid_sample_passes():
    assert vf.validate(VALID) == []


def test_severity_enum_enforced():
    d = copy.deepcopy(VALID)
    d["findings"][0]["severity"] = "CRITICAL"  # not in enum
    assert vf.validate(d)


def test_verified_enum_is_exactly_three_values():
    for ok in ("ladder_passed", "ladder_failed", "static_review_only"):
        d = copy.deepcopy(VALID)
        d["findings"][0]["verified"] = ok
        assert vf.validate(d) == []
    d = copy.deepcopy(VALID)
    d["findings"][0]["verified"] = "confirmed"  # not allowed
    assert vf.validate(d)


def test_missing_required_field_rejected():
    d = copy.deepcopy(VALID)
    del d["findings"][0]["file"]
    assert vf.validate(d)


def test_absolute_file_path_rejected():
    # Public-repo guard: an absolute/home path in `file` leaks the host machine layout
    # (root cause of the path leak we scrubbed). The schema must REJECT these.
    for bad in ("/Users/alice/repo/src/x.py", "/home/bob/main.go", "~/x.ts", "/etc/passwd"):
        d = copy.deepcopy(VALID)
        d["findings"][0]["file"] = bad
        assert vf.validate(d), f"absolute path {bad!r} must be rejected"


def test_repo_relative_file_path_accepted():
    # The counter-direction (Policy 9): legitimate repo-relative paths still pass.
    for ok in ("src/x.py", "go-vuln/main.go", "a.ts", "deep/nested/dir/File.java"):
        d = copy.deepcopy(VALID)
        d["findings"][0]["file"] = ok
        assert vf.validate(d) == [], f"relative path {ok!r} must be accepted"


def test_confidence_out_of_range_rejected():
    for bad in (1.5, -0.1):
        d = copy.deepcopy(VALID)
        d["findings"][0]["confidence"] = bad
        assert vf.validate(d)


def test_unknown_field_rejected():
    d = copy.deepcopy(VALID)
    d["findings"][0]["foo"] = "bar"  # additionalProperties: false
    assert vf.validate(d)


def test_negative_line_rejected():
    d = copy.deepcopy(VALID)
    d["findings"][0]["line"] = -1
    assert vf.validate(d)


def test_counts_required_in_summary():
    d = copy.deepcopy(VALID)
    del d["summary"]["counts"]
    assert vf.validate(d)


def test_bad_id_pattern_rejected():
    d = copy.deepcopy(VALID)
    d["findings"][0]["id"] = "finding-1"  # must match ^F-\d{3,}$
    assert vf.validate(d)


def test_canonical_of_accepts_null_and_id():
    d = copy.deepcopy(VALID)
    d["findings"][0]["canonical_of"] = "F-002"
    assert vf.validate(d) == []


def test_empty_findings_list_is_valid():
    d = copy.deepcopy(VALID)
    d["findings"] = []
    d["summary"]["counts"] = {"high": 0, "medium": 0, "low": 0}
    assert vf.validate(d) == []


def test_duplicate_ids_detected():
    d = copy.deepcopy(VALID)
    d["findings"].append(copy.deepcopy(d["findings"][0]))  # second F-001
    assert vf.duplicate_ids(d) == ["F-001"]


def test_no_duplicate_ids_on_clean_doc():
    assert vf.duplicate_ids(VALID) == []


def test_main_cli_ok(tmp_path, capsys):
    import json
    p = tmp_path / "ok.json"
    p.write_text(json.dumps(VALID))
    assert vf.main([str(p)]) == 0


def test_main_cli_detects_dup_ids(tmp_path):
    import json
    d = copy.deepcopy(VALID)
    d["findings"].append(copy.deepcopy(d["findings"][0]))
    p = tmp_path / "dup.json"
    p.write_text(json.dumps(d))
    # schema is fine, but --no-dup-ids should fail it
    assert vf.main([str(p)]) == 0
    assert vf.main([str(p), "--no-dup-ids"]) == 1


# === T-4.6: --check-kb-refs (every kb_ref must resolve to a KB entry id) ===
def _make_kb(tmp_path, *ids):
    kb = tmp_path / "kb"
    kb.mkdir()
    for i in ids:
        (kb / f"{i.lower()}.md").write_text(
            f"---\nid: {i}\ntitle: t\ntechnique_class: data-exfil\n---\nbody\n"
        )
    return kb


def test_kb_entry_ids_parses_front_matter(tmp_path):
    kb = _make_kb(tmp_path, "AISEC-DATA-EXFIL-001", "AISEC-TOOL-POISONING-001")
    assert vf.kb_entry_ids(kb) == {"AISEC-DATA-EXFIL-001", "AISEC-TOOL-POISONING-001"}


def test_unresolved_kb_refs_empty_when_all_resolve():
    d = copy.deepcopy(VALID)
    d["findings"][0]["kb_refs"] = ["AISEC-DATA-EXFIL-001"]
    assert vf.unresolved_kb_refs(d, {"AISEC-DATA-EXFIL-001"}) == []


def test_unresolved_kb_refs_reports_dangling():
    d = copy.deepcopy(VALID)
    d["findings"][0]["kb_refs"] = ["AISEC-NOPE-999"]
    errs = vf.unresolved_kb_refs(d, {"AISEC-DATA-EXFIL-001"})
    assert len(errs) == 1 and "AISEC-NOPE-999" in errs[0]


def test_main_check_kb_refs_resolves(tmp_path):
    import json
    kb = _make_kb(tmp_path, "AISEC-DATA-EXFIL-001")
    d = copy.deepcopy(VALID)
    d["findings"][0]["kb_refs"] = ["AISEC-DATA-EXFIL-001"]
    p = tmp_path / "ok.json"
    p.write_text(json.dumps(d))
    assert vf.main([str(p), "--check-kb-refs", str(kb)]) == 0


def test_main_check_kb_refs_dangling_fails(tmp_path):
    import json
    kb = _make_kb(tmp_path, "AISEC-DATA-EXFIL-001")
    d = copy.deepcopy(VALID)
    d["findings"][0]["kb_refs"] = ["AISEC-DATA-EXFIL-001", "AISEC-GONE-002"]
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(d))
    # passes plain validation, fails the kb-ref resolution check
    assert vf.main([str(p)]) == 0
    assert vf.main([str(p), "--check-kb-refs", str(kb)]) == 1


def test_main_check_kb_refs_missing_dir_is_usage_error(tmp_path):
    import json
    p = tmp_path / "x.json"
    p.write_text(json.dumps(VALID))
    assert vf.main([str(p), "--check-kb-refs", str(tmp_path / "nope")]) == 2
