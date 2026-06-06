"""Tests for the PATCH-STATE.json schema + validator (T-5.2, TDD).

Run: uv run --with jsonschema --with pytest pytest plugins/white-hacker/skills/sec-patch/scripts/tests/

Edge cases: valid sample passes; a missing ladder rung is rejected; ladder values are
tri-state {pass,fail,n/a} (exactly); bad finding_id rejected; unknown field rejected;
bad verdict rejected; variant rows require file+line; empty variants allowed.
"""
from __future__ import annotations

import copy

import validate_patch_state as vp

VALID = {
    "schema_version": "1.0",
    "patches": [
        {
            "finding_id": "F-001",
            "patch_path": "PATCHES/F-001-command-injection.diff",
            "ladder": {
                "build": "pass",
                "poc_stopped": "pass",
                "tests_passed": "pass",
                "reattack": "pass",
            },
            "variants": [
                {"file": "src/exec.py", "line": 42, "note": "same shell=True sink"}
            ],
            "verdict": "patched",
        }
    ],
}


def test_valid_sample_passes():
    assert vp.validate(VALID) == []


def test_missing_ladder_rung_rejected():
    d = copy.deepcopy(VALID)
    del d["patches"][0]["ladder"]["poc_stopped"]
    assert vp.validate(d)


def test_ladder_tri_state_enforced():
    # an out-of-vocab value is rejected
    d = copy.deepcopy(VALID)
    d["patches"][0]["ladder"]["build"] = "passed"  # not in {pass,fail,n/a}
    assert vp.validate(d)
    # all three legal values accepted
    for v in ("pass", "fail", "n/a"):
        d2 = copy.deepcopy(VALID)
        d2["patches"][0]["ladder"]["reattack"] = v
        assert vp.validate(d2) == []


def test_tri_state_enum_is_exactly_pass_fail_na():
    schema = vp.load_schema()
    assert set(schema["$defs"]["tri_state"]["enum"]) == {"pass", "fail", "n/a"}


def test_bad_finding_id_rejected():
    d = copy.deepcopy(VALID)
    d["patches"][0]["finding_id"] = "finding-1"  # must match ^F-\d{3,}$
    assert vp.validate(d)


def test_unknown_field_rejected():
    d = copy.deepcopy(VALID)
    d["patches"][0]["root_cause"] = "x"  # additionalProperties: false
    assert vp.validate(d)


def test_bad_verdict_rejected():
    d = copy.deepcopy(VALID)
    d["patches"][0]["verdict"] = "done"  # not in enum
    assert vp.validate(d)


def test_verdict_enum_is_class_not_severity():
    # verdict is a verification CLASS (PLAN 6.1), distinct from severity.
    schema = vp.load_schema()
    assert set(schema["$defs"]["patch_record"]["properties"]["verdict"]["enum"]) == {
        "patched", "patch_failed", "wont_fix", "needs_human"
    }


def test_patch_path_must_be_under_patches():
    # ADR-010 enforced at the data layer: a diff written anywhere but PATCHES/ is invalid.
    d = copy.deepcopy(VALID)
    d["patches"][0]["patch_path"] = "src/fix.diff"
    assert vp.validate(d)


def test_schema_carries_no_severity_field():
    # The ladder records what was demonstrated; severity stays in finding-schema (PLAN 6.1).
    schema = vp.load_schema()
    props = schema["$defs"]["patch_record"]["properties"]
    assert "severity" not in props
    assert schema["$defs"]["patch_record"]["additionalProperties"] is False


def test_variant_requires_file_and_line():
    d = copy.deepcopy(VALID)
    d["patches"][0]["variants"] = [{"file": "src/x.py"}]  # missing line
    assert vp.validate(d)


def test_empty_variants_allowed():
    d = copy.deepcopy(VALID)
    d["patches"][0]["variants"] = []
    assert vp.validate(d) == []


def test_na_ladder_rung_with_nonpatched_verdict_is_valid():
    d = copy.deepcopy(VALID)
    d["patches"][0]["ladder"]["build"] = "n/a"  # e.g. interpreted language, no build
    d["patches"][0]["ladder"]["reattack"] = "fail"
    d["patches"][0]["verdict"] = "patch_failed"
    assert vp.validate(d) == []


def test_main_cli_ok(tmp_path):
    import json
    p = tmp_path / "ok.json"
    p.write_text(json.dumps(VALID))
    assert vp.main([str(p)]) == 0


def test_main_cli_rejects_invalid(tmp_path):
    import json
    d = copy.deepcopy(VALID)
    del d["patches"][0]["ladder"]["reattack"]
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(d))
    assert vp.main([str(p)]) == 1


def test_main_cli_usage_error_on_no_args():
    assert vp.main([]) == 2
