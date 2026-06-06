"""Tests for the deterministic eval scorer (T-7.2, TDD).

Run: uv run --with jsonschema --with pytest pytest evals/tests/test_score.py

Synthetic labeled sets with known TP/FP/FN: a perfect run (J=1), an all-FP run (J=-1), a
line-tolerance edge case, and the machine-JSON shape.
"""
from __future__ import annotations

import score as sc

LABELS = [
    {"case_id": "c1", "language": "python", "category": "injection", "severity": "HIGH",
     "vulnerable": {"file": "cases/c1/vulnerable_variant.py", "line": 12},
     "benign_lookalike": {"file": "cases/c1/benign_lookalike.py"}},
    {"case_id": "c2", "language": "go", "category": "ssrf", "severity": "HIGH",
     "vulnerable": {"file": "cases/c2/vulnerable_variant.go", "line": 20},
     "benign_lookalike": {"file": "cases/c2/benign_lookalike.go"}},
]


def _f(file, line, category):
    return {"file": file, "line": line, "category": category}


def test_perfect_run_j_is_1():
    findings = {"findings": [
        _f("cases/c1/vulnerable_variant.py", 12, "injection"),
        _f("cases/c2/vulnerable_variant.go", 20, "ssrf"),
    ]}
    r = sc.score(findings, LABELS)
    assert r["tp"] == 2 and r["fn"] == 0 and r["fp"] == 0 and r["tn"] == 2
    assert r["tpr"] == 1.0 and r["fpr"] == 0.0 and r["youden_j"] == 1.0


def test_all_fp_run_j_is_negative_1():
    # findings only on the benign look-alikes; none on the vulnerable variants
    findings = {"findings": [
        _f("cases/c1/benign_lookalike.py", 5, "injection"),
        _f("cases/c2/benign_lookalike.go", 8, "ssrf"),
    ]}
    r = sc.score(findings, LABELS)
    assert r["tp"] == 0 and r["fp"] == 2
    assert r["tpr"] == 0.0 and r["fpr"] == 1.0 and r["youden_j"] == -1.0


def test_no_findings_is_tpr0_fpr0():
    r = sc.score({"findings": []}, LABELS)
    assert r["tpr"] == 0.0 and r["fpr"] == 0.0 and r["youden_j"] == 0.0


def test_line_tolerance():
    # within tol (+3) matches; beyond tol (+4) does not
    near = {"findings": [_f("cases/c1/vulnerable_variant.py", 15, "injection")]}
    far = {"findings": [_f("cases/c1/vulnerable_variant.py", 16, "injection")]}
    assert sc.score(near, LABELS[:1], tol=3)["tp"] == 1
    assert sc.score(far, LABELS[:1], tol=3)["tp"] == 0


def test_category_must_match():
    # right file+line but wrong category -> not a TP
    findings = {"findings": [_f("cases/c1/vulnerable_variant.py", 12, "xss")]}
    assert sc.score(findings, LABELS[:1])["tp"] == 0


def test_file_match_by_basename():
    # a finding referencing just the basename still matches the labeled path
    findings = {"findings": [_f("vulnerable_variant.py", 12, "injection")]}
    assert sc.score(findings, LABELS[:1])["tp"] == 1


def test_output_shape_and_by_category():
    findings = {"findings": [_f("cases/c1/vulnerable_variant.py", 12, "injection")]}
    r = sc.score(findings, LABELS)
    assert {"tpr", "fpr", "youden_j", "tp", "fn", "fp", "tn", "by_category"} <= r.keys()
    assert "injection" in r["by_category"] and "ssrf" in r["by_category"]
    assert r["by_category"]["injection"]["youden_j"] == 1.0


def test_main_cli(tmp_path, capsys):
    import json
    findings = {"summary": {"scanned_langs": [], "tools_used": [], "tools_unavailable": [],
                            "scoring_standard": "x", "counts": {"high": 0, "medium": 0, "low": 0}},
                "findings": [_f("cases/c1/vulnerable_variant.py", 12, "injection")]}
    fp = tmp_path / "f.json"; fp.write_text(json.dumps(findings))
    lp = tmp_path / "labels.json"; lp.write_text(json.dumps(LABELS))
    assert sc.main(["--findings", str(fp), "--labels", str(lp)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["tp"] == 1


def test_main_requires_labels_or_corpus(tmp_path):
    import json
    fp = tmp_path / "f.json"; fp.write_text(json.dumps({"findings": []}))
    assert sc.main(["--findings", str(fp)]) == 2
