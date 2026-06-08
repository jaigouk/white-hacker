"""TDD (T-12.9b / wh-966): cross-file (multi-file) corpus cases for eval headroom.

The 115-case corpus saturated at J=1.0 — the agent aces single-file pairs (T-12.9). These `mf-*`
cases put the taint SOURCE in a `_support_*.py` file and the SINK in another file, with neutral
names so the sink file ALONE cannot reveal the taint — the reviewer must build a cross-file call
graph. Each pins: multifile marker, support files present, the sink file imports its support module
(genuinely cross-file), the labeled line is the intended sink, and no answer-leaking markers.

Run: uv run --project evals --with pytest --with jsonschema pytest evals/tests/test_multifile_cases_t129b.py
"""
from __future__ import annotations

import json
import pathlib

_HERE = pathlib.Path(__file__).resolve()
REPO = next(c for c in (_HERE, *_HERE.parents) if (c / ".git").exists())
CASES = REPO / "evals" / "corpus" / "cases"

EXPECTED_SINK = {
    "mf-pathtrav-crossfile": "os.path.join(BASE, ctx.target)",
    "mf-sqli-crossfile": "ORDER BY {col}",
    "mf-llm05-crossfile": "subprocess.run(s, shell=True",
}
LEAK_MARKERS = ("sink", "vuln", "exploit", "insecure", "unsafe", "attacker", "tainted",
                "injection", "cwe-", "todo", "fixme", "# bad")


def _mf_dirs() -> list[pathlib.Path]:
    return sorted(d for d in CASES.glob("mf-*") if (d / "label.json").exists())


def test_at_least_three_multifile_cases():
    assert len(_mf_dirs()) >= 3, f"expected >= 3 mf-* cases, found {len(_mf_dirs())}"
    assert {d.name for d in _mf_dirs()} >= set(EXPECTED_SINK)


def test_each_multifile_case_well_formed():
    for d in _mf_dirs():
        lab = json.loads((d / "label.json").read_text())
        assert lab["case_id"] == d.name
        assert lab.get("multifile") is True, f"{d.name}: must set multifile:true"
        assert lab["difficulty"] == "hard"
        assert (d / "vulnerable_variant.py").exists() and (d / "benign_lookalike.py").exists()
        sup = lab.get("support_files") or []
        assert sup, f"{d.name}: multifile case must list support_files"
        for s in sup:
            assert (d / s).exists(), f"{d.name}: missing support file {s}"


def test_taint_is_genuinely_cross_file():
    """Both the vulnerable and benign sink files must IMPORT from a support module — i.e. the taint
    source lives in another file (the cross-file property this whole ticket exists to test)."""
    for d in _mf_dirs():
        sup_mods = {s[:-3] for s in (json.loads((d / "label.json").read_text()).get("support_files") or [])}
        for variant in ("vulnerable_variant.py", "benign_lookalike.py"):
            txt = (d / variant).read_text()
            assert any(f"import {m}" in txt or f"from {m} " in txt for m in sup_mods), \
                f"{d.name}/{variant}: must import a support module (cross-file taint), got none of {sup_mods}"


def test_labeled_line_sits_on_intended_sink():
    for d in _mf_dirs():
        lab = json.loads((d / "label.json").read_text())
        tok = EXPECTED_SINK.get(d.name)
        if tok is None:
            continue
        lines = (d / "vulnerable_variant.py").read_text().splitlines()
        ln = lab["vulnerable"]["line"]
        assert 1 <= ln <= len(lines) and tok in lines[ln - 1], \
            f"{d.name}: labeled line {ln} ({lines[ln-1]!r}) lacks sink {tok!r}"


def test_no_answer_leaking_markers():
    for d in _mf_dirs():
        files = ["vulnerable_variant.py", "benign_lookalike.py", *(json.loads((d / "label.json").read_text()).get("support_files") or [])]
        for fn in files:
            text = (d / fn).read_text().lower()
            hit = [m for m in LEAK_MARKERS if m in text]
            assert not hit, f"{d.name}/{fn} leaks answer marker(s): {hit}"
