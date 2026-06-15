"""Tests for the coverage matrix aggregator (wh-5ox.19, TDD).

Run: nice -n 10 uv run --project plugins/white-hacker/skills/sec-report/scripts \
       --with pytest pytest plugins/white-hacker/skills/sec-report/scripts/tests -q

A coverage matrix joins findings -> their att_ck/atlas technique ids against the KB
technique universe, grouping by MITRE id. An in-scope KB technique with ZERO covering
finding is the intended recall/degradation GAP signal the outer loop (/sec-learn) harvests.

Policy 9 (tests verify intent): each invariant pins BOTH `== expected` AND `!= wrong`.
FIXTURES ONLY — tests inject a tmp_path KB dir via --kb-dir / the kb_dir arg; they NEVER
read the live `ai-attack-kb/reference/` dir (concurrently edited by wh-5ox.5).
"""
from __future__ import annotations

from pathlib import Path

import coverage_matrix as cm


# --- fixtures -------------------------------------------------------------

def _kb_entry(entry_id: str, xref: list, *, title: str = "t") -> str:
    """A minimal KB *.md with YAML front-matter carrying `id` + `xref` (the two fields
    coverage_matrix reads). YAML list of xref strings/ints is rendered inline."""
    import json as _json

    rendered = "[" + ", ".join(_json.dumps(x) for x in xref) + "]"
    return (
        "---\n"
        f"id: {entry_id}\n"
        f"title: {title}\n"
        f"xref: {rendered}\n"
        "---\n"
        "Body summary paragraph for the entry.\n"
    )


def _write_kb(tmp_path: Path, files: dict[str, str]) -> Path:
    kb = tmp_path / "kb"
    kb.mkdir()
    for name, text in files.items():
        (kb / name).write_text(text)
    return kb


def _finding(**over) -> dict:
    """A schema-valid finding (15 required fields) + optional att_ck/atlas overrides."""
    base = {
        "id": "F-001",
        "canonical_of": None,
        "file": "src/x.ts",
        "line": 42,
        "severity": "HIGH",
        "category": "injection",
        "owasp": ["A03:2025"],
        "preconditions": [],
        "access_required": "unauth-remote",
        "verified": "static_review_only",
        "confidence": 0.7,
        "exploit_scenario": "scenario",
        "recommendation": "fix it",
        "first_link": "src/x.ts:42",
        "tool_assisted": False,
        "kb_refs": [],
    }
    base.update(over)
    return base


def _doc(findings: list[dict]) -> dict:
    return {
        "summary": {
            "scanned_langs": [],
            "tools_used": [],
            "tools_unavailable": [],
            "scoring_standard": "CVSS4.0",
            "counts": {"high": 0, "medium": 0, "low": 0},
        },
        "findings": findings,
    }


# --- (a) covered technique shows its refs + covered?=yes -------------------

def test_covered_technique_shows_refs_and_yes(tmp_path):
    kb = _write_kb(tmp_path, {"e.md": _kb_entry("AISEC-1", ["T1195.002"])})
    doc = _doc([_finding(att_ck=["T1195.002"])])
    out = cm.build_matrix(doc, kb)
    # the row for T1195.002 is covered and names the finding ref
    assert "T1195.002" in out
    assert "F-001 (src/x.ts:42)" in out
    # covered, NOT a gap
    assert "yes" in out
    assert "gap" not in out


# --- (b) in-scope KB technique with ZERO finding -> gap, refs `—` ----------

def test_uncovered_in_scope_technique_is_gap(tmp_path):
    kb = _write_kb(tmp_path, {"e.md": _kb_entry("AISEC-1", ["T1195.002"])})
    doc = _doc([])  # no findings at all -> the technique is a recall gap
    out = cm.build_matrix(doc, kb)
    assert "T1195.002" in out
    # gap row: covered? == gap, refs == em-dash placeholder, NOT covered
    assert "gap" in out
    assert "yes" not in out
    assert "—" in out


def test_finding_with_unrelated_id_leaves_kb_technique_a_gap(tmp_path):
    # finding cites T9999 (not in KB universe); the KB's T1195.002 stays a gap.
    kb = _write_kb(tmp_path, {"e.md": _kb_entry("AISEC-1", ["T1195.002"])})
    doc = _doc([_finding(att_ck=["T9999"])])
    out = cm.build_matrix(doc, kb)
    # T1195.002 present and a gap; T9999 is NOT in the matrix (universe = KB only)
    assert "T1195.002" in out
    assert "gap" in out
    assert "T9999" not in out


# --- (c) groups by id, rows sorted, deterministic -------------------------

def test_groups_sorted_and_deterministic(tmp_path):
    kb = _write_kb(
        tmp_path,
        {
            "a.md": _kb_entry("AISEC-A", ["T2000", "AML.T0010"]),
            "b.md": _kb_entry("AISEC-B", ["T1000"]),
        },
    )
    doc = _doc(
        [
            _finding(id="F-002", att_ck=["T2000", "T1000"]),
            _finding(id="F-001", att_ck=["T1000"]),
        ]
    )
    out1 = cm.build_matrix(doc, kb)
    out2 = cm.build_matrix(doc, kb)
    # determinism: identical across calls (no RNG / set-ordering leak)
    assert out1 == out2
    # rows sorted by ID ascending: AML.T0010 < T1000 < T2000 (lexical)
    pos_aml = out1.index("AML.T0010")
    pos_t1000 = out1.index("| T1000 ")
    pos_t2000 = out1.index("| T2000 ")
    assert pos_aml < pos_t1000 < pos_t2000
    # refs for a multi-finding id are sorted + de-duped, NOT reverse order
    i1 = out1.index("F-001 (src/x.ts:42)")
    i2 = out1.index("F-002 (src/x.ts:42)")
    assert i1 < i2


def test_atlas_and_attck_modality_labelled(tmp_path):
    kb = _write_kb(
        tmp_path,
        {"e.md": _kb_entry("AISEC-1", ["AML.T0010", "T1195.002"])},
    )
    doc = _doc([_finding(atlas=["AML.T0010"]), _finding(id="F-002", att_ck=["T1195.002"])])
    out = cm.build_matrix(doc, kb)
    # modality column distinguishes the two taxonomies
    assert "atlas" in out
    assert "att_ck" in out


# --- (d) DEGRADE: non-str xref element + malformed front-matter ------------

def test_non_str_xref_element_dropped_not_raised(tmp_path):
    # int 123 in xref must be DROPPED at the call site (mitre_from_xref has no isinstance
    # guard and would AttributeError on .split). T1195 still enters the universe.
    kb = _write_kb(tmp_path, {"e.md": _kb_entry("AISEC-1", [123, "T1195"])})
    doc = _doc([])
    out = cm.build_matrix(doc, kb)  # must NOT raise
    assert isinstance(out, str)
    assert "T1195" in out
    # the int was coerced away, never rendered as a technique id
    assert "| 123 " not in out


def test_malformed_front_matter_file_skipped_not_raised(tmp_path):
    kb = _write_kb(
        tmp_path,
        {
            "good.md": _kb_entry("AISEC-1", ["T1195"]),
            "nofm.md": "no front matter here\njust body\n",
            "unterminated.md": "---\nid: X\nxref: [\"T2000\"]\nstill open...\n",
        },
    )
    doc = _doc([])
    out = cm.build_matrix(doc, kb)  # degrade-never-raise (ADR-003)
    # the well-formed entry's technique survives
    assert "T1195" in out
    # the skipped files' would-be id never enters the universe
    assert "T2000" not in out


def test_xref_not_a_list_yields_no_techniques(tmp_path):
    kb = _write_kb(tmp_path, {"e.md": _kb_entry("AISEC-1", []).replace(
        "xref: []", "xref: not-a-list")})
    doc = _doc([])
    out = cm.build_matrix(doc, kb)  # must not raise
    assert isinstance(out, str)
    assert "T1195" not in out


# --- (e) main() returns 2 on a schema-invalid doc -------------------------

def test_main_schema_invalid_returns_2(tmp_path):
    import json

    kb = _write_kb(tmp_path, {"e.md": _kb_entry("AISEC-1", ["T1195"])})
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"findings": []}))  # missing required summary
    rc = cm.main([str(bad), "--kb-dir", str(kb)])
    assert rc == 2
    assert rc != 0


def test_main_malformed_json_returns_2(tmp_path):
    kb = _write_kb(tmp_path, {"e.md": _kb_entry("AISEC-1", ["T1195"])})
    p = tmp_path / "broken.json"
    p.write_text("{not json")
    assert cm.main([str(p), "--kb-dir", str(kb)]) == 2


def test_main_valid_doc_returns_0_and_writes_out(tmp_path):
    import json

    kb = _write_kb(tmp_path, {"e.md": _kb_entry("AISEC-1", ["T1195"])})
    good = tmp_path / "good.json"
    good.write_text(json.dumps(_doc([_finding(att_ck=["T1195"])])))
    out_path = tmp_path / "SECTION.md"
    rc = cm.main([str(good), "--kb-dir", str(kb), "--out", str(out_path)])
    assert rc == 0
    written = out_path.read_text()
    assert "T1195" in written
    assert "F-001 (src/x.ts:42)" in written


# --- (f) degrade-never-raise hardening (QA/security adversarial findings) ---

def test_non_utf8_kb_file_skipped_not_raised(tmp_path):
    # A KB file with a stray non-UTF-8 byte must DEGRADE, not raise UnicodeDecodeError
    # (a ValueError, NOT an OSError) — ADR-003. The good entry still survives.
    kb = _write_kb(tmp_path, {"good.md": _kb_entry("AISEC-1", ["T1195"])})
    (kb / "bad.md").write_bytes(b"---\nid: BAD\nxref: [\"T2000\"]\n---\n\xff body\n")
    out = cm.build_matrix(_doc([]), kb)  # must NOT raise
    assert isinstance(out, str)
    assert "T1195" in out


def test_non_dict_finding_and_non_list_findings_degrade(tmp_path):
    # A non-dict finding element is skipped; a non-list `findings` yields no coverage.
    kb = _write_kb(tmp_path, {"e.md": _kb_entry("AISEC-1", ["T1195"])})
    out1 = cm.build_matrix({"findings": ["oops", 123, None]}, kb)  # must NOT raise
    out2 = cm.build_matrix({"findings": {"not": "a list"}}, kb)    # must NOT raise
    assert isinstance(out1, str) and isinstance(out2, str)
    assert "T1195" in out1 and "gap" in out1   # KB technique still renders, uncovered
    assert "T1195" in out2


def test_markdown_cell_injection_neutralized(tmp_path):
    # A schema-permitted `file` (finding-schema only constrains its FIRST char) carrying a
    # pipe + newline must NOT forge table columns or a phantom coverage row.
    kb = _write_kb(tmp_path, {"e.md": _kb_entry("AISEC-1", ["T1195"])})
    evil = _finding(file="a|INJ\n| evil | T1195 | yes | att_ck | pwned", att_ck=["T1195"])
    out = cm.build_matrix(_doc([evil]), kb)
    pipe_lines = [ln for ln in out.splitlines() if ln.startswith("|")]
    assert len(pipe_lines) == 3                # header + separator + ONE real row, no phantom
    assert "\n| evil " not in out             # the injected newline did not survive
    assert "a\\|INJ" in out                    # the pipe was escaped, not a column delimiter
