"""Tests for the ai-attack-kb entry validator (T-4.1, TDD).

Run: `uv run --with jsonschema --with pyyaml --with pytest pytest .claude/skills/ai-attack-kb/scripts/tests/`

Covers (edge cases per the Phase-4 grooming Definition of Ready):
  * a well-formed entry validates clean;
  * missing metadata.source / url / retrieved -> fails (all three MANDATORY);
  * bad technique_class / status -> fails (controlled enums);
  * id not matching the typed pattern -> fails;
  * duplicate id across files -> fails;
  * oversize summary (>120 words) / oversize file (>400 lines) -> fails;
  * a file with no YAML front-matter -> fails;
  * the schema's `status` enum is exactly {active, archived, deprecated};
  * the schema's `id` pattern is typed (rejects a non-AISEC id).
"""
from __future__ import annotations

from pathlib import Path

import validate_kb as vk

# --- fixtures -------------------------------------------------------------

VALID_FRONT = """\
id: AISEC-PROMPT-INJECTION-001
title: Indirect prompt injection via retrieved content
technique_class: prompt-injection
severity: high
confidence: 0.8
status: active
date: 2026-06-06
modified: 2026-06-06
review_by: 2026-09-06
metadata:
  source: OWASP Top 10 for LLM Applications 2025
  url: https://genai.owasp.org/llm-top-10/
  retrieved: 2026-06-06
supersedes: null
detections:
  - "grep for retrieved/tool content concatenated into a prompt string"
xref:
  - "LLM01:2025"
  - "AML.T0051"
"""

VALID_BODY = "Untrusted retrieved content is concatenated into the model prompt.\n\nDetection: ...\n\nChecklist: segregate untrusted spans.\n"


def _entry(front: str, body: str = VALID_BODY) -> str:
    return f"---\n{front}---\n\n{body}"


def _write(dirpath: Path, name: str, front: str, body: str = VALID_BODY) -> Path:
    p = dirpath / name
    p.write_text(_entry(front, body))
    return p


# --- happy path -----------------------------------------------------------

def test_valid_entry_passes(tmp_path: Path):
    p = _write(tmp_path, "prompt-injection.md", VALID_FRONT)
    assert vk.validate_file(p)[1] == []


def test_dir_of_valid_entries_exits_zero(tmp_path: Path):
    _write(tmp_path, "prompt-injection.md", VALID_FRONT)
    _write(tmp_path, "tool-poisoning.md",
           VALID_FRONT.replace("AISEC-PROMPT-INJECTION-001", "AISEC-TOOL-POISONING-001")
                      .replace("technique_class: prompt-injection", "technique_class: tool-poisoning"))
    assert vk.main([str(tmp_path)]) == 0


# --- mandatory provenance -------------------------------------------------

def test_missing_metadata_source_fails(tmp_path: Path):
    front = VALID_FRONT.replace("  source: OWASP Top 10 for LLM Applications 2025\n", "")
    p = _write(tmp_path, "prompt-injection.md", front)
    errs = vk.validate_file(p)[1]
    assert any("source" in e for e in errs), errs
    assert vk.main([str(tmp_path)]) == 1


def test_missing_metadata_url_fails(tmp_path: Path):
    front = VALID_FRONT.replace("  url: https://genai.owasp.org/llm-top-10/\n", "")
    assert vk.validate_file(_write(tmp_path, "x.md", front))[1] != []


def test_missing_metadata_retrieved_fails(tmp_path: Path):
    front = VALID_FRONT.replace("  retrieved: 2026-06-06\n", "")
    assert vk.validate_file(_write(tmp_path, "x.md", front))[1] != []


def test_bad_metadata_url_scheme_fails(tmp_path: Path):
    front = VALID_FRONT.replace("https://genai.owasp.org/llm-top-10/", "ftp://example.com")
    assert vk.validate_file(_write(tmp_path, "x.md", front))[1] != []


# --- controlled enums -----------------------------------------------------

def test_bad_technique_class_fails(tmp_path: Path):
    front = VALID_FRONT.replace("technique_class: prompt-injection", "technique_class: made-up-class")
    assert vk.validate_file(_write(tmp_path, "x.md", front))[1] != []


def test_supply_chain_technique_class_validates(tmp_path: Path):
    """`supply-chain` is in the closed enum (ADR-019: 5->6 stems). Rule 9: pin BOTH
    sides — a real `supply-chain` entry validates, AND a made-up class still fails."""
    front = (
        VALID_FRONT.replace("AISEC-PROMPT-INJECTION-001", "AISEC-SUPPLY-CHAIN-001")
        .replace("technique_class: prompt-injection", "technique_class: supply-chain")
        .replace('"LLM01:2025"', '"LLM03:2025"')
    )
    assert vk.validate_file(_write(tmp_path, "supply-chain.md", front))[1] == []
    # the controlled enum is still closed: an out-of-vocab class must fail.
    bad = front.replace("technique_class: supply-chain", "technique_class: made-up-class")
    assert vk.validate_file(_write(tmp_path, "bad.md", bad))[1] != []


def test_supply_chain_in_schema_enum():
    schema = vk.load_schema()
    enum = schema["properties"]["technique_class"]["enum"]
    assert "supply-chain" in enum
    assert "made-up-class" not in enum  # still a closed vocabulary


def test_bad_status_fails(tmp_path: Path):
    front = VALID_FRONT.replace("status: active", "status: retired")
    assert vk.validate_file(_write(tmp_path, "x.md", front))[1] != []


def test_status_enum_is_exactly_active_archived_deprecated():
    schema = vk.load_schema()
    assert set(schema["properties"]["status"]["enum"]) == {"active", "archived", "deprecated"}


# --- typed id -------------------------------------------------------------

def test_bad_id_pattern_fails(tmp_path: Path):
    front = VALID_FRONT.replace("AISEC-PROMPT-INJECTION-001", "PROMPT-INJECTION-1")
    assert vk.validate_file(_write(tmp_path, "x.md", front))[1] != []


def test_id_pattern_is_typed():
    import re
    pat = vk.load_schema()["properties"]["id"]["pattern"]
    assert re.match(pat, "AISEC-PROMPT-INJECTION-001")
    assert not re.match(pat, "prompt-injection-001")  # must be the typed AISEC- form


def test_confidence_out_of_range_fails(tmp_path: Path):
    front = VALID_FRONT.replace("confidence: 0.8", "confidence: 1.7")
    assert vk.validate_file(_write(tmp_path, "x.md", front))[1] != []


# --- uniqueness across the dir -------------------------------------------

def test_duplicate_id_across_files_fails(tmp_path: Path):
    _write(tmp_path, "prompt-injection.md", VALID_FRONT)
    # same id, different file -> collision
    _write(tmp_path, "tool-poisoning.md",
           VALID_FRONT.replace("technique_class: prompt-injection", "technique_class: tool-poisoning"))
    errs = vk.validate_dir(tmp_path)
    assert any("duplicate" in e.lower() for e in errs), errs
    assert vk.main([str(tmp_path)]) == 1


# --- size caps ------------------------------------------------------------

def test_oversize_summary_fails(tmp_path: Path):
    body = " ".join(["word"] * 121) + "\n\nrest\n"
    p = _write(tmp_path, "x.md", VALID_FRONT, body=body)
    errs = vk.validate_file(p)[1]
    assert any("summary" in e.lower() or "120" in e for e in errs), errs


def test_summary_at_cap_passes(tmp_path: Path):
    body = " ".join(["word"] * 120) + "\n\nrest\n"
    p = _write(tmp_path, "x.md", VALID_FRONT, body=body)
    assert vk.validate_file(p)[1] == []


def test_oversize_file_fails(tmp_path: Path):
    body = VALID_BODY + ("\nfiller line" * 405)
    p = _write(tmp_path, "x.md", VALID_FRONT, body=body)
    errs = vk.validate_file(p)[1]
    assert any("400" in e or "line" in e.lower() for e in errs), errs


# --- data-minimization (Rule 9: no verbatim third-party body) -------------

def _msg_is_datamin(errs: list[str]) -> bool:
    return any("data-minimization" in e and "verbatim" in e for e in errs)


def test_oversize_fenced_code_block_fails(tmp_path: Path):
    """A 25-line fenced ``` block (>MAX_VERBATIM_BLOCK_LINES) reads like a pasted
    source dump -> INVALID with the data-minimization message."""
    code = "\n".join(f"line {i}" for i in range(25))  # 25 content lines
    body = VALID_BODY + f"\n```\n{code}\n```\n"
    p = _write(tmp_path, "x.md", VALID_FRONT, body=body)
    errs = vk.validate_file(p)[1]
    assert _msg_is_datamin(errs), errs
    assert any("code-block" in e for e in errs), errs
    assert vk.main([str(tmp_path)]) == 1


def test_short_code_block_passes(tmp_path: Path):
    """A few-line detection grep snippet is legit paraphrased note -> VALID
    (no data-min error). Pins the `!=` side: a short block must NOT trip."""
    body = VALID_BODY + "\n```\ngrep -rn 'eval(' .\ngrep -rn 'pickle.loads' .\n```\n"
    p = _write(tmp_path, "x.md", VALID_FRONT, body=body)
    errs = vk.validate_file(p)[1]
    assert errs == [], errs
    assert not _msg_is_datamin(errs)


def test_code_block_at_threshold_passes(tmp_path: Path):
    """Exactly MAX_VERBATIM_BLOCK_LINES content lines is at the cap, not over -> VALID."""
    n = vk.MAX_VERBATIM_BLOCK_LINES
    code = "\n".join(f"line {i}" for i in range(n))
    body = VALID_BODY + f"\n```\n{code}\n```\n"
    p = _write(tmp_path, "x.md", VALID_FRONT, body=body)
    assert vk.validate_file(p)[1] == []


def test_oversize_blockquote_run_fails(tmp_path: Path):
    """A 25-line contiguous `>` blockquote run reads like a pasted source quote
    -> INVALID with the data-minimization message."""
    quote = "\n".join(f"> quoted line {i}" for i in range(25))  # 25 contiguous `>` lines
    body = VALID_BODY + f"\n{quote}\n"
    p = _write(tmp_path, "x.md", VALID_FRONT, body=body)
    errs = vk.validate_file(p)[1]
    assert _msg_is_datamin(errs), errs
    assert any("blockquote" in e for e in errs), errs
    assert vk.main([str(tmp_path)]) == 1


def test_short_blockquote_passes(tmp_path: Path):
    """A 2-line `>` callout is fine -> VALID (the `!=` side for blockquotes)."""
    body = VALID_BODY + "\n> note: this is an architectural design risk.\n> see ai-llm.md LLM01.\n"
    p = _write(tmp_path, "x.md", VALID_FRONT, body=body)
    errs = vk.validate_file(p)[1]
    assert errs == [], errs
    assert not _msg_is_datamin(errs)


def test_max_verbatim_block_lines_constant():
    """The threshold is a tunable module constant (DESIGN: tunable default)."""
    assert vk.MAX_VERBATIM_BLOCK_LINES == 20
    assert vk.MAX_VERBATIM_BLOCK_LINES != 0  # a real positive cap, not disabled


def test_real_reference_entries_still_validate():
    """The shipped reference/*.md entries must NOT trip the data-min lint
    (else the threshold is too low). Pins the `!=` side against false positives."""
    ref = Path(__file__).resolve().parents[2] / "reference"
    assert ref.is_dir(), ref
    errs = vk.validate_dir(ref)
    assert errs == [], errs
    assert vk.main([str(ref)]) == 0


# --- malformed ------------------------------------------------------------

def test_missing_front_matter_fails(tmp_path: Path):
    p = tmp_path / "x.md"
    p.write_text("# just a heading, no front matter\n")
    assert vk.validate_file(p)[1] != []


def test_unparseable_yaml_fails(tmp_path: Path):
    p = tmp_path / "x.md"
    p.write_text("---\nid: [unclosed\n---\nbody\n")
    assert vk.validate_file(p)[1] != []
