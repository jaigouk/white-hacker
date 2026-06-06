"""Tests for dedupe_kb (T-8.2, TDD).

Run: uv run --with pyyaml --with pytest pytest plugins/white-hacker/skills/ai-attack-kb/scripts/tests/test_dedupe_kb.py
"""
from __future__ import annotations

import dedupe_kb as dk


def _entry(d, fname, eid, tclass="prompt-injection", title="t", xref=("LLM01:2025",)):
    fm = (f"---\nid: {eid}\ntitle: {title}\ntechnique_class: {tclass}\nstatus: active\n"
          f"review_by: 2099-01-01\nxref: [{', '.join(repr(x) for x in xref)}]\n---\nbody\n")
    (d / fname).write_text(fm)


def test_duplicate_id_fails(tmp_path):
    _entry(tmp_path, "a.md", "AISEC-PROMPT-INJECTION-001")
    _entry(tmp_path, "b.md", "AISEC-PROMPT-INJECTION-001", tclass="tool-poisoning")
    assert dk.duplicate_ids(dk_read(tmp_path))
    assert dk.main([str(tmp_path)]) == 1


def test_shared_xref_flagged_not_failed(tmp_path):
    _entry(tmp_path, "a.md", "AISEC-PROMPT-INJECTION-001", xref=("MCP03:2025",))
    _entry(tmp_path, "b.md", "AISEC-TOOL-POISONING-001", tclass="tool-poisoning", xref=("MCP03:2025",))
    flags = dk.merge_flags(dk_read(tmp_path))
    assert any("MCP03:2025" in f for f in flags)
    assert dk.main([str(tmp_path)]) == 0  # advisory only, no duplicate id


def test_distinct_entries_clean(tmp_path):
    _entry(tmp_path, "a.md", "AISEC-PROMPT-INJECTION-001", xref=("LLM01:2025",))
    _entry(tmp_path, "b.md", "AISEC-TOOL-POISONING-001", tclass="tool-poisoning", xref=("MCP03:2025",))
    assert dk.duplicate_ids(dk_read(tmp_path)) == []
    assert dk.merge_flags(dk_read(tmp_path)) == []
    assert dk.main([str(tmp_path)]) == 0


def test_title_similarity_flagged(tmp_path):
    _entry(tmp_path, "a.md", "AISEC-RAG-POISONING-001", tclass="rag-poisoning",
           title="RAG vector poisoning cross tenant leakage", xref=("LLM08:2025",))
    _entry(tmp_path, "b.md", "AISEC-RAG-POISONING-002", tclass="rag-poisoning",
           title="RAG vector poisoning cross tenant leakage variant", xref=("AML.T0070",))
    assert any("title" in f for f in dk.merge_flags(dk_read(tmp_path)))


def test_main_usage_error():
    assert dk.main([]) == 2


def dk_read(d):
    from _kb_entries import read_entries
    return read_entries(d)
