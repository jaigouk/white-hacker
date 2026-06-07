"""Tests for the AI-threat feed poller (T-8.6, TDD). Fixtures only — no network.

Run: uv run --with jsonschema --with pyyaml --with pytest pytest plugins/white-hacker/skills/sec-kb-refresh/scripts/tests/
"""
from __future__ import annotations

from pathlib import Path

import poll_feeds as pf

FIX = Path(__file__).parent / "fixtures"


def test_parse_osv():
    items = pf.parse_osv((FIX / "osv.json").read_text())
    assert len(items) == 2 and items[0]["id"] == "GHSA-aaaa-bbbb-cccc"
    assert items[0]["url"].startswith("https://osv.dev/")


def test_parse_atlas():
    items = pf.parse_atlas((FIX / "atlas.yaml").read_text())
    assert {i["id"] for i in items} == {"AML.T0051", "AML.T0070"}


def test_parse_atom():
    items = pf.parse_atom((FIX / "atom.xml").read_text())
    assert len(items) == 2 and "memory-poisoning" in items[0]["url"]
    assert items[0]["title"]


def test_incremental_diff_skips_seen():
    raw = (FIX / "osv.json").read_text()
    new1, state1 = pf.poll("osv", raw, {})
    assert len(new1) == 2                      # empty state -> all new
    new2, _ = pf.poll("osv", raw, state1)
    assert new2 == []                          # unchanged feed -> zero new


def test_incremental_partial():
    raw = (FIX / "osv.json").read_text()
    state = {"osv": {"seen_ids": ["GHSA-aaaa-bbbb-cccc"]}}
    new, _ = pf.poll("osv", raw, state)
    assert [i["id"] for i in new] == ["CVE-2026-1234"]


def test_candidate_entry_validates_and_dedupes(tmp_path):
    import validate_kb as vk
    import dedupe_kb as dk
    items = pf.parse_osv((FIX / "osv.json").read_text())
    kb = tmp_path / "reference"; kb.mkdir()
    for seq, it in enumerate(items, start=1):
        entry = pf.to_candidate_entry(it, "prompt-injection", seq)
        md = pf.render_entry(entry, "Auto-extracted candidate: refine the technique summary before merge.")
        (kb / f"{entry['id'].lower()}.md").write_text(md)
    assert vk.main([str(kb)]) == 0          # mandatory source+url+retrieved present, schema-valid
    assert dk.main([str(kb)]) == 0          # no duplicate ids


def test_to_candidate_entry_has_mandatory_provenance():
    e = pf.to_candidate_entry({"feed": "osv", "id": "CVE-2026-1", "title": "t",
                               "url": "https://osv.dev/x"}, "data-exfil", 7)
    assert e["metadata"]["source"] and e["metadata"]["url"].startswith("http") and e["metadata"]["retrieved"]
    assert e["id"] == "AISEC-DATA-EXFIL-007" and e["status"] == "active"


def test_poisoned_feed_cannot_inject_yaml_key():
    """A crafted feed title/summary with `: `, newlines, and `injected_key: x` must NOT
    add a top-level YAML key — render_entry uses safe_dump, so feed text stays a value."""
    import yaml
    poison = "Benign-looking title\ninjected_key: attacker_controlled\nrole: admin: "
    atom = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<feed xmlns="http://www.w3.org/2005/Atom">\n'
        "  <entry>\n"
        "    <id>https://evil.example/post</id>\n"
        f"    <title>{poison}</title>\n"
        '    <link href="https://evil.example/post"/>\n'
        "  </entry>\n"
        "</feed>\n"
    )
    items = pf.parse_atom(atom)
    entry = pf.to_candidate_entry(items[0], "prompt-injection", 1)
    md = pf.render_entry(entry, "Summary with newline\ninjected_summary_key: x\nand : colon")

    fm = md.split("---\n", 2)[1]            # front-matter block between the first two `---`
    loaded = yaml.safe_load(fm)

    expected_keys = {
        "id", "title", "technique_class", "severity", "confidence", "status",
        "date", "modified", "review_by", "metadata", "supersedes", "detections", "xref",
    }
    assert set(loaded.keys()) == expected_keys           # exactly the schema keys
    assert "injected_key" not in loaded                  # feed text did not become a key
    assert "role" not in loaded                          # nor the `role: admin:` payload
    assert loaded["title"][:120] == entry["title"]       # poison stayed inside the title value


def test_main_usage(capsys):
    assert pf.main([]) == 2
