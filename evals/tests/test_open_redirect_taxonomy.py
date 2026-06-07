"""TDD (T-12.2): open-redirect is its OWN category, not AuthN/AuthZ.

The QA-8 baseline showed the agent *finds* every open-redirect case but categorizes it differently
from the corpus's `AuthN/AuthZ` label (it's CWE-601, not access control). This pins the corrected
taxonomy: the corpus labels them `open-redirect`, and the category is documented.

Run: uv run --project evals --with pytest pytest evals/tests/test_open_redirect_taxonomy.py
"""
from __future__ import annotations

import json
import pathlib

_HERE = pathlib.Path(__file__).resolve()
REPO = next(c for c in (_HERE, *_HERE.parents) if (c / ".git").exists())
CASES = REPO / "evals" / "corpus" / "cases"
CHECKLIST = REPO / "plugins/white-hacker/skills/_shared/reference/core-checklist.md"
EXCLUSIONS = REPO / "plugins/white-hacker/skills/_shared/reference/exclusion-rules.md"


def test_open_redirect_cases_use_open_redirect_category():
    cases = sorted(CASES.glob("*open-redirect*/label.json"))
    assert cases, "expected open-redirect corpus cases"
    bad = [(lp.parent.name, json.loads(lp.read_text())["category"])
           for lp in cases if json.loads(lp.read_text())["category"] != "open-redirect"]
    assert not bad, f"open-redirect cases must use category 'open-redirect', got: {bad}"


def test_open_redirect_is_a_documented_category():
    assert "`open-redirect`" in CHECKLIST.read_text(), \
        "core-checklist.md must list the `open-redirect` category tag"


def test_ssrf_allowlist_guard_is_excluded():
    """The allow-list-before-fetch SSRF mitigation must be a recognized non-finding (rule 20)."""
    t = EXCLUSIONS.read_text().lower()
    assert "allow-list-guarded ssrf" in t or "allowlist" in t and "ssrf" in t, \
        "exclusion-rules.md must document the allow-list-guarded SSRF non-finding"


def test_mcp_tokenpassthrough_relabeled_to_data_exfil():
    """py-mcp-tokenpassthrough was mislabeled `tool-poisoning` (a distinct MCP class per ai-llm §4);
    it is token-passthrough → relabeled to `data-exfil` (the agent's defensible impact category)."""
    lab = json.loads((CASES / "py-mcp-tokenpassthrough" / "label.json").read_text())
    assert lab["category"] == "data-exfil", f"expected data-exfil, got {lab['category']}"


def test_hardcoded_secret_categorized_as_crypto():
    """Hardcoded secrets are a `crypto`/secrets failure, not `config` — the checklist must say so."""
    t = CHECKLIST.read_text()
    assert "Hardcoded credentials" in t and "`crypto`" in t, \
        "core-checklist §4 must categorize hardcoded secrets as `crypto`"

