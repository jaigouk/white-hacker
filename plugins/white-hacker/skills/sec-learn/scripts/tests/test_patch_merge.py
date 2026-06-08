"""Tests for the section-keyed Markdown patch-merge (wh-0aq, si-10 borrowing #1, TDD).

Deterministic, stdlib-only, append-only: a patch section whose level-2 `##` heading matches a
base section REPLACES it; an unmatched patch section is APPENDED; base preamble is preserved.
Rule 9 — every invariant pins BOTH `==`/`in` (the right value) AND `not in` (the wrong value).

Run: uv run --project plugins/white-hacker/skills/sec-learn/scripts pytest \
        plugins/white-hacker/skills/sec-learn/scripts/tests/test_patch_merge.py -q
"""
from __future__ import annotations

from patch_merge import merge_markdown_patch


def test_matching_heading_replaces_section():
    base = "## Alpha\nold alpha body\n\n## Beta\nbeta body\n"
    patch = "## Alpha\nnew alpha body\n"
    out = merge_markdown_patch(base, patch)
    # The new body is present...
    assert "new alpha body" in out
    # ...and the OLD body is gone (replace, not append).
    assert "old alpha body" not in out
    # The untouched section survives unchanged.
    assert "beta body" in out
    # Exactly one Alpha heading (replaced, not duplicated).
    assert out.count("## Alpha") == 1


def test_unmatched_heading_is_appended_order_preserved():
    base = "## Alpha\nalpha body\n\n## Beta\nbeta body\n"
    patch = "## Gamma\ngamma body\n"
    out = merge_markdown_patch(base, patch)
    # Both base sections remain AND the new one is present (append-only).
    assert "alpha body" in out
    assert "beta body" in out
    assert "gamma body" in out
    # Appended AFTER the base (order preserved), not prepended.
    assert out.index("gamma body") > out.index("beta body")
    # Nothing was dropped.
    assert "## Gamma" in out and "## Alpha" in out and "## Beta" in out


def test_base_preamble_is_preserved():
    base = "preamble line before any heading\n\n## Alpha\nalpha body\n"
    patch = "## Alpha\nnew alpha\n"
    out = merge_markdown_patch(base, patch)
    # Preamble survives the merge...
    assert "preamble line before any heading" in out
    # ...and it stays at the top, ahead of the section.
    assert out.index("preamble line before any heading") < out.index("## Alpha")
    # Replace still happened.
    assert "new alpha" in out and "alpha body" not in out


def test_mixed_replace_and_append():
    base = "## Alpha\nold a\n\n## Beta\nold b\n"
    patch = "## Beta\nnew b\n\n## Delta\nnew d\n"
    out = merge_markdown_patch(base, patch)
    # Beta replaced in place; Alpha untouched; Delta appended.
    assert "new b" in out and "old b" not in out
    assert "old a" in out
    assert "new d" in out
    # Replaced section keeps its original position (before the appended Delta).
    assert out.index("new b") < out.index("new d")
    assert out.count("## Beta") == 1


def test_empty_patch_returns_base_content():
    base = "## Alpha\nalpha body\n"
    out = merge_markdown_patch(base, "")
    assert "alpha body" in out
    # No spurious heading introduced.
    assert out.count("## Alpha") == 1
