"""T-3.1 lock — keep tool-registry.md and detect_tools.py::SCANNER_PREFERENCE in sync.

The registry is the human-facing twin of the executable capability→tool map. If a capability is
added/renamed in the code but not the doc (or vice-versa), this fails — preventing drift.

Run: `uv run --with pytest pytest plugins/white-hacker/skills/_shared/scripts/tests/test_registry_lock.py`
"""
from __future__ import annotations

import pathlib
import re

import detect_tools as dt  # exposed via _shared conftest (sec-detect/scripts on path)

_REGISTRY = (
    pathlib.Path(__file__).resolve().parents[2] / "reference" / "tool-registry.md"
)

# Capability name in code -> the heading token that must appear in the registry.
_HEADING_TOKEN = {
    "sast": "sast",
    "sca": "sca",
    "secrets": "secret",
    "iac": "iac",
    "ai-redteam": "redteam",
}


def _registry_text() -> str:
    return _REGISTRY.read_text(encoding="utf-8").lower()


def test_every_code_capability_is_documented():
    text = _registry_text()
    missing = [cap for cap in dt.SCANNER_PREFERENCE
               if _HEADING_TOKEN.get(cap, cap) not in text]
    assert missing == [], f"capabilities in SCANNER_PREFERENCE missing from registry: {missing}"


def test_code_and_token_map_cover_the_same_capabilities():
    # guards against adding a capability to the code without teaching this lock about it
    assert set(dt.SCANNER_PREFERENCE) == set(_HEADING_TOKEN), (
        "SCANNER_PREFERENCE and the registry-lock token map disagree; update both"
    )


def test_registry_states_illustrative_and_pinning():
    text = _registry_text()
    assert "illustrative" in text
    assert "pin" in text
    # The Trivy-specific safe-version regex (`r"0\.7[01]"`) is RETIRED: ADR-027 §5
    # removes Trivy permanently, so the pin block that line guarded is deleted. The
    # neutral pinning-discipline assertion above (`"pin" in text`) is what remains.
    assert not re.search(r"0\.7[01]", text), (
        "the Trivy safe-version pin line must be gone (ADR-027 permanent removal)"
    )


def test_registry_references_the_executable_twin():
    assert "scanner_preference" in _registry_text()


# --- per-tool present/absent TDD (ADR-025 §5 / ADR-027 §5; Policy 9) -----------
# The capability-level lock above cannot catch a *tool* regression (a violator or
# Trivy re-added to a list, or an admitted tool dropped from the registry). These
# pin BOTH directions: the rejected set is ABSENT from every SCANNER_PREFERENCE
# list, and the admitted set is PRESENT (in the code map and/or the registry text).

# Tools that must NEVER appear in any SCANNER_PREFERENCE list:
#   - License-gate violators (ADR-025 §2): opengrep/semgrep (LGPL-2.1),
#     govulncheck (BSD-3), trufflehog (AGPL-3.0), hadolint (GPL-3.0).
#   - integrity/TeamPCP (ADR-027 §1): trivy — permanently removed, does not return.
_FORBIDDEN_IN_SCANNER_PREFERENCE: frozenset[str] = frozenset(
    {"trivy", "opengrep", "semgrep", "govulncheck", "trufflehog", "hadolint"}
)

# Admitted tools that MUST remain wired in SCANNER_PREFERENCE (per category).
# Grype/Syft are deliberately EXCLUDED here: they are image/SBOM tools the static
# filesystem default never auto-selects (ADR-007) — registry-listed, not in the map.
_REQUIRED_IN_SCANNER_PREFERENCE: dict[str, frozenset[str]] = {
    "sast": frozenset({"gosec", "bandit", "ruff", "eslint-plugin-security"}),
    "sca": frozenset({"pip-audit", "osv-scanner", "cargo-audit"}),
    "secrets": frozenset({"gitleaks", "detect-secrets"}),
    "iac": frozenset({"checkov", "actionlint", "zizmor"}),
    "ai-redteam": frozenset({"promptfoo", "garak"}),
}


def _all_pref_tools() -> set[str]:
    return {tool for prefs in dt.SCANNER_PREFERENCE.values() for tool, _ in prefs}


def test_no_forbidden_tool_in_scanner_preference():
    """Violators + Trivy are ABSENT from every SCANNER_PREFERENCE list (the != arm)."""
    present = _all_pref_tools()
    leaked = sorted(_FORBIDDEN_IN_SCANNER_PREFERENCE & present)
    assert leaked == [], (
        f"License-gate/TeamPCP-rejected tools must not be selectable: {leaked}"
    )


def test_trivy_absent_from_every_category():
    """Trivy specifically — permanent removal (ADR-027 §1), pinned per-category."""
    for category, prefs in dt.SCANNER_PREFERENCE.items():
        tools = {tool for tool, _ in prefs}
        assert "trivy" not in tools, f"trivy must not be in SCANNER_PREFERENCE[{category!r}]"


def test_sast_leads_with_per_language_linters_no_cross_language_engine():
    """SAST is per-language linters only — NO cross-language taint engine (AC7).

    Pins both directions: opengrep/semgrep ABSENT, the per-language linters PRESENT.
    Wiring a new cross-language engine here is the gated SAST-default flip (a named
    follow-up), explicitly NOT done in this ticket.
    """
    sast_tools = {tool for tool, _ in dt.SCANNER_PREFERENCE["sast"]}
    assert "opengrep" not in sast_tools
    assert "semgrep" not in sast_tools
    assert _REQUIRED_IN_SCANNER_PREFERENCE["sast"] <= sast_tools, (
        f"SAST must lead with per-language linters; have {sorted(sast_tools)}"
    )


def test_admitted_tools_present_per_category():
    """Each category keeps its admitted tools wired (the == arm)."""
    for category, required in _REQUIRED_IN_SCANNER_PREFERENCE.items():
        present = {tool for tool, _ in dt.SCANNER_PREFERENCE[category]}
        missing = sorted(required - present)
        assert missing == [], (
            f"SCANNER_PREFERENCE[{category!r}] missing admitted tools: {missing}"
        )


def test_grype_syft_not_auto_selected():
    """Grype/Syft are registry-listed but never in SCANNER_PREFERENCE (ADR-007).

    No surprise docker/image pull from the static filesystem default; they are
    selected only for explicit image/SBOM scope, not via this map.
    """
    pref_tools = _all_pref_tools()
    assert "grype" not in pref_tools
    assert "syft" not in pref_tools


def test_admitted_tools_documented_in_registry():
    """The admitted replacement tools appear by name in the registry text.

    Pairs the code-map assertions with the human-facing twin so a row deletion in
    the doc (without a code change) still fails the lock (== arm on the registry).
    """
    text = _registry_text()
    for tool in ("grype", "syft", "osv-scanner", "checkov", "gitleaks",
                 "detect-secrets", "cargo-audit", "kube-linter"):
        assert tool in text, f"admitted tool {tool!r} missing from registry text"


def test_registry_has_admissibility_columns_and_rejected_subsections():
    """ADR-025 columns + the TWO distinct Rejected subsections are present."""
    text = _registry_text()
    for col in ("license", "data_egress", "gdpr"):
        assert col in text, f"registry missing the {col!r} admissibility column"
    assert "rejected (license-gate)" in text
    assert "rejected (integrity/teampcp)" in text
