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
    assert re.search(r"0\.7[01]", text), "registry must carry the safe Trivy version line"


def test_registry_references_the_executable_twin():
    assert "scanner_preference" in _registry_text()
