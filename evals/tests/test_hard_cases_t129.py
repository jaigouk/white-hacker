"""TDD (T-12.9): the harder corpus cases that restore eval discriminating headroom.

The 103-case corpus saturated at J=1.0 (recall ~100%; every Wave-B/C gain was a category-name
correction). A saturated eval can catch REGRESSIONS but can no longer *measure improvement*.
These `hard-*` cases are deliberately discriminating — bypassable mitigations (blocklist SSRF,
single-pass path sanitizer, tag-stripping XSS), cross-function taint (IDOR, second-order SQLi,
chained LLM05), and an alg-confusion JWT — so a competent reviewer must reason, not pattern-match.

Two invariants this pins (rule #9 — pin intent, not just structure):
  1. Each labeled vulnerable line actually sits on the intended sink (labels can't silently drift).
  2. Neutralization-safety: the code files leak NO answer markers, so a fair (filename-shuffled)
     run cannot cheat — the difficulty is real, not telegraphed.

Run: uv run --project evals --with pytest pytest evals/tests/test_hard_cases_t129.py
"""
from __future__ import annotations

import json
import pathlib

_HERE = pathlib.Path(__file__).resolve()
REPO = next(c for c in (_HERE, *_HERE.parents) if (c / ".git").exists())
CASES = REPO / "evals" / "corpus" / "cases"

# Known scorer categories (must match core-checklist.md tags + the AI LLM05 tag).
KNOWN_CATEGORIES = {
    "injection", "AuthN/AuthZ", "ssrf", "open-redirect", "crypto", "deserialization",
    "xss", "config", "supply-chain", "error", "data-exposure", "resource",
    "improper-output-handling", "data-exfil", "rag-poisoning", "prompt-injection",
    "excessive-agency", "tool-poisoning",
}

# Intent map: cid -> a substring that MUST appear on the labeled vulnerable line. This is what
# makes the case "this specific sink", so an edit that moves the bug fails the test loudly.
EXPECTED_SINK = {
    "hard-ssrf-blocklist-bypass": "requests.get",
    "hard-idor-cross-function": "to_dict()",
    "hard-pathtrav-partial-sanitizer": "os.path.join(BASE, safe)",
    "hard-sqli-second-order": "ORDER BY {col}",
    "hard-llm05-chained-exec": "subprocess.run",
    "hard-jwt-alg-confusion": 'algorithms=["RS256", "HS256"]',
    "hard-xss-incomplete-sanitizer": "{clean}",
    # subtle FN/FP-boundary batch (surface matches the checklist template; the defect/safety is in the detail)
    "hard-ssrf-allowlist-suffix-bypass": "requests.get(url, timeout=5)",
    "hard-authz-missing-ownership": "return doc.body",
    "hard-cmdi-vs-hardcoded-argv": 'subprocess.run(f"ping',
    "hard-deser-yaml-load": "yaml.load(data)",
    "hard-sqli-vs-constant-interp": "status='{status}'",
}

# Case-insensitive markers that would telegraph the answer to a reviewing agent.
LEAK_MARKERS = ("sink", "vuln", "exploit", "insecure", "unsafe", "attack",
                "cwe-", "todo", "fixme", "# bad", "injection", "backdoor")


def _hard_dirs() -> list[pathlib.Path]:
    return sorted(d for d in CASES.glob("hard-*") if (d / "label.json").exists())


def test_hard_cases_present():
    dirs = _hard_dirs()
    assert len(dirs) >= 7, f"expected >= 7 hard-* cases, found {len(dirs)}"
    # Every intent-mapped case exists, and vice-versa (no orphan map entries).
    assert {d.name for d in dirs} >= set(EXPECTED_SINK), \
        f"intent map references missing cases: {set(EXPECTED_SINK) - {d.name for d in dirs}}"


def test_each_hard_case_well_formed():
    for d in _hard_dirs():
        lab = json.loads((d / "label.json").read_text())
        assert lab["case_id"] == d.name
        assert lab["difficulty"] == "hard", f"{d.name}: must be tagged difficulty=hard"
        assert lab["category"] in KNOWN_CATEGORIES, f"{d.name}: unknown category {lab['category']}"
        assert (d / "vulnerable_variant.py").exists() and (d / "benign_lookalike.py").exists()
        assert (d / "target.md").exists()
        # benign label points at a real, distinct file
        assert lab["benign_lookalike"]["file"] == "benign_lookalike.py"


def test_labeled_line_sits_on_intended_sink():
    """Pin intent: the labeled line must contain the expected sink token (within +/-0 — exact)."""
    for d in _hard_dirs():
        lab = json.loads((d / "label.json").read_text())
        token = EXPECTED_SINK.get(d.name)
        if token is None:
            continue
        lines = (d / "vulnerable_variant.py").read_text().splitlines()
        ln = lab["vulnerable"]["line"]
        assert 1 <= ln <= len(lines), f"{d.name}: line {ln} out of range (1..{len(lines)})"
        assert token in lines[ln - 1], \
            f"{d.name}: labeled line {ln} ({lines[ln-1]!r}) does not contain sink {token!r}"


def test_no_answer_leaking_markers():
    """Neutralization-safety: a filename-shuffled run must not be cheatable via in-file hints.
    The vulnerable AND benign files must carry none of the leak markers (case-insensitive)."""
    for d in _hard_dirs():
        for fn in ("vulnerable_variant.py", "benign_lookalike.py"):
            text = (d / fn).read_text().lower()
            hit = [m for m in LEAK_MARKERS if m in text]
            assert not hit, f"{d.name}/{fn} leaks answer marker(s): {hit}"


def test_hard_cases_broaden_underrepresented_categories():
    """The pre-T-12.9 corpus had only 3 AuthN/AuthZ cases; hard-* must add to that thin class."""
    authz = [d for d in _hard_dirs()
             if json.loads((d / "label.json").read_text())["category"] == "AuthN/AuthZ"]
    assert len(authz) >= 2, "expected >= 2 hard AuthN/AuthZ cases (the most under-tested class)"
