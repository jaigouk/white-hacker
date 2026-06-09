"""Deterministic vendor-lane scrubber (wh-7gh).

The vendor lane (`install.sh`) copies the white-hacker agent + the consumer/inner-loop skills into a
target project's `.claude/`. Those SOURCE files legitimately carry DEV-repo + OUTER-loop content — the
convention `## Verification criteria` definition-of-done blocks, `docs/research/spike-*` and ADR
citations that resolve *in the white-hacker repo*, and the agent's self-improvement section — none of
which resolves or applies in a target. This module removes that content **from the vendored copy
only**; the source tree is never touched (the dev repo keeps its outer loop and its conventions).

Determinism over a brittle prose regex (Policy 5): it strips whole markdown sections by their exact
`## ` header prefix and applies an explicit, drift-guarded replacement table — then `find_leaks()`
asserts that NO dev-repo token survives anywhere in the vendored tree. That leakage assertion is the
real guard: if a future source edit moves a reference, the assertion fails LOUD (Policy 12) instead
of silently shipping a leak. New leak found in CI? add a strip/replacement here; don't weaken the set.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# The consumer/inner-loop skills the vendor lane ships (must match install.sh's manifest).
CONSUMER_SKILLS = (
    "_shared", "ai-attack-kb", "ai-llm-review", "deps-scan", "sec-detect", "sec-init",
    "sec-patch", "sec-policy", "sec-report", "sec-threat-model", "sec-triage",
    "sec-vuln-scan", "secrets-scan",
)

# (relpath under .claude/, '## ' header PREFIX) — drop the header line .. next top-level '## ' or EOF.
# Header prefix-match tolerates suffix drift (e.g. "## Verification criteria (definition of done…)").
SECTION_STRIPS = [
    ("agents/white-hacker.md", "## Self-improvement (the outer loop)"),
    ("skills/ai-attack-kb/SKILL.md", "## Lifecycle (outer loop)"),
    ("skills/deps-scan/reference/MALWARE-DB.md", "## Pinned snapshot — recorded (this project, wh-8qw)"),
    ("skills/sec-init/SKILL.md", "## Gating (Phase-9 keep-or-revert + size caps)"),
    ("skills/sec-report/SKILL.md", "## Logged evidence"),
]
# Every shipped skill's author-facing definition-of-done block (dev metadata; dangling in a target).
SECTION_STRIPS += [(f"skills/{s}/SKILL.md", "## Verification criteria") for s in CONSUMER_SKILLS]

# (relpath, exact old substring, replacement) — surgical inline neuters of dev-repo pointers.
REPLACEMENTS = [
    ("agents/white-hacker.md",
     "> Built on two foundations (see `docs/ARCHITECTURE.md`, `docs/ARD.md` ADR-001):",
     "> Built on two foundations:"),
    ("agents/white-hacker.md",
     "Skills live under `skills/` (plugin-relative; resolved at runtime as `${CLAUDE_PLUGIN_ROOT}/skills/`).",
     "Skills live alongside this agent under `.claude/skills/`."),
    ("agents/white-hacker.md",
     "or user already has, and propose adding genuinely useful unknown tools via `/sec-learn`.",
     "or user already has."),
    ("agents/white-hacker.md",
     "Findings flow to a beads P1 ticket only **after** triage —",
     "Findings flow to a tracked P1 issue only **after** triage —"),
    ("skills/sec-init/SKILL.md",
     "[spike-07](../../../../docs/research/spike-07-agent-distribution-and-init-2026-06.md) F4).",
     "the agent-distribution design)."),
    ("skills/sec-policy/SKILL.md",
     "(ADR-018; resolves [spike-08](../../../../docs/research/spike-08-security-md-policy-2026-06.md)).",
     "(per the SECURITY.md policy design)."),
    ("skills/_shared/reference/tool-registry.md",
     "New/unknown tools are added here by `/sec-learn` and `/sec-kb-refresh`",
     "New/unknown tools are added here over time"),
    ("skills/_shared/reference/tool-registry.md",
     "- 2026-06-06 · seed · initial registry from research (`docs/research/fnd-tool-matrix.md`).",
     "- 2026-06-06 · seed · initial registry from research."),
    ("skills/_shared/reference/lang-java.md",
     "> (`docs/research/spike-04-phase2-cve-currency.md`).",
     "> (from phase-2 CVE-currency research)."),
    ("skills/_shared/reference/lang-typescript.md",
     "> (`docs/research/spike-04-phase2-cve-currency.md`) — they are evidence, the pattern is the lesson.",
     "> They are evidence, the pattern is the lesson."),
    ("skills/ai-attack-kb/SKILL.md",
     "layout reconcile and `docs/plan/phase-4-ai-llm-api.md`.",
     "layout reconcile."),
    ("skills/deps-scan/SKILL.md",
     "The allowlist lives in `reference/` so `/sec-kb-refresh`",
     "The allowlist lives in `reference/` so the KB-refresh process"),
    ("skills/deps-scan/SKILL.md",
     "'../../../../../docs/research/poc-supply-chain'",
     "'<project-dir>'"),
    ("skills/deps-scan/reference/MALWARE-DB.md",
     "Re-pin to a newer reviewed SHA on the project's KB-refresh cadence (`/sec-kb-refresh`). A",
     "Re-pin to a newer reviewed SHA on the project's KB-refresh cadence. A"),
    ("skills/sec-detect/SKILL.md",
     "See `docs/ARCHITECTURE.md` and `.claude/agents/white-hacker.md`.",
     "See `.claude/agents/white-hacker.md`."),
    ("skills/sec-threat-model/SKILL.md",
     "See `docs/ARCHITECTURE.md` and `.claude/agents/white-hacker.md`.",
     "See `.claude/agents/white-hacker.md`."),
]

# Producer-only files pruned from a shipped consumer skill (manifest excludes whole skills, not files).
DROP_FILES = [
    "skills/ai-attack-kb/scripts/precommit_safety.py",
    "skills/ai-attack-kb/scripts/tests/test_precommit_safety.py",
]

# Dev-repo tokens that must NOT survive into a vendored target (the leakage guard). Specific on
# purpose — bare `(ADR-015)` provenance is tolerated inert; these are paths/commands/infra that
# dangle or instruct an impossible action in a target.
FORBIDDEN_TOKENS = (
    # dangling dev-repo PATHS (a path-bearing spike/si link is caught here too)
    "docs/research", "docs/ARD", "docs/ARCHITECTURE.md", "docs/plan", "docs/qa",
    "${CLAUDE_PLUGIN_ROOT}",
    # actionable OUTER-loop commands a target cannot run
    "/sec-learn", "/sec-kb-refresh",
    # dev-only eval/issue infrastructure
    "keep_or_revert", "baseline.json", "evals/", ".beads",
)
# NOT forbidden: bare citation provenance (`(ADR-015)`, `(spike-09 §F2)`, `(si-08 §7)`) — harmless
# attribution with no dangling path or action, tolerated inert (a path-bearing form is caught above).
# Scan the AGENT-FACING surface only: the agent reads SKILL.md + reference/*.md, never the skills'
# Python. `.py`/`.json` carry developer PROVENANCE (e.g. `# spike-09 §F2`, `"_source": …`) — code
# archaeology that neither breaks a target nor instructs the agent (rewriting working code comments
# would be brittle, Policy 5, and non-surgical, Policy 3). The one runtime hazard in code — a test
# that drives an absent dev fixture — is handled by skip-guards in the tests themselves (wh-7gh,
# wh-8lx), not here. This scope is deliberate and stated (ADR-021), not a silent omission.
_SCAN_SUFFIXES = (".md",)


def strip_section(text: str, header_prefix: str) -> tuple[str, bool]:
    """Remove a markdown section: the line starting with `header_prefix` through (not including) the
    next top-level `## ` heading, or EOF. `### ` subheadings inside the section are removed too."""
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    i, n, removed = 0, len(lines), False
    while i < n:
        if lines[i].startswith(header_prefix):
            removed = True
            i += 1
            while i < n and not lines[i].startswith("## "):
                i += 1
        else:
            out.append(lines[i])
            i += 1
    return "".join(out), removed


def scrub(dst: Path) -> dict:
    """Scrub a vendored `.claude/` tree in place. Returns a report; raises nothing (the installer
    decides what to do with remaining leaks)."""
    dst = Path(dst)
    report = {"sections_stripped": [], "replacements_applied": [], "files_dropped": [],
              "missing": [], "leaks": []}

    for relpath, header in SECTION_STRIPS:
        f = dst / relpath
        if not f.exists():
            report["missing"].append(f"section:{relpath}:{header}")
            continue
        new, removed = strip_section(f.read_text(), header)
        if removed:
            f.write_text(new)
            report["sections_stripped"].append(f"{relpath} :: {header}")

    for relpath, old, new in REPLACEMENTS:
        f = dst / relpath
        if not f.exists():
            report["missing"].append(f"replace:{relpath}")
            continue
        text = f.read_text()
        if old in text:
            f.write_text(text.replace(old, new))
            report["replacements_applied"].append(f"{relpath} :: {old[:48]}…")
        else:
            report["missing"].append(f"replace-nomatch:{relpath}:{old[:48]}…")

    for relpath in DROP_FILES:
        f = dst / relpath
        if f.exists():
            f.unlink()
            report["files_dropped"].append(relpath)

    report["leaks"] = find_leaks(dst)
    return report


def find_leaks(root: Path) -> list[dict]:
    """Scan a vendored tree for surviving dev-repo tokens. Returns a list of {file,line,token,text}."""
    root = Path(root)
    leaks: list[dict] = []
    for f in sorted(root.rglob("*")):
        if not f.is_file() or f.suffix not in _SCAN_SUFFIXES:
            continue
        if any(part in (".venv", "__pycache__", ".pytest_cache") for part in f.parts):
            continue
        try:
            lines = f.read_text().splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in enumerate(lines, 1):
            for tok in FORBIDDEN_TOKENS:
                if tok in line:
                    leaks.append({"file": str(f.relative_to(root)), "line": n,
                                  "token": tok, "text": line.strip()[:120]})
    return leaks


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="scrub_vendored.py",
                                 description="Scrub dev/outer-loop content from a vendored .claude/ tree.")
    ap.add_argument("dst", help="path to the vendored .claude/ directory")
    ap.add_argument("--check", action="store_true", help="only report leaks (no scrub); exit 1 if any")
    ns = ap.parse_args(sys.argv[1:] if argv is None else argv)
    dst = Path(ns.dst)
    if not dst.is_dir():
        print(f"error: not a directory: {dst}", file=sys.stderr)
        return 2
    if ns.check:
        leaks = find_leaks(dst)
        for lk in leaks:
            print(f"LEAK {lk['file']}:{lk['line']} [{lk['token']}] {lk['text']}", file=sys.stderr)
        print(f"{len(leaks)} leak(s)")
        return 1 if leaks else 0
    report = scrub(dst)
    print(f"scrubbed: {len(report['sections_stripped'])} sections, "
          f"{len(report['replacements_applied'])} replacements, {len(report['files_dropped'])} files dropped")
    if report["leaks"]:
        for lk in report["leaks"]:
            print(f"LEAK {lk['file']}:{lk['line']} [{lk['token']}] {lk['text']}", file=sys.stderr)
        print(f"error: {len(report['leaks'])} dev-repo leak(s) survived the scrub", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
