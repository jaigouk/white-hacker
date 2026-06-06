"""Pre-commit safety checklist — the 10 mandatory gates for any outer-loop self-write (T-9.4).

si-08 §5.2: a self-write (sec-learn / sec-kb-refresh proposal) may proceed only if ALL pass:
  1 schema_caps          — lint_skill + validate_kb pass
  2 references_one_level  — reference/ is one level deep
  3 source_linked         — KB entry carries source+url+retrieved
  4 dedup_passed          — no duplicate ids
  5 identity_preserved    — NO edit to the agent role / .claude/rules/ / CLAUDE.md (NON-NEGOTIABLE)
  6 confined              — every write is within the self-improvement lane
  7 self_critique         — the self-critique pass succeeded
  8 promotion_eligible    — the change was seen in >= 3 sessions
  9 regression_gate       — keep_or_revert verdict == KEEP
 10 feature_branch        — it is a PR on a feature branch (not default, not an autocommit)

On any failure: DO NOT WRITE; append the rejection to `evals/rejected.md` so the loop never
re-proposes a known loser. This script is itself read-only to the agent (confinement).
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

_IDENTITY_RE = re.compile(r"(^|/)CLAUDE\.md$|(^|/)\.claude/rules/|(^|/)\.claude/agents/")
_FROZEN_BASENAMES = {"keep_or_revert.py", "baseline.json", "score.py", "label-schema.json"}
_ALLOW_SEGMENTS = ("/ai-attack-kb/", "/_shared/reference/", "/PATCHES/", "/evals/traces/")


def _confined(path: str, root: str = ".") -> bool:
    t = path if os.path.isabs(path) else os.path.join(root, path)
    rel = os.path.relpath(os.path.realpath(t), os.path.realpath(root)).replace(os.sep, "/")
    if rel.startswith("../") or rel == "..":
        return "/memory/" in os.path.realpath(t).replace(os.sep, "/")
    norm = "/" + rel
    if rel.startswith("evals/corpus/") or os.path.basename(rel) in _FROZEN_BASENAMES:
        return False
    if rel.startswith(".claude/settings"):
        return False
    return any(seg in norm for seg in _ALLOW_SEGMENTS)


def check(change: dict) -> list[tuple[str, bool, str]]:
    paths = change.get("paths", [])
    root = change.get("cwd", ".")
    return [
        ("schema_caps", bool(change.get("lint_passed")) and bool(change.get("validate_passed")),
         "lint_skill + validate_kb must pass"),
        ("references_one_level", bool(change.get("references_one_level", True)),
         "reference/ must be one level deep"),
        ("source_linked", bool(change.get("sourced")),
         "KB entry must carry source+url+retrieved"),
        ("dedup_passed", bool(change.get("dedup_passed")), "no duplicate ids"),
        ("identity_preserved", bool(paths) and not any(_IDENTITY_RE.search(p) for p in paths),
         "NON-NEGOTIABLE: no edit to agent role / .claude/rules/ / CLAUDE.md"),
        ("confined", bool(paths) and all(_confined(p, root) for p in paths),
         "every write must be within the self-improvement lane"),
        ("self_critique", bool(change.get("self_critique_passed")), "self-critique must pass"),
        ("promotion_eligible", int(change.get("seen_sessions", 0)) >= 3, "seen in >= 3 sessions"),
        ("regression_gate", change.get("gate_verdict") == "KEEP", "keep_or_revert verdict must be KEEP"),
        ("feature_branch",
         change.get("branch", "") not in ("main", "master", "") and not change.get("autocommit", False),
         "must be a PR on a feature branch (not default, no autocommit)"),
    ]


def failures(change: dict) -> list[tuple[str, str]]:
    return [(g, reason) for g, ok, reason in check(change) if not ok]


def passed(change: dict) -> bool:
    return not failures(change)


def enforce(change: dict, rejected_path: Path) -> bool:
    fails = failures(change)
    if fails:
        cid = change.get("id", "<unknown>")
        line = f"- {cid}: BLOCKED — " + "; ".join(f"{g} ({r})" for g, r in fails)
        with Path(rejected_path).open("a") as fh:
            fh.write(line + "\n")
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: precommit_safety.py <change.json> [--rejected evals/rejected.md]")
        return 2
    change = json.loads(Path(argv[0]).read_text())
    rejected = argv[argv.index("--rejected") + 1] if "--rejected" in argv else "evals/rejected.md"
    ok = enforce(change, Path(rejected))
    for g, passed_, reason in check(change):
        print(f"  [{'x' if passed_ else ' '}] {g} — {reason}")
    print("PASS" if ok else "BLOCKED")
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
