"""Deterministic eval scorer (T-7.2): findings vs. corpus labels -> TPR / FPR / Youden's J.

This does NOT run the review pipeline (that is the agent, non-deterministic). It compares a
finding-schema **findings JSON** against the corpus **labels** and returns a single deterministic
number per run (Youden's J = TPR - FPR; the OWASP Benchmark convention, si-08 §6.2), plus a
per-category breakdown.

Matching (no exact-line brittleness): a finding matches a label's vulnerable variant when the
file matches (suffix/basename) AND the category matches AND |line - expected| <= tolerance
(default 3). A label's benign look-alike must produce NO finding (the false-positive term):
one finding on the benign file = one FP for that case; otherwise a true negative.

CLI:
    uv run python score.py --findings FINDINGS.json (--labels LABELS.json | --corpus DIR) [--tol 3]
Prints {tpr, fpr, youden_j, tp, fn, fp, tn, by_category} as JSON.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _file_match(finding_file: str, label_file: str) -> bool:
    # Suffix match on case-qualified paths (load_labels qualifies labels with the case id, so
    # shared basenames like `benign_lookalike.js` do NOT collide across cases). A bare-basename
    # finding still matches via the second endswith branch.
    if not finding_file or not label_file:
        return False
    if finding_file == label_file:
        return True
    return finding_file.endswith("/" + label_file) or label_file.endswith("/" + finding_file)


def _rates(tp: int, fn: int, fp: int, tn: int) -> dict:
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"tpr": tpr, "fpr": fpr, "youden_j": tpr - fpr, "tp": tp, "fn": fn, "fp": fp, "tn": tn}


# wh-71r — DOCUMENTED, AUDITED category equivalences for the OPT-IN lenient scorer. Each frozenset is
# a pair of categories that are BOTH defensible labels for the SAME flaw, so a finding that pinpoints
# the vuln at the right line but picks the sibling class should not read as a miss. Symmetric.
# OPT-IN ONLY (score(..., lenient=True) / `--lenient`); the STRICT default is the gate metric and is
# never silently widened — silent widening is exactly what inflated the prior baseline (see
# docs/qa/20260609/opus-rebaseline-report.md). NOTE: improper-output-handling↔ssrf (py-llm05-ssrf) is
# deliberately NOT aliased — that equivalence is too broad to apply safely to all 18 ssrf cases.
CATEGORY_ALIASES = (
    frozenset({"crypto", "config"}),                              # hardcoded secret: a crypto/secrets AND a config flaw
    frozenset({"AuthN/AuthZ", "crypto"}),                         # JWT alg-confusion/none: a crypto flaw that bypasses authz
    frozenset({"prompt-injection", "rag-poisoning"}),            # LLM01/LLM08: untrusted content entering the model context
    frozenset({"improper-output-handling", "excessive-agency"}), # LLM05/LLM06: unsafe LLM output that drives an action
)


def _cat_match(found: str, label: str, lenient: bool) -> bool:
    """Strict: categories must be equal. Lenient: equal OR in the same documented alias group."""
    if found == label:
        return True
    return lenient and any({found, label} <= g for g in CATEGORY_ALIASES)


def score(findings_doc: dict, labels: list[dict], tol: int = 3, lenient: bool = False) -> dict:
    findings = findings_doc.get("findings", [])
    tp = fn = fp = tn = 0
    cats: dict[str, dict] = {}

    def bump(cat: str, key: str) -> None:
        cats.setdefault(cat, {"tp": 0, "fn": 0, "fp": 0, "tn": 0})[key] += 1

    for lab in labels:
        cat = lab["category"]
        vf, vl = lab["vulnerable"]["file"], lab["vulnerable"]["line"]
        hit = any(
            _file_match(f.get("file", ""), vf)
            and _cat_match(f.get("category", ""), cat, lenient)
            and abs(f.get("line", -999) - vl) <= tol
            for f in findings
        )
        if hit:
            tp += 1; bump(cat, "tp")
        else:
            fn += 1; bump(cat, "fn")

        bf = lab["benign_lookalike"]["file"]
        fp_hit = any(_file_match(f.get("file", ""), bf) for f in findings)
        if fp_hit:
            fp += 1; bump(cat, "fp")
        else:
            tn += 1; bump(cat, "tn")

    result = _rates(tp, fn, fp, tn)
    result["by_category"] = {c: _rates(**v) for c, v in sorted(cats.items())}
    return result


def load_labels(labels_path: str | None, corpus_dir: str | None) -> list[dict]:
    if labels_path:
        data = json.loads(Path(labels_path).read_text())
        return data if isinstance(data, list) else data.get("labels", [])
    labels: list[dict] = []
    for lp in sorted(Path(corpus_dir).glob("*/label.json")):
        lab = json.loads(lp.read_text())
        cid = lp.parent.name
        # Qualify file paths with the case id so identical basenames (benign_lookalike.js, ...)
        # cannot cross-match between cases. Findings from a real run reference the full path,
        # which ends with `<case_id>/<file>`, so suffix matching stays unique.
        lab = {
            **lab,
            "vulnerable": {**lab["vulnerable"], "file": f"{cid}/{lab['vulnerable']['file']}"},
            "benign_lookalike": {**lab["benign_lookalike"], "file": f"{cid}/{lab['benign_lookalike']['file']}"},
        }
        labels.append(lab)
    return labels


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="score.py")
    parser.add_argument("--findings", required=True)
    parser.add_argument("--labels")
    parser.add_argument("--corpus")
    parser.add_argument("--tol", type=int, default=3)
    parser.add_argument("--lenient", action="store_true",
                        help="credit DOCUMENTED defensible category equivalences (CATEGORY_ALIASES); off by default")
    try:
        ns = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit:
        return 2
    if not (ns.labels or ns.corpus):
        print("error: one of --labels / --corpus is required")
        return 2
    findings_doc = json.loads(Path(ns.findings).read_text())
    labels = load_labels(ns.labels, ns.corpus)
    print(json.dumps(score(findings_doc, labels, ns.tol, ns.lenient), indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
