"""Second ratchet (T-9.5): promote a confirmed true finding into the FROZEN corpus as a locked case.

Run by the HUMAN / CI identity ONLY — the agent is write-blocked from `evals/corpus/**` (T-8.4), so
it cannot promote its own findings (no grading-its-own-exam). Adds the four case files
(target.md / vulnerable_variant.* / benign_lookalike.* / label.json) and appends the id to LOCKED,
so the bar keeps rising as new true positives are confirmed.

CLI:
    uv run python promote_finding.py <spec.json> [--corpus evals/corpus]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def promote(corpus_dir, spec: dict) -> Path:
    corpus_dir = Path(corpus_dir)
    cid, ext = spec["case_id"], spec["ext"]
    d = corpus_dir / "cases" / cid
    d.mkdir(parents=True, exist_ok=False)
    vfile, bfile = f"vulnerable_variant.{ext}", f"benign_lookalike.{ext}"
    (d / vfile).write_text(spec["vulnerable_code"])
    (d / bfile).write_text(spec["benign_code"])
    (d / "target.md").write_text(
        f"# {cid}\n\n- **language:** {spec['language']}\n- **category:** {spec['category']}\n"
        f"- {spec.get('note', 'promoted confirmed finding')}\n")
    label = {
        "case_id": cid, "language": spec["language"], "category": spec["category"],
        "severity": spec["severity"], "owasp": spec.get("owasp", []),
        "vulnerable": {"file": vfile, "line": spec["vulnerable_line"]},
        "benign_lookalike": {"file": bfile},
        "note": spec.get("note", "promoted confirmed finding (second ratchet)"),
    }
    (d / "label.json").write_text(json.dumps(label, indent=2) + "\n")
    locked = corpus_dir / "LOCKED"
    if locked.exists():
        with locked.open("a") as fh:
            fh.write(cid + "\n")
    return d


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    pos = [a for a in argv if not a.startswith("-")]
    if not pos:
        print("usage: promote_finding.py <spec.json> [--corpus evals/corpus]")
        return 2
    corpus = argv[argv.index("--corpus") + 1] if "--corpus" in argv else "evals/corpus"
    spec = json.loads(Path(pos[0]).read_text())
    d = promote(corpus, spec)
    print(f"promoted {spec['case_id']} -> {d}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
