"""Second ratchet (T-9.5): promote a confirmed true finding into the FROZEN corpus as a locked case.

Run by the HUMAN / CI identity ONLY — the agent is write-blocked from `evals/corpus/**` (T-8.4), so
it cannot promote its own findings (no grading-its-own-exam). Adds the case files + a label.json and
appends the id to LOCKED, so the bar keeps rising as new true positives are confirmed.

Two spec shapes (mode selected by the presence of a `files` map):
  * FLAT (default): `{case_id, ext, vulnerable_code, benign_code, vulnerable_line, ...}` →
    `vulnerable_variant.<ext>` + `benign_lookalike.<ext>` flat files.
  * MULTIFILE (wh-705): `{case_id, files:{relpath: content}, vulnerable_file, vulnerable_line,
    benign_file, ...}` → an arbitrary subdir tree (e.g. per-variant PROJECT DIRS for floor-scored
    supply-chain cases, where `supply_chain.scan` scans a directory, not a flat file).
Both shapes share: `language, category, severity, owasp?, note?` and the optional label keys
`difficulty?, multifile?, support_files?`. MULTIFILE also accepts `target_md?` (verbatim passthrough).

CLI:
    uv run python promote_finding.py <spec.json> [--corpus evals/corpus]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path, PurePosixPath

# Optional label keys carried through verbatim when present (both spec shapes).
_OPTIONAL_LABEL_KEYS = ("difficulty", "multifile", "support_files")


def _check_relpath(rel: str) -> None:
    """A `files` key must stay INSIDE the case dir. Reject absolute paths and any `..` segment
    BEFORE any write — a malformed/hostile spec must never clobber the working tree."""
    p = PurePosixPath(rel)
    if not rel.strip() or p.is_absolute() or ".." in p.parts:
        raise ValueError(f"unsafe path in files map (absolute or '..'): {rel!r}")


def _target_md(spec: dict) -> str:
    if spec.get("target_md") is not None:
        return spec["target_md"]
    return (f"# {spec['case_id']}\n\n- **language:** {spec['language']}\n"
            f"- **category:** {spec['category']}\n"
            f"- {spec.get('note', 'promoted confirmed finding')}\n")


def _label(spec: dict, vfile: str, bfile: str) -> dict:
    label = {
        "case_id": spec["case_id"], "language": spec["language"], "category": spec["category"],
        "severity": spec["severity"], "owasp": spec.get("owasp", []),
        "vulnerable": {"file": vfile, "line": spec["vulnerable_line"]},
        "benign_lookalike": {"file": bfile},
        "note": spec.get("note", "promoted confirmed finding (second ratchet)"),
    }
    for k in _OPTIONAL_LABEL_KEYS:
        if k in spec:
            label[k] = spec[k]
    return label


def promote(corpus_dir, spec: dict) -> Path:
    corpus_dir = Path(corpus_dir)
    cid = spec["case_id"]
    multifile = "files" in spec
    if multifile:  # validate the whole tree before ANY side effect (mkdir / writes)
        for rel in spec["files"]:
            _check_relpath(rel)

    d = corpus_dir / "cases" / cid
    d.mkdir(parents=True, exist_ok=False)  # never overwrite an existing locked case

    if multifile:
        for rel, content in spec["files"].items():
            target = d / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        vfile, bfile = spec["vulnerable_file"], spec["benign_file"]
    else:
        ext = spec["ext"]
        vfile, bfile = f"vulnerable_variant.{ext}", f"benign_lookalike.{ext}"
        (d / vfile).write_text(spec["vulnerable_code"])
        (d / bfile).write_text(spec["benign_code"])

    (d / "target.md").write_text(_target_md(spec))
    (d / "label.json").write_text(json.dumps(_label(spec, vfile, bfile), indent=2) + "\n")
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
