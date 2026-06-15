"""Coverage matrix (wh-5ox.19): join findings -> MITRE technique ids vs the KB universe.

PURE aggregation — NO LLM, NO RNG, NO network (Policy 5). Reads the triaged findings doc
and the ai-attack-kb technique universe, groups by MITRE technique id, and emits a
markdown matrix `Technique | ID | covered? | modality | finding-refs`.

An in-scope KB technique with ZERO covering finding is flagged a recall/degradation GAP —
the intended outer-loop signal /sec-learn harvests (an output, not an error). Degrade-never-
raise on a malformed KB file (ADR-003): a bad/absent front-matter file is skipped, a non-str
xref element is dropped at THIS call site (kb_attribution.mitre_from_xref has no isinstance
guard and would AttributeError on a non-str element — we are the first KB-file-derived caller).

CLI:
    uv run --with jsonschema --with pyyaml python coverage_matrix.py FINDINGS.json \
        [--kb-dir DIR] [--out PATH]

Exit code 0 = ok (matrix emitted), 2 = usage error / malformed / non-schema input.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

# --- cross-skill imports: put the sibling skills' scripts dirs on sys.path -----
# We are the FIRST sec-report script needing kb_attribution + validate_kb; reuse, do
# not reimplement (ADR-015 / Policy 2). Inserted BEFORE the imports below.
_SKILLS = Path(__file__).resolve().parents[2]
for _p in (_SKILLS / "_shared" / "scripts", _SKILLS / "ai-attack-kb" / "scripts"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import yaml  # noqa: E402  (validate_kb also needs it; we call yaml.safe_load directly)

import kb_attribution  # noqa: E402
import validate_kb  # noqa: E402

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "_shared" / "reference" / "finding-schema.json"
KB_DIR = _SKILLS / "ai-attack-kb" / "reference"

GAP_REFS = "—"  # em-dash placeholder for an uncovered (recall-gap) technique row


def _md_cell(value: object) -> str:
    """Neutralize a value for a GitHub-flavored-markdown table cell. A finding `file` is
    untrusted-derived (finding-schema only constrains its FIRST char), so a literal `|`
    would forge a column and a newline a phantom row — escape the pipe, flatten newlines."""
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def load_schema(path: Path = SCHEMA_PATH) -> dict:
    return json.loads(path.read_text())


def schema_errors(doc: dict, schema: dict | None = None) -> list[str]:
    schema = schema if schema is not None else load_schema()
    validator = Draft202012Validator(schema)
    return [
        f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
        for e in sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    ]


def kb_universe(kb_dir: Path) -> dict[str, dict]:
    """Parse every *.md in `kb_dir` -> {technique_id: {"modality": str, "sources": set}}.

    Degrade-never-raise (ADR-003): a file with absent/malformed front-matter, unparseable
    YAML, a non-dict mapping, or a non-list `xref` is SKIPPED. A non-str `xref` element is
    DROPPED at this call site (the load-bearing guard — mitre_from_xref would AttributeError
    on it). Modality is `att_ck` or `atlas` per kb_attribution's partition.
    """
    universe: dict[str, dict] = {}
    kb_dir = Path(kb_dir)
    if not kb_dir.is_dir():
        return universe
    for md in sorted(kb_dir.glob("*.md")):
        try:
            # errors="ignore": a KB file with non-UTF-8 bytes must DEGRADE, not raise
            # UnicodeDecodeError (a ValueError, not an OSError) — ADR-003, mirror
            # supply_chain._read_text. The KB is the untrusted /sec-kb-refresh surface.
            text = md.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        front, _ = validate_kb.split_front_matter(text)
        if front is None:
            continue
        try:
            meta = yaml.safe_load(front)
        except (yaml.YAMLError, RecursionError):
            # RecursionError (a RuntimeError subclass, NOT a yaml.YAMLError): deeply-nested
            # untrusted YAML front-matter trips PyYAML's recursion limit at parse-DEPTH ->
            # name it, else a hostile KB file aborts the scan (ADR-003; mirror supply_chain.py:410).
            continue
        if not isinstance(meta, dict):
            continue
        xref = meta.get("xref")
        if not isinstance(xref, list):
            xref = []
        # load-bearing non-str guard: drop non-str elements before mitre_from_xref.
        xref = [s for s in xref if isinstance(s, str)]
        buckets = kb_attribution.mitre_from_xref(xref)
        source = meta.get("id")
        for modality in ("att_ck", "atlas"):
            for tid in buckets[modality]:
                entry = universe.setdefault(tid, {"modality": modality, "sources": set()})
                if source is not None:
                    entry["sources"].add(str(source))
    return universe


def finding_ref(finding: dict) -> str:
    """A deterministic finding-ref string `F-001 (src/x.ts:42)` from id/file/line."""
    fid = finding.get("id", "F-???")
    file = finding.get("file", "?")
    line = finding.get("line", "?")
    return f"{fid} ({file}:{line})"


def coverage_by_id(findings: list[dict]) -> dict[str, set]:
    """Map every cited technique id -> the set of covering finding-ref strings."""
    cover: dict[str, set] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue  # degrade-never-raise: skip a malformed (non-dict) finding element
        ref = finding_ref(f)
        for field in ("att_ck", "atlas"):
            ids = f.get(field, [])
            if not isinstance(ids, list):
                continue
            for tid in ids:
                if isinstance(tid, str):
                    cover.setdefault(tid, set()).add(ref)
    return cover


def build_matrix(doc: dict, kb_dir: Path = KB_DIR) -> str:
    """Pure: return the GitHub-flavored markdown coverage matrix.

    Universe = the KB technique ids (in-scope set). For each id (sorted): covered? = `yes`
    when >=1 finding cites it else `gap` (the intended recall-gap signal). Refs are sorted
    finding-refs, or `—` on a gap.
    """
    universe = kb_universe(kb_dir)
    findings = doc.get("findings", [])
    if not isinstance(findings, list):
        findings = []  # degrade-never-raise: a non-list findings field yields no coverage
    cover = coverage_by_id(findings)

    rows = []
    # sorted-grouping idiom (score.py:94): deterministic order, no set-ordering leak.
    for tid in sorted(universe):
        entry = universe[tid]
        technique = _md_cell(", ".join(sorted(entry["sources"])) if entry["sources"] else "—")
        refs = sorted(cover.get(tid, set()))
        covered = "yes" if refs else "gap"
        refs_cell = _md_cell(", ".join(refs) if refs else GAP_REFS)
        rows.append(
            f"| {technique} | {_md_cell(tid)} | {covered} | {_md_cell(entry['modality'])} | {refs_cell} |"
        )

    header = (
        "| Technique | ID | covered? | modality | finding-refs |\n"
        "| --- | --- | --- | --- | --- |"
    )
    if not rows:
        return header + "\n"
    return header + "\n" + "\n".join(rows) + "\n"


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="coverage_matrix.py", add_help=True)
    parser.add_argument("file")
    parser.add_argument("--kb-dir", default=str(KB_DIR))
    parser.add_argument("--out", default=None)
    try:
        ns = parser.parse_args(argv)
    except SystemExit:
        return 2

    try:
        # errors="ignore" (mirror :84): a findings file with non-UTF-8 bytes must DEGRADE,
        # not raise UnicodeDecodeError (a ValueError, NOT an OSError) — ADR-003.
        doc = json.loads(Path(ns.file).read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError, RecursionError, UnicodeDecodeError) as exc:
        # RecursionError (a RuntimeError subclass): deeply-nested untrusted findings JSON trips
        # json's recursion limit at parse-DEPTH. UnicodeDecodeError kept defensively even though
        # errors="ignore" prevents it (the AC enumerates it across the read path); JSONDecodeError
        # already covers the ValueError class. Mirror supply_chain.py:410 (ADR-003).
        print(f"INVALID {ns.file}: could not read/parse JSON: {exc}")
        return 2

    errors = schema_errors(doc)
    if errors:
        print(f"INVALID {ns.file}: does not conform to finding-schema:")
        for e in errors[:5]:
            print(f"  - {e}")
        return 2

    matrix = build_matrix(doc, Path(ns.kb_dir))
    if ns.out:
        section = "## MITRE technique coverage\n\n" + matrix
        Path(ns.out).write_text(section)
        print(f"WROTE {ns.out}")
    else:
        print(matrix, end="")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
