"""KB anti-drift: duplicate-id failure + shared-xref / title-similarity merge flagging (T-8.2).

Duplicate `id` across entries is a hard error (exit 1) — typed, never-reused ids (ADR-012).
Entries that share an `xref` or have near-identical titles are *flagged* for human merge review
(advisory; merges are done via `supersedes` lineage), but do NOT fail the run on their own.

CLI:
    uv run --with pyyaml python dedupe_kb.py <kb-reference-dir>
Exit 0 = no duplicate ids, 1 = duplicate id(s), 2 = usage.
"""
from __future__ import annotations

import sys
from itertools import combinations
from pathlib import Path

from _kb_entries import read_entries


def duplicate_ids(entries: list[dict]) -> list[str]:
    seen: dict[str, str] = {}
    dups: list[str] = []
    for e in entries:
        eid = e["id"]
        if eid in seen:
            dups.append(f"duplicate id {eid}: {Path(e['path']).name} and {seen[eid]}")
        else:
            seen[eid] = Path(e["path"]).name
    return dups


def _title_tokens(t: str) -> set[str]:
    return {w for w in t.lower().replace("/", " ").replace("-", " ").split() if len(w) > 3}


def merge_flags(entries: list[dict]) -> list[str]:
    """Advisory: entry pairs that share an xref or have high title-token overlap."""
    flags: list[str] = []
    for a, b in combinations(entries, 2):
        shared = a["xref"] & b["xref"]
        if shared:
            flags.append(f"{a['id']} & {b['id']} share xref {sorted(shared)} — review for merge")
            continue
        ta, tb = _title_tokens(a["title"]), _title_tokens(b["title"])
        if ta and tb and len(ta & tb) / len(ta | tb) >= 0.6:
            flags.append(f"{a['id']} & {b['id']} have near-identical titles — review for merge")
    return flags


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    targets = [a for a in argv if not a.startswith("-")]
    if not targets:
        print("usage: dedupe_kb.py <kb-reference-dir>")
        return 2
    rc = 0
    for t in targets:
        entries = read_entries(t)
        dups = duplicate_ids(entries)
        flags = merge_flags(entries)
        for d in dups:
            print(f"ERROR {t}: {d}")
        for f in flags:
            print(f"FLAG (advisory) {t}: {f}")
        if dups:
            rc = 1
        elif not flags:
            print(f"OK {t}: no duplicate ids, no merge flags")
    return rc


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
