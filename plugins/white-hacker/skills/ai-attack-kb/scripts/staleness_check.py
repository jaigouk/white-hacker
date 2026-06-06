"""KB staleness gate (T-8.2): flag entries past `review_by`; archive (never delete).

The fast AI-threat tier ages: an entry past its `review_by` is flagged for re-verification. With
`--archive`, stale entries are MOVED to `ai-attack-kb/archive/` (content preserved, never deleted)
so the active set stays current while history is auditable.

CLI:
    uv run --with pyyaml python staleness_check.py <kb-reference-dir> [--today YYYY-MM-DD] [--archive]
Exit 0 = nothing stale, 1 = stale entries found, 2 = usage.
"""
from __future__ import annotations

import datetime as _dt
import shutil
import sys
from pathlib import Path

from _kb_entries import read_entries


def stale_entries(entries: list[dict], today: str) -> list[dict]:
    # ISO date strings compare correctly lexicographically.
    return [e for e in entries if e["review_by"] and e["review_by"] < today]


def archive_entry(entry: dict, archive_dir: Path) -> Path:
    archive_dir.mkdir(parents=True, exist_ok=True)
    dest = archive_dir / Path(entry["path"]).name
    shutil.move(str(entry["path"]), str(dest))
    return dest


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    today = _dt.date.today().isoformat()
    do_archive = "--archive" in argv
    if "--today" in argv:
        today = argv[argv.index("--today") + 1]
    targets = [a for a in argv if not a.startswith("-") and a != today]
    if not targets:
        print("usage: staleness_check.py <kb-reference-dir> [--today YYYY-MM-DD] [--archive]")
        return 2
    rc = 0
    for t in targets:
        entries = read_entries(t)
        stale = stale_entries(entries, today)
        for e in stale:
            rc = 1
            line = f"STALE {t}: {e['id']} review_by={e['review_by']} < {today}"
            if do_archive:
                dest = archive_entry(e, Path(t).parent / "archive")
                line += f" -> archived to {dest}"
            print(line)
        if not stale:
            print(f"OK {t}: no entries past review_by ({today})")
    return rc


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
