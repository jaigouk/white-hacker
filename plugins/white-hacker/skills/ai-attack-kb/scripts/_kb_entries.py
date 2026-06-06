"""Shared KB-entry front-matter reader for dedupe_kb / staleness_check (pyyaml only, no jsonschema)."""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

import yaml


def _front(text: str) -> str | None:
    if not text.startswith("---"):
        return None
    lines = text.splitlines(keepends=True)
    for i in range(1, len(lines)):
        if lines[i].rstrip("\n") in ("---", "..."):
            return "".join(lines[1:i])
    return None


def _iso(v) -> str:
    if isinstance(v, (_dt.date, _dt.datetime)):
        return (v.date() if isinstance(v, _dt.datetime) else v).isoformat()
    return str(v) if v else ""


def read_entries(directory) -> list[dict]:
    """Parse every *.md KB entry's front-matter into a normalized dict."""
    out: list[dict] = []
    for f in sorted(Path(directory).glob("*.md")):
        fm = _front(f.read_text())
        if fm is None:
            continue
        try:
            meta = yaml.safe_load(fm) or {}
        except yaml.YAMLError:
            continue
        if not isinstance(meta, dict):
            continue
        out.append({
            "path": f,
            "id": meta.get("id"),
            "technique_class": meta.get("technique_class"),
            "title": str(meta.get("title", "")),
            "xref": set(meta.get("xref") or []),
            "status": meta.get("status"),
            "review_by": _iso(meta.get("review_by")),
            "supersedes": meta.get("supersedes"),
        })
    return out
