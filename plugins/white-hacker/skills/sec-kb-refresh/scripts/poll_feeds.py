"""Poll authoritative AI-threat feeds -> incremental candidate KB entries (T-8.6).

Parses recorded feed content (OSV query JSON, MITRE ATLAS YAML, atom/RSS XML) into items, diffs
each feed against last-seen markers in `feed-state.json` (process deltas only), and renders
schema-conforming **draft** KB entries (mandatory `source`+`url`+`retrieved`). NO network here — the
caller fetches (live polling honors the egress allow-list in `confine_self_writes`, T-8.4); this
module only parses/diffs/renders. Drafts go to a PR; never auto-merged, fast tier only.

CLI:
    uv run --with pyyaml python poll_feeds.py <feed_type> <fixture-file> [--state feed-state.json]
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

VALID_CLASSES = {"prompt-injection", "tool-poisoning", "rag-poisoning", "excessive-agency", "data-exfil"}


def parse_osv(raw: str) -> list[dict]:
    data = json.loads(raw)
    vulns = data.get("vulns", data) if isinstance(data, dict) else data
    out = []
    for v in vulns:
        vid = v["id"]
        out.append({"feed": "osv", "id": vid, "title": v.get("summary") or vid,
                    "url": f"https://osv.dev/vulnerability/{vid}"})
    return out


def parse_atlas(raw: str) -> list[dict]:
    data = yaml.safe_load(raw) or {}
    out = []
    for t in (data.get("techniques") or []):
        tid = t["id"]
        out.append({"feed": "atlas", "id": tid, "title": t.get("name") or tid,
                    "url": f"https://atlas.mitre.org/techniques/{tid}"})
    return out


def _local(tag: str) -> str:
    return tag.split("}")[-1]


def parse_atom(raw: str) -> list[dict]:
    root = ET.fromstring(raw)
    out = []
    for e in root.iter():
        if _local(e.tag) not in ("entry", "item"):
            continue
        kids = {_local(c.tag): c for c in e}
        link = kids.get("link")
        href = (link.get("href") if link is not None and link.get("href") else
                (link.text if link is not None else None))
        idc = kids.get("id")
        idc = idc if idc is not None else kids.get("guid")
        iid = (idc.text if idc is not None and idc.text else href) or "?"
        title = kids["title"].text if "title" in kids and kids["title"].text else ""
        out.append({"feed": "atom", "id": iid, "title": title, "url": href or iid})
    return out


PARSERS = {"osv": parse_osv, "atlas": parse_atlas, "atom": parse_atom}


def poll(feed_type: str, raw: str, state: dict) -> tuple[list[dict], dict]:
    """Return (new_items, updated_state). new_items = items whose id wasn't already seen."""
    items = PARSERS[feed_type](raw)
    seen = set((state.get(feed_type) or {}).get("seen_ids", []))
    new = [it for it in items if it["id"] not in seen]
    updated = dict(state)
    updated[feed_type] = {"seen_ids": sorted(seen | {it["id"] for it in items})}
    return new, updated


def to_candidate_entry(item: dict, technique_class: str, seq: int,
                       today: str = "2026-06-06", source: str | None = None) -> dict:
    assert technique_class in VALID_CLASSES, technique_class
    review_by = (_dt.date.fromisoformat(today) + _dt.timedelta(days=90)).isoformat()
    cls = technique_class.upper()
    xref = [item["id"]] if re.search(r"(AML\.T|LLM\d|ASI\d|MCP\d|CVE-)", item["id"], re.I) else []
    return {
        "id": f"AISEC-{cls}-{seq:03d}",
        "title": item["title"][:120] or item["id"],
        "technique_class": technique_class,
        "severity": "medium",
        "confidence": 0.6,
        "status": "active",
        "date": today,
        "modified": today,
        "review_by": review_by,
        "metadata": {"source": source or f"{item['feed']} feed", "url": item["url"], "retrieved": today},
        "supersedes": None,
        "detections": ["AUTO-EXTRACTED from feed — refine the detection pattern before merge"],
        "xref": xref,
    }


def render_entry(entry: dict, summary: str) -> str:
    fm = yaml.safe_dump(entry, sort_keys=False, default_flow_style=False, allow_unicode=True)
    return f"---\n{fm}---\n\n{summary}\n\nDetection: see `detections`.\nChecklist: maps to `ai-llm.md`.\n"


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    pos = [a for a in argv if not a.startswith("-")]
    if len(pos) < 2 or pos[0] not in PARSERS:
        print(f"usage: poll_feeds.py <{'|'.join(PARSERS)}> <fixture-file> [--state feed-state.json]")
        return 2
    feed_type, fixture = pos[0], pos[1]
    state = {}
    if "--state" in argv:
        sp = Path(argv[argv.index("--state") + 1])
        if sp.exists():
            state = json.loads(sp.read_text())
    new, _ = poll(feed_type, Path(fixture).read_text(), state)
    print(json.dumps({"new_count": len(new), "new_items": new}, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
