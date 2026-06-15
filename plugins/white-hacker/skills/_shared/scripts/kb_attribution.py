"""KB-entry attribution helpers (wh-5ox.10): xref -> MITRE buckets + finding attribution.

Pure / stdlib / deterministic (Policy 5, no LLM/RNG/network). Shared because ≥2 skills
(deps-scan normalize_deps + supply_chain) attribute findings from a matched KB entry's
`xref`, so the logic lives once behind the _shared scripts dir (ADR-015 / Policy 2).

A KB entry's `xref` mixes taxonomy ids (LLM03:2025, ASIxx, MCPxx, CVE-…) with MITRE
technique ids, each optionally tagged ` [primary-sourced: <url>]`. We split out only the
MITRE subset — ATT&CK enterprise (T#### / T####.###) and ATLAS (AML.*) — onto a finding,
and optionally propagate a contested `disputed` claim (capping confidence while unresolved).
"""
from __future__ import annotations

import re

_ATTCK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")   # T1195 / T1195.002 (ATT&CK enterprise)
DISPUTED_UNRESOLVED_CAP = 0.5  # primary sources split -> confidence no better than even odds


def mitre_from_xref(xref: list[str] | None) -> dict:
    """Partition a KB `xref` list into MITRE buckets: {"att_ck": [...], "atlas": [...]}.

    Non-MITRE ids (LLMxx:2025, ASIxx, MCPxx, CVE-…, AISEC-…) are dropped. The
    ` [primary-sourced: <url>]` provenance tag is stripped before matching. Order-stable.
    """
    att_ck: list[str] = []
    atlas: list[str] = []
    for raw in xref or []:
        bare = raw.split(" [", 1)[0].strip()     # strip " [primary-sourced: <url>]"
        if bare.startswith("AML."):
            atlas.append(bare)
        elif _ATTCK_RE.match(bare):
            att_ck.append(bare)
    return {"att_ck": att_ck, "atlas": atlas}


def apply_kb_attribution(finding: dict, *, xref: list[str] | None = None,
                         disputed: dict | None = None) -> dict:
    """Return a copy of `finding` with att_ck/atlas (and optional disputed) attributed.

    `att_ck`/`atlas` are always set (empty when no KB entry / xref). When `disputed` is
    given it is attached; an `unresolved` dispute caps confidence at DISPUTED_UNRESOLVED_CAP
    (primary sources split → no better than even odds). Idempotent on a no-KB finding.
    """
    out = dict(finding)
    mitre = mitre_from_xref(xref or [])
    out["att_ck"] = mitre["att_ck"]
    out["atlas"] = mitre["atlas"]
    if disputed is not None:
        out["disputed"] = dict(disputed)
        if disputed.get("status") == "unresolved":
            out["confidence"] = min(float(out.get("confidence", 1.0)), DISPUTED_UNRESOLVED_CAP)
    return out
