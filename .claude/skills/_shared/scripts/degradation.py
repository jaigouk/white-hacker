"""Graceful-degradation glue (ADR-003, ADR-015).

The single place that turns a `SCAN-PLAN.json` (from `sec-detect`) into the finding-document
fields that record *how strong the evidence is*:
  * `summary.tools_used` / `summary.tools_unavailable`, and
  * each finding's `tool_assisted` flag (+ a floor-confidence cap when no tool backed it).

Depends only on the **SCAN-PLAN artifact shape**, never on `sec-detect`'s module — so every
skill (`deps-scan`, `secrets-scan`, `sec-vuln-scan`) and the integration test can reuse it without
a cross-package import. "Never block on a missing tool": a degraded capability lowers confidence and
is listed, it does not raise.
"""
from __future__ import annotations

# Floor findings (no tool backing) are capped here — weaker evidence, lower confidence (PLAN §4.5).
FLOOR_CONFIDENCE_CAP = 0.8


def degraded_capabilities(scan_plan: dict) -> set[str]:
    """The capabilities that fell back to the Read/Grep/Glob floor."""
    return set(scan_plan.get("degraded", []))


def is_degraded(scan_plan: dict, capability: str) -> bool:
    return capability in degraded_capabilities(scan_plan)


def capability_has_tool(scan_plan: dict, capability: str) -> bool:
    """True iff `sec-detect` bound an installed tool to this capability."""
    return bool(scan_plan.get("category_tool", {}).get(capability))


def summary_tools(scan_plan: dict) -> dict:
    """Derive the finding-doc `summary` tool fields from a SCAN-PLAN.

    `tools_used`        = the installed tools actually bound to a capability.
    `tools_unavailable` = the capabilities that degraded to the floor (capability-level view;
                          the run had no tool for them).
    """
    category_tool = scan_plan.get("category_tool", {})
    tools_used = sorted({t for t in category_tool.values() if t})
    tools_unavailable = sorted(degraded_capabilities(scan_plan))
    return {"tools_used": tools_used, "tools_unavailable": tools_unavailable}


def stamp_tool_assisted(finding: dict, scan_plan: dict, capability: str) -> dict:
    """Return a copy of `finding` with `tool_assisted` set from the SCAN-PLAN.

    True only when the capability is not degraded AND a tool is bound to it. Idempotent.
    """
    out = dict(finding)
    out["tool_assisted"] = (
        not is_degraded(scan_plan, capability)
        and capability_has_tool(scan_plan, capability)
    )
    return out


def cap_floor_confidence(finding: dict, cap: float = FLOOR_CONFIDENCE_CAP) -> dict:
    """Cap confidence for findings that no tool backed (`tool_assisted` falsey). Idempotent."""
    out = dict(finding)
    if not out.get("tool_assisted", False):
        out["confidence"] = min(float(out.get("confidence", cap)), cap)
    return out


def finalize(finding: dict, scan_plan: dict, capability: str) -> dict:
    """Stamp `tool_assisted` then apply the floor cap — the usual one-call path for a normalizer."""
    return cap_floor_confidence(stamp_tool_assisted(finding, scan_plan, capability))
