"""Normalize SCA tool output → a schema-valid white-hacker findings document.

Today this maps a Trivy `--format json` document (the cross-language SCA fallback) into the
canonical finding shape (`_shared/reference/finding-schema.json`). The same module is where other
SCA tools' output (OSV-Scanner, native gates) would be normalized behind the **SCA capability** —
the finding shape is the stable contract, the tool is swappable (ADR-015).

SCA evidence is about *a known CVE in a dependency*, not about reachability — so findings come out
`access_required: "unknown"`, `verified: "static_review_only"`, with a modest confidence; **triage**
decides whether the vulnerable code path is actually reached (the "outdated-lib without a reachable
sink" exclusion). `tool_assisted` / `tools_unavailable` are derived from the SCAN-PLAN via
`degradation.py` so a degraded run is recorded, never crashes.
"""
from __future__ import annotations

import degradation as dg

# Trivy package Type -> our language label (for summary.scanned_langs).
_TYPE_LANG = {
    "pip": "python", "poetry": "python",
    "npm": "javascript", "yarn": "javascript", "pnpm": "javascript",
    "gomod": "go", "pom": "java", "gradle": "java", "jar": "java",
    "cargo": "rust",
}

# Provisional severity (triage re-derives from preconditions). Trivy uses CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN.
_SEVERITY = {"CRITICAL": "HIGH", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "UNKNOWN": "LOW"}
_CONFIDENCE = {"HIGH": 0.7, "MEDIUM": 0.6, "LOW": 0.5}

_OWASP = ["A06:2021"]  # Vulnerable and Outdated Components


def _vuln_to_finding(vuln: dict, target: str, idx: int) -> dict:
    sev = _SEVERITY.get(str(vuln.get("Severity", "UNKNOWN")).upper(), "LOW")
    pkg = vuln.get("PkgName", "?")
    installed = vuln.get("InstalledVersion", "?")
    fixed = vuln.get("FixedVersion")
    cve = vuln.get("VulnerabilityID", "?")
    title = vuln.get("Title") or f"Known vulnerability {cve} in {pkg}"
    if fixed:
        rec = f"Upgrade {pkg} from {installed} to {fixed} (fixes {cve})."
    else:
        rec = f"No fixed version for {cve} in {pkg} {installed}; mitigate exposure or replace the dependency."
    kb_refs = [cve]
    url = vuln.get("PrimaryURL")
    if url:
        kb_refs.append(url)
    return {
        "id": f"F-{idx:03d}",
        "canonical_of": None,
        "file": target,
        "line": 0,
        "severity": sev,
        "category": "supply-chain",
        "owasp": list(_OWASP),
        "preconditions": [],
        "access_required": "unknown",
        "verified": "static_review_only",
        "confidence": _CONFIDENCE[sev],
        "exploit_scenario": f"{pkg} {installed}: {title}",
        "recommendation": rec,
        "first_link": target,
        "tool_assisted": True,
        "kb_refs": kb_refs,
    }


def _counts(findings: list[dict]) -> dict:
    c = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        c[f["severity"].lower()] += 1
    return c


def normalize(trivy_doc: dict, scan_plan: dict | None = None,
              scoring_standard: str = "CVSS4.0") -> dict:
    """Trivy JSON → findings document. Dedups by (PkgName, VulnerabilityID)."""
    findings: list[dict] = []
    langs: set[str] = set()
    seen: set[tuple[str, str]] = set()
    idx = 1
    for result in trivy_doc.get("Results") or []:
        target = result.get("Target") or "dependencies"
        lang = _TYPE_LANG.get(str(result.get("Type", "")).lower())
        if lang:
            langs.add(lang)
        for vuln in result.get("Vulnerabilities") or []:
            key = (vuln.get("PkgName", "?"), vuln.get("VulnerabilityID", "?"))
            if key in seen:
                continue
            seen.add(key)
            finding = _vuln_to_finding(vuln, target, idx)
            if scan_plan is not None:
                finding = dg.finalize(finding, scan_plan, "sca")
            findings.append(finding)
            idx += 1

    if scan_plan is not None:
        tools = dg.summary_tools(scan_plan)
    else:
        tools = {"tools_used": ["trivy"], "tools_unavailable": []}

    return {
        "summary": {
            "scanned_langs": sorted(langs),
            "tools_used": tools["tools_used"],
            "tools_unavailable": tools["tools_unavailable"],
            "scoring_standard": scoring_standard,
            "counts": _counts(findings),
        },
        "findings": findings,
    }


def degraded_result(scan_plan: dict, scanned_langs: list[str] | None = None,
                    scoring_standard: str = "CVSS4.0") -> dict:
    """No SCA tool on PATH → emit a structurally valid, empty (floor) result that records the
    degradation instead of raising. The floor lockfile heuristic (documented in SKILL.md) would add
    low-confidence `tool_assisted:false` candidates; this base result never blocks the pipeline."""
    tools = dg.summary_tools(scan_plan)
    return {
        "summary": {
            "scanned_langs": sorted(scanned_langs or []),
            "tools_used": tools["tools_used"],
            "tools_unavailable": tools["tools_unavailable"],
            "scoring_standard": scoring_standard,
            "counts": {"high": 0, "medium": 0, "low": 0},
        },
        "findings": [],
    }


if __name__ == "__main__":  # pragma: no cover
    import json
    import sys

    doc = json.loads(open(sys.argv[1]).read()) if len(sys.argv) > 1 else json.load(sys.stdin)
    print(json.dumps(normalize(doc), indent=2))
