"""Secret redaction + finding construction for `secrets-scan`.

The hard rule (security posture): a secret value must **never** leave this process — not in a
finding, a log, a ticket, or the KB. So we never reveal any substring of the secret. For
identification/dedup we use a **one-way SHA-256 fingerprint** (a hash prefix), which lets two
findings be told apart without disclosing the value.

`to_finding()` builds a schema-valid finding whose fields carry only `{file, line, rule}` and the
fingerprint — `degradation.py` stamps `tool_assisted` from the SCAN-PLAN.
"""
from __future__ import annotations

import hashlib

import degradation as dg


def fingerprint(secret: str) -> str:
    """A short one-way fingerprint — identifies a secret without revealing it."""
    return hashlib.sha256(str(secret).encode("utf-8")).hexdigest()[:12]


def redact(secret: str) -> str:
    """A safe placeholder for a secret. Reveals **no** substring of the value (not even a prefix,
    which would aid brute force) — only a one-way fingerprint for correlation."""
    if not secret:
        return "<redacted:empty>"
    return f"<redacted:sha256={fingerprint(secret)}>"


def to_finding(file: str, line: int, rule: str, secret: str, fid: int = 1,
               scan_plan: dict | None = None) -> dict:
    """Build a schema-valid secrets finding that contains no secret value."""
    finding = {
        "id": f"F-{fid:03d}",
        "canonical_of": None,
        "file": file,
        "line": int(line),
        "severity": "HIGH",            # a committed live secret defaults HIGH; triage may temper
        "category": "hardcoded-secret",
        "owasp": ["A07:2021"],         # Identification and Authentication Failures
        "preconditions": [],           # triage confirms the secret is still valid
        "access_required": "unknown",
        "verified": "static_review_only",
        "confidence": 0.7,
        "exploit_scenario": f"Hardcoded secret ({rule}) committed at {file}:{line} [{redact(secret)}]",
        "recommendation": ("Rotate the exposed credential immediately, remove it from the working "
                           "tree and git history, and load it from a secret manager / env var."),
        "first_link": f"{file}:{line}",
        "tool_assisted": False,
        "kb_refs": [rule],
    }
    if scan_plan is not None:
        finding = dg.finalize(finding, scan_plan, "secrets")
    return finding
