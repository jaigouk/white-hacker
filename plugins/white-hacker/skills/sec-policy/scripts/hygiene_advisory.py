"""hygiene_advisory (T-11.5): a missing security policy is an ADVISORY, not a vuln.

When a repo has NO security policy (`SECURITY.md` / RFC 9116 `security.txt`), the
white-hacker agent surfaces an INFORMATIONAL supply-chain-hygiene ADVISORY — it is
NEVER promoted to a vuln finding (see `_shared/reference/exclusion-rules.md` rule 19 and
`severity-rubric.md`: hygiene advisories carry no severity label and no CVSS).

The advisory is deliberately shaped so it can NEVER be mistaken for a `VULN-FINDINGS.json`
/ `TRIAGE.json` entry: it carries `kind="hygiene-advisory"` and has NO `severity`, NO
`cvss`, and NO `owasp` keys. Its `message` is FACTUAL (not imperative) so an advisory
echoed back into agent context cannot act as an injected instruction.

stdlib only.
"""
from __future__ import annotations

import re

# Imperative markers — a string starting with one of these is an instruction, not a
# fact. Mirrors sec-init's `is_factual` so advisory text stays injection-safe (the
# message is FACTUAL, never a directive). Kept local to remain stdlib-only and avoid a
# cross-skill import-path dependency.
_IMPERATIVE_RE = re.compile(
    r"^(always|never|you must|ignore|disregard|do not)\b",
    re.IGNORECASE,
)

# Stable advisory identity (not a CVE / not scored).
ADVISORY_ID = "WH-HYGIENE-SECPOLICY"

# A FACTUAL one-liner (declarative, never imperative): states the absence and that a
# draft can be proposed under PATCHES/. Phrased as fact so is_factual() accepts it.
_MESSAGE = (
    "This repository has no security policy; adding a SECURITY.md is recommended for "
    "supply-chain hygiene, and a draft can be proposed under PATCHES/."
)

_REFERENCES = (
    "https://github.com/ossf/scorecard/blob/main/docs/checks.md#security-policy",
    "https://www.rfc-editor.org/rfc/rfc9116",
)


def is_factual(text: str) -> bool:
    """True when `text` reads as a factual statement (not an imperative instruction).

    False if it begins with an imperative marker (always/never/you must/ignore/
    disregard/do not). Empty/whitespace strings are treated as factual (vacuously).
    Same semantics as sec-init's `is_factual`.
    """
    return not bool(_IMPERATIVE_RE.match(text.strip()))


def policy_hygiene_advisory(gap_report: dict) -> dict | None:
    """Return a hygiene advisory when the repo has no security policy, else None.

    Input is a parse_policy gap report. When `gap_report["present"]` is truthy a
    SECURITY.md exists → no advisory (returns None). Otherwise returns an INFORMATIONAL
    supply-chain-hygiene advisory dict.

    The returned dict carries NO `severity` and NO `cvss` keys (hygiene advisories are
    not scored) and is NOT a vuln finding — it must never be written to
    `VULN-FINDINGS.json` / `TRIAGE.json`. The `message` is FACTUAL (guarded by
    is_factual) so it cannot act as an injected directive when echoed into context.
    """
    if gap_report.get("present"):
        return None

    # Guard the message at construction time: never emit a non-factual (imperative)
    # advisory string into downstream context.
    assert is_factual(_MESSAGE), "hygiene advisory message must be factual, not imperative"

    return {
        "kind": "hygiene-advisory",
        "category": "supply-chain-hygiene",
        "id": ADVISORY_ID,
        "message": _MESSAGE,
        "references": list(_REFERENCES),
    }
