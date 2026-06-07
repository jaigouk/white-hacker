"""parse_policy (T-11.3): parse an existing security policy → a structured gap report.

Reads an existing SECURITY.md and/or RFC 9116 security.txt STRUCTURALLY and emits a gap
report: which best-practice sections are present/missing, OpenSSF-Scorecard-style signals,
the reporting channel, security.txt facts, and a prompt-injection screen result. It REUSES
the T-11.2 detector (`policy_detect`) for locate/detect/timeline/expiry — no duplication —
and NEVER touches the project profile (ADR-018, resolves spike-08).

SECURITY POSTURE — every byte read here is UNTRUSTED DATA. A SECURITY.md / security.txt
lives in the repo under review and may carry prompt-injection payloads aimed at the
white-hacker agent (Agents Rule of Two: never simultaneously hold untrusted input +
secrets + egress). This module therefore:
  * uses regex / structural matching ONLY — it never executes, evals, or "follows" file
    content, and never derives behavior from it;
  * emits ONLY structured data — booleans, a closed reporting-channel enum, section-name
    strings, integer scores — and NEVER any span of the file body, so injected directive
    text cannot flow downstream into any report consumer or decision-maker view;
  * the injection SCREEN is a DENYLIST (flag known-bad markers — appropriate for
    detection) returning a BOOLEAN signal only. NB: this is the opposite filter to F-001's
    output sanitizer, which is an ALLOWLIST for *emitting* context — do not conflate them.
    This module only FLAGS; it emits nothing from the body.

stdlib + jsonschema. Imports `policy_detect as pd` (the shared T-11.2 detector).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import jsonschema

# Make the _shared policy_detect (the T-11.2 detector) importable both under pytest (the
# conftest shim) AND when this file is run directly as a CLI.
_HERE = Path(__file__).parent
_SHARED_SCRIPTS = _HERE.parent.parent / "_shared" / "scripts"
if str(_SHARED_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SHARED_SCRIPTS))

import policy_detect as pd  # noqa: E402  (path shim above must run first)

_SCHEMA_PATH = _HERE / "policy_gap_schema.json"

# The seven best-practice sections, in report order.
SECTION_KEYS = (
    "supported_versions",
    "reporting",
    "response_timeline",
    "coordinated_disclosure",
    "scope",
    "safe_harbor",
    "acknowledgments",
)

# Case-insensitive markdown-heading regexes for each section (any heading level).
# `supported_versions` is delegated to pd.has_supported_versions for consistency, but a
# pattern is kept here for completeness/documentation.
SECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "supported_versions": re.compile(r"(?im)^#{1,6}\s*supported\s+versions\b"),
    "reporting": re.compile(r"(?im)^#{1,6}\s*report"),
    "response_timeline": re.compile(
        r"(?im)^#{1,6}\s*(response|disclosure)\s+(time|timeline|sla|target)"
        r"|^#{1,6}\s*(timeline|response\s+time)\b"
    ),
    "coordinated_disclosure": re.compile(
        r"(?im)^#{1,6}\s*(coordinated|responsible)\s+disclosure\b"
    ),
    "scope": re.compile(r"(?im)^#{1,6}\s*(in[\s-]*)?scope\b|^#{1,6}\s*out[\s-]*of[\s-]*scope\b"),
    "safe_harbor": re.compile(r"(?im)^#{1,6}\s*safe[\s-]*harbou?r\b"),
    "acknowledgments": re.compile(
        r"(?im)^#{1,6}\s*(acknowled|hall\s+of\s+fame|credits?|recognition|thanks)"
    ),
}

# DENYLIST of indirect-prompt-injection markers. A match flips a BOOLEAN signal only; the
# matched text is NEVER returned (no body echo).
INJECTION_MARKERS = re.compile(
    r"ignore\s+(all|previous|prior)(\s+\w+){0,3}\s+instructions"
    r"|disregard\s+(the|all)\s+above"
    r"|you\s+are\s+now\b"
    r"|system\s*:\s"
    r"|developer\s+mode"
    r"|exfiltrat"
    r"|print\s+(the\s+)?secrets"
    r"|base64",
    re.IGNORECASE,
)

# For the Scorecard "specific" signal: count vuln*/disclos* mentions.
_VULN_RE = re.compile(r"(?i)\bvuln\w*")
_DISCLOS_RE = re.compile(r"(?i)\bdisclos\w*")

# Strip URLs and emails before the free-form word count (a bare link must not count as prose).
# The email regex mirrors policy_detect._EMAIL_RE: ReDoS-hardened with BOUNDED runs (RFC
# limits) and a hard `\.` label delimiter, so it stays linear on attacker-influenceable
# content (the `.` is never inside the same unbounded class that also feeds the literal dot).
_URL_RE = re.compile(r"https?://\S+|mailto:\S+", re.IGNORECASE)
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}"
)
# A "word" for the prose threshold: an alphabetic token of length >= 2.
_WORD_RE = re.compile(r"[A-Za-z]{2,}")
_FREE_FORM_MIN_WORDS = 20


def injection_suspected(text: str) -> bool:
    """True when any indirect-prompt-injection marker matches `text` (denylist screen).

    Returns a BOOLEAN signal only — the matched span is never returned or logged, so
    attacker-controlled directive text cannot leak downstream.
    """
    return bool(INJECTION_MARKERS.search(text))


def detect_sections(text: str) -> dict[str, bool]:
    """Map each best-practice section to whether its heading is present in `text`.

    `supported_versions` reuses pd.has_supported_versions (single source of truth).
    """
    sections: dict[str, bool] = {}
    for key in SECTION_KEYS:
        if key == "supported_versions":
            sections[key] = pd.has_supported_versions(text)
        else:
            sections[key] = bool(SECTION_PATTERNS[key].search(text))
    return sections


def scorecard_signals(text: str) -> dict:
    """Model OpenSSF Scorecard's Security-Policy signals as structured booleans + a score.

    Signals (all structural — no body span returned):
      * contact        — a reporting channel exists (pd.detect_reporting_channel != "none");
      * free_form_text — substantive prose beyond a bare link/email: the alphabetic word
                         count, with URLs and emails removed, exceeds a threshold;
      * specific       — >=2 case-insensitive hits among vuln*/disclos* AND a numeric time
                         expectation (pd.has_disclosure_timeline).
    Score = 6*contact + 3*free_form_text + 1*specific, clamped to 0..10.
    """
    contact = pd.detect_reporting_channel(text) != "none"

    stripped = _EMAIL_RE.sub(" ", _URL_RE.sub(" ", text))
    free_form_text = len(_WORD_RE.findall(stripped)) >= _FREE_FORM_MIN_WORDS

    hits = len(_VULN_RE.findall(text)) + len(_DISCLOS_RE.findall(text))
    specific = hits >= 2 and pd.has_disclosure_timeline(text)

    score = 6 * int(contact) + 3 * int(free_form_text) + 1 * int(specific)
    return {
        "contact": contact,
        "free_form_text": free_form_text,
        "specific": specific,
        "score": score,
    }


def _empty_sections() -> dict[str, bool]:
    return {key: False for key in SECTION_KEYS}


def parse_policy(repo_root, now=None) -> dict:
    """Parse `repo_root`'s security policy and return the gap report (exact shape).

    Shape (and nothing else):
      {present, path, sections, missing_sections, reporting_channel, scorecard,
       security_txt: {present, expired}, injection_suspected}

    When no SECURITY.md exists: present=False, path=None, all sections False, all seven
    keys in missing_sections, reporting_channel="none", scorecard all-false/0,
    injection_suspected=False — but security_txt is STILL filled from any security.txt.
    File content is read utf-8 with errors="replace" and treated as untrusted data.
    """
    root = Path(repo_root)

    md_path = pd.locate_security_md(root)
    if md_path is not None:
        # Capped, untrusted read (F2): bound the SECURITY.md size — unbounded read is a DoS
        # vector on attacker-influenceable content. Single source of truth: pd.read_capped.
        body = pd.read_capped(root / md_path)
        present = True
        sections = detect_sections(body)
        reporting_channel = pd.detect_reporting_channel(body)
        scorecard = scorecard_signals(body)
        inj = injection_suspected(body)
    else:
        present = False
        sections = _empty_sections()
        reporting_channel = "none"
        scorecard = {
            "contact": False,
            "free_form_text": False,
            "specific": False,
            "score": 0,
        }
        inj = False

    missing_sections = [key for key in SECTION_KEYS if not sections[key]]

    txt_path = pd.locate_security_txt(root)
    if txt_path is not None:
        txt_body = pd.read_capped(root / txt_path)  # capped untrusted read (F2)
        security_txt = {
            "present": True,
            "expired": pd.security_txt_expired(txt_body, now=now),
        }
    else:
        security_txt = {"present": False, "expired": None}

    return {
        "present": present,
        "path": md_path,
        "sections": sections,
        "missing_sections": missing_sections,
        "reporting_channel": reporting_channel,
        "scorecard": scorecard,
        "security_txt": security_txt,
        "injection_suspected": inj,
    }


def _load_schema() -> dict:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def validate_gap(report: dict) -> list[str]:
    """Validate `report` against policy_gap_schema.json (Draft 7). Returns [] when valid.

    additionalProperties:false (top level and every nested object) means any raw-body or
    surprise key yields a validation error here.
    """
    schema = _load_schema()
    validator = jsonschema.Draft7Validator(schema)
    return [e.message for e in sorted(validator.iter_errors(report), key=str)]


def main(argv: list[str]) -> int:
    """CLI: print the gap report JSON for the given repo root. Exit 0 on valid, 1 on error.

    Usage: parse_policy.py <repo_root>   (defaults to cwd).
    """
    repo_root = Path(argv[0]) if argv else Path.cwd()
    report = parse_policy(repo_root)
    errors = validate_gap(report)
    if errors:
        print(f"gap-report validation failed: {errors}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
