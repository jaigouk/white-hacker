"""policy_detect (T-11.2): security-policy DETECTION primitives (stdlib only).

Detects whether a repo ships a coordinated-disclosure policy (a SECURITY.md and/or an
RFC 9116 security.txt) and extracts a few structural facts: the reporting channel, a
"Supported Versions" section, a numeric disclosure window, and security.txt expiry.

SECURITY POSTURE — every byte read here is UNTRUSTED DATA. A SECURITY.md / security.txt
lives in the repo under review and may contain prompt-injection payloads aimed at the
white-hacker agent (Agents Rule of Two: never simultaneously hold untrusted input +
secrets + egress). This module therefore:
  * uses regex / structural matching ONLY — it never executes, evals, or "follows" file
    content, and it never imports/derives behavior from it;
  * returns ONLY booleans, a closed enum, and the repo-relative path string — never any
    span of the file body — so injected directive text cannot flow downstream into a
    SessionStart additionalContext or any decision-maker's view.

stdlib only: re, pathlib, datetime.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

# Candidate locations, in precedence order (first existing wins). GitHub renders any of
# the SECURITY.md locations; .well-known/security.txt is the RFC 9116 canonical location.
SECURITY_MD_PATHS = (".github/SECURITY.md", "SECURITY.md", "docs/SECURITY.md")
SECURITY_TXT_PATHS = (".well-known/security.txt", "security.txt")

# --- reporting-channel signals -----------------------------------------------
# GitHub private vulnerability reporting (PVR): the draft-advisory endpoint, or the
# canonical phrases GitHub / advisories use.
_PVR_RE = re.compile(
    r"/security/advisories/new"
    r"|private\s+vulnerability\s+reporting"
    r"|report\s+a\s+vulnerability",
    re.IGNORECASE,
)
# A mailto: link or a bare email address (kept deliberately simple — we only need a
# boolean "is there a contact email", not RFC-5322 completeness).
# ReDoS-hardened: the domain is a first label followed by 1..N dotted labels, and EVERY
# run is BOUNDED (RFC limits: local<=64, label<=63). The `.` is never inside the same
# *unbounded* repeated class that also feeds the literal `\.` delimiter — that ambiguity,
# plus unbounded greedy runs over a long input, is what causes catastrophic backtracking
# on adversarial bodies. Bounded quantifiers keep matching linear (verified by the no-ReDoS
# tests) while still detecting every real contact address.
_MAILTO_RE = re.compile(r"mailto:", re.IGNORECASE)
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}"
)
# Any http(s) link — a plausible reporting portal when nothing more specific is present.
_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)

# A markdown heading "Supported Versions" (any heading level, any case).
_SUPPORTED_VERSIONS_RE = re.compile(r"(?im)^#{1,6}\s*supported versions\b")

# A numeric disclosure window: "90 days", "5 business days", "48 hours".
_TIMELINE_RE = re.compile(r"(?i)\b\d+\s*(business\s+)?(day|days|hours)\b")

# An RFC 9116 "Expires:" field carrying an RFC3339/ISO-8601 timestamp.
_EXPIRES_RE = re.compile(r"(?im)^\s*Expires\s*:\s*(\S+)\s*$")


# Default read cap for untrusted policy files: 256 KiB. A SECURITY.md / security.txt is a
# short human-authored document; a multi-MB file is either a mistake or a DoS attempt, so we
# bound the read rather than slurp an unbounded attacker-controlled file into memory.
_READ_LIMIT = 262_144


def read_capped(path, limit: int = _READ_LIMIT) -> str:
    """Read at most `limit` bytes of `path` as UNTRUSTED utf-8 text (errors='replace').

    A SECURITY.md / security.txt lives in the repo under review and is attacker-influenceable,
    unbounded data. Reading the whole file (read_text) is a memory-exhaustion / DoS vector,
    so we read at most `limit` BYTES and decode with errors='replace' (never crash). The
    returned char count is <= `limit` (utf-8 decoding never grows the byte count).
    """
    with open(path, "rb") as f:
        raw = f.read(limit)
    return raw.decode("utf-8", errors="replace")


def _read_text(p: Path) -> str:
    """Read file content as UNTRUSTED data — capped, utf-8, errors='replace' (never crash)."""
    return read_capped(p)


def locate_security_md(repo_root) -> str | None:
    """Return the first existing SECURITY.md as a repo-relative path string, else None.

    Precedence follows SECURITY_MD_PATHS list order (.github > root > docs).
    """
    root = Path(repo_root)
    for rel in SECURITY_MD_PATHS:
        if (root / rel).is_file():
            return rel
    return None


def locate_security_txt(repo_root) -> str | None:
    """Return the first existing security.txt as a repo-relative path string, else None.

    Precedence follows SECURITY_TXT_PATHS list order (.well-known > root).
    """
    root = Path(repo_root)
    for rel in SECURITY_TXT_PATHS:
        if (root / rel).is_file():
            return rel
    return None


def detect_reporting_channel(text: str) -> str:
    """Classify the reporting channel referenced in `text` (structural match only).

    Returns one of "github-pvr" | "email" | "url" | "none", checked in that precedence:
      * "github-pvr" — references GitHub private vulnerability reporting;
      * "email"      — a mailto: link or a bare email address;
      * "url"        — any http(s) link (a plausible reporting portal);
      * "none"       — no channel signal found.
    """
    if _PVR_RE.search(text):
        return "github-pvr"
    if _MAILTO_RE.search(text) or _EMAIL_RE.search(text):
        return "email"
    if _URL_RE.search(text):
        return "url"
    return "none"


def has_supported_versions(text: str) -> bool:
    """True when `text` has a markdown heading "Supported Versions" (any level/case)."""
    return bool(_SUPPORTED_VERSIONS_RE.search(text))


def has_disclosure_timeline(text: str) -> bool:
    """True when `text` states a numeric time window (a coordinated-disclosure SLA)."""
    return bool(_TIMELINE_RE.search(text))


def security_txt_expired(text: str, now=None) -> bool | None:
    """Evaluate an RFC 9116 security.txt "Expires:" field against `now`.

    Returns True when the policy has expired (expires < now), False when still valid
    (expires >= now), and None when no Expires field is present or it cannot be parsed.

    `now` defaults to datetime.now(timezone.utc); callers (and all tests) SHOULD pass a
    fixed `now` for determinism.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    m = _EXPIRES_RE.search(text)
    if not m:
        return None
    raw = m.group(1).strip()
    # Python's fromisoformat handles "...Z" since 3.11; normalize defensively for safety.
    candidate = raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
    try:
        expires = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    # Treat a naive timestamp as UTC so the comparison is always tz-aware.
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires < now


def security_policy_facts(repo_root, now=None) -> dict:
    """Assemble the security-policy fact block for `repo_root` (exact schema shape).

    Returns exactly:
      {present, path, reporting_channel, supported_versions_present,
       disclosure_timeline_present, security_txt_present, security_txt_expired}

    All file content is read as untrusted data; only booleans, the reporting_channel
    enum, and the repo-relative path string are returned — never any file body span.
    """
    root = Path(repo_root)

    md_path = locate_security_md(root)
    if md_path is not None:
        body = _read_text(root / md_path)
        present = True
        reporting_channel = detect_reporting_channel(body)
        supported_versions_present = has_supported_versions(body)
        disclosure_timeline_present = has_disclosure_timeline(body)
    else:
        present = False
        reporting_channel = "none"
        supported_versions_present = False
        disclosure_timeline_present = False

    txt_path = locate_security_txt(root)
    if txt_path is not None:
        txt_body = _read_text(root / txt_path)
        security_txt_present = True
        txt_expired = security_txt_expired(txt_body, now=now)
    else:
        security_txt_present = False
        txt_expired = None

    return {
        "present": present,
        "path": md_path,
        "reporting_channel": reporting_channel,
        "supported_versions_present": supported_versions_present,
        "disclosure_timeline_present": disclosure_timeline_present,
        "security_txt_present": security_txt_present,
        "security_txt_expired": txt_expired,
    }
