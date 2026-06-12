"""MONITOR staleness threshold rule (wh-hxt.18) — the §2 rule of
docs/research/20260612_staleness_signal.md as a pure function. NO network.

Computes a *staleness verdict* per tool from GitHub-API fields (release age, archived/disabled,
last commit, EOL/feature-complete). Deterministic (Policy 5): a total function of dates/flags +
an injected `now` — no LLM, no RNG, no `date.today()` in the pure path. This is the core a future
`parse_staleness` parser wraps into `poll_feeds.py` PARSERS (poll_feeds.py:69); the live fetch /
state diff / draft-PR render stay wh-5es's plumbing (NOT implemented here). Human-gated swaps only
(ADR-012): a non-`fresh` verdict becomes a proposal a human applies, never an auto-swap.
"""
from __future__ import annotations

import datetime as _dt
import json

# Cadence thresholds (whole days). Starting constants — tune via this DATA, never the rule body
# (Open/Closed). Rationale: docs/research/20260612_staleness_signal.md §2.
WATCH_DAYS = 365   # >= this, no release AND no commit -> aging (MEDIUM: watch)
STALE_DAYS = 540   # >= this -> stale (HIGH: propose a DIVERSIFY/RETIRE review)  (~18 months)

# status -> severity. severity is a PURE function of status, never an independent input, so the
# two can never disagree (docs/research/20260612_staleness_signal.md §3).
SEVERITY_BY_STATUS = {
    "fresh": "none",
    "aging": "medium",
    "stale": "high",
    "archived": "immediate",
    "eol": "immediate",   # default; feature_complete overrides to "info" at the call site
    "unknown": "info",
}


def _severity(status: str) -> str:
    return SEVERITY_BY_STATUS[status]


def _to_date(ts: str | None) -> _dt.date | None:
    """ISO-8601 timestamp/date -> date. 'T...Z' is truncated to the date. None/'' -> None."""
    if not ts:
        return None
    return _dt.date.fromisoformat(ts[:10])


def is_stale(
    *,
    tool: str,
    published_at: str | None,
    pushed_at: str | None,
    archived: bool = False,
    disabled: bool = False,
    feature_complete: bool = False,
    eol_date: str | None = None,
    now: str,
) -> dict:
    """Return one staleness verdict (the §2 ordered rule, first match wins).

    age basis = the MORE-RECENT of published_at / pushed_at (a live repo with a slow release
    cadence but recent commits is fresh). Degrade-never-raise (ADR-003): missing/null timestamps
    fall back or yield status 'unknown'; this never raises on absent fields.
    """
    now_d = _dt.date.fromisoformat(now)

    # 1. archived / disabled -> IMMEDIATE, regardless of age.
    if archived or disabled:
        signal = "archived" if archived else "disabled"
        return _verdict(tool, "archived", signal, _age_days(published_at, pushed_at, now_d),
                        _basis(published_at, pushed_at), now)

    # 2. EOL date reached -> IMMEDIATE.
    eol_d = _to_date(eol_date)
    if eol_d is not None and now_d >= eol_d:
        return _verdict(tool, "eol", "eol", _age_days(published_at, pushed_at, now_d),
                        _basis(published_at, pushed_at), now)

    # 3. feature_complete -> EOL/INFO; the cadence rule is SKIPPED (a long gap is expected).
    if feature_complete:
        v = _verdict(tool, "eol", "feature_complete", _age_days(published_at, pushed_at, now_d),
                     _basis(published_at, pushed_at), now)
        v["severity"] = "info"   # declared posture, not decay -> informational, not "act now"
        return v

    age = _age_days(published_at, pushed_at, now_d)
    basis = _basis(published_at, pushed_at)

    # 6. no timestamps at all (404 latest_release + no pushed_at) -> unknown. (Checked before the
    #    cadence rules: absence of data is not freshness, and age is None.)
    if age is None:
        return _verdict(tool, "unknown", "none", None, None, now)

    # 4 / 5. cadence.
    if age >= STALE_DAYS:
        return _verdict(tool, "stale", _release_signal(basis), age, basis, now)
    if age >= WATCH_DAYS:
        return _verdict(tool, "aging", _release_signal(basis), age, basis, now)

    # 7. fresh.
    return _verdict(tool, "fresh", "none", age, basis, now)


def _basis(published_at: str | None, pushed_at: str | None) -> str | None:
    """Which timestamp the age is computed from: the MORE-RECENT of the two (None if both absent)."""
    pub, push = _to_date(published_at), _to_date(pushed_at)
    if pub is None and push is None:
        return None
    if push is None:
        return "published_at"
    if pub is None:
        return "pushed_at"
    return "pushed_at" if push >= pub else "published_at"


def _age_days(published_at: str | None, pushed_at: str | None, now_d: _dt.date) -> int | None:
    pub, push = _to_date(published_at), _to_date(pushed_at)
    most_recent = max([d for d in (pub, push) if d is not None], default=None)
    if most_recent is None:
        return None
    # Clamp to 0: GitHub clock skew can yield a future timestamp -> a negative delta. A future
    # release/commit is "fresh" (age 0), never negative (QA Finding 2).
    return max(0, (now_d - most_recent).days)


def _release_signal(basis: str | None) -> str:
    return "last_commit" if basis == "pushed_at" else "release_age"


def _verdict(tool: str, status: str, signal: str, age_days: int | None,
             basis: str | None, checked: str) -> dict:
    return {
        "tool": tool,
        "status": status,
        "signal": signal,
        "age_days": age_days,
        "severity": _severity(status),
        "basis": basis,
        "checked": checked,
    }


def parse_github_json(raw_github_json: str, *, now: str) -> list[dict]:
    """PARSERS-shaped entry point: recorded GitHub REST JSON -> list[verdict]. NO network.

    `raw_github_json` is the already-fetched `repos/{owner}/{repo}` object (the fetch is wh-5es's
    egress-confined plumbing), optionally with the `releases/latest` object merged under a
    `latest_release` key. Mirrors poll_feeds.py parse_* (raw str in, list[dict] out). One object
    -> one verdict; a JSON array -> one verdict per element. Degrade-never-raise: a missing
    `latest_release` (404) or absent field yields a verdict, never an exception.

    CONTRACT CAVEAT (QA Gap C) — the verdict uses `tool` as its stable diff key; it has NO `id`
    key. poll_feeds.py poll() (:72-79) dedups items by `it["id"]`, so registering this parser into
    PARSERS as-is would raise KeyError: 'id'. Before wiring it in, wh-5es's plumbing MUST either add
    an `id` alias (`verdict["id"] = verdict["tool"]`) or extend poll() to key off `tool`. This stays
    a DEFINITION here — implementing that wiring is wh-5es's scope, not this module's.
    """
    data = json.loads(raw_github_json)
    repos = data if isinstance(data, list) else [data]
    out = []
    for repo in repos:
        rel = repo.get("latest_release") or {}
        out.append(is_stale(
            tool=repo.get("full_name") or repo.get("tool") or "?",
            published_at=rel.get("published_at"),
            pushed_at=repo.get("pushed_at"),
            archived=bool(repo.get("archived")),
            disabled=bool(repo.get("disabled")),
            feature_complete=bool(repo.get("feature_complete")),
            eol_date=repo.get("eol_date"),
            now=now,
        ))
    return out
