"""Tests for the MONITOR staleness threshold rule (wh-hxt.18, TDD). Pure — no network.

The verdict is a total function of (published_at|pushed_at, archived, disabled, feature_complete,
eol_date, now) — see docs/research/20260612_staleness_signal.md §2. Every invariant is pinned BOTH
directions (== the right status AND != a wrong one) per Policy 9.

Run: uv run --project plugins/white-hacker/skills/sec-kb-refresh/scripts --with pytest \
       pytest plugins/white-hacker/skills/sec-kb-refresh/scripts/tests -q
"""
from __future__ import annotations

import staleness as st

NOW = "2026-06-12"


def _v(**kw):
    """is_stale with sensible defaults; override per case."""
    base = dict(tool="owner/repo", published_at=None, pushed_at=None, archived=False,
                disabled=False, feature_complete=False, eol_date=None, now=NOW)
    base.update(kw)
    return st.is_stale(**base)


# --- rule 1: archived / disabled -> IMMEDIATE, regardless of age -------------
def test_archived_is_immediate_even_when_recently_released():
    # A repo released yesterday but archived today is STILL archived (rule 1 beats age).
    v = _v(published_at="2026-06-11", archived=True)
    assert v["status"] == "archived"          # == the right verdict
    assert v["status"] != "fresh"             # != the wrong one (recent release must NOT win)
    assert v["severity"] == "immediate"
    assert v["signal"] == "archived"


def test_disabled_is_immediate():
    v = _v(pushed_at="2026-06-10", disabled=True)
    assert v["status"] == "archived" and v["severity"] == "immediate"
    assert v["signal"] == "disabled"


# --- rule 2 / 3: EOL date and feature_complete ------------------------------
def test_eol_date_passed_is_immediate():
    v = _v(published_at="2026-06-01", eol_date="2026-06-01")   # now >= eol_date
    assert v["status"] == "eol" and v["severity"] == "immediate"
    assert v["status"] != "fresh"


def test_eol_date_future_does_not_fire():
    v = _v(published_at="2026-06-10", eol_date="2099-01-01")   # eol in the future
    assert v["status"] == "fresh"             # not yet EOL
    assert v["status"] != "eol"


def test_feature_complete_is_eol_info_and_skips_cadence():
    # Old release (>STALE_DAYS) BUT feature_complete -> eol/INFO, NOT stale (the gitleaks case).
    v = _v(published_at="2023-01-01", feature_complete=True)
    assert v["status"] == "eol"               # == declared posture
    assert v["status"] != "stale"             # != the cadence verdict it must suppress
    assert v["severity"] == "info"
    assert v["signal"] == "feature_complete"


# --- rule 4 / 5: cadence thresholds (release age) ---------------------------
def test_stale_when_past_stale_days():
    # ~2 years old, no commit -> stale/HIGH.
    v = _v(published_at="2024-06-01")
    assert v["age_days"] >= st.STALE_DAYS
    assert v["status"] == "stale" and v["severity"] == "high"
    assert v["status"] != "aging" and v["status"] != "fresh"


def test_aging_between_watch_and_stale():
    # ~400 days old: past WATCH_DAYS (365) but under STALE_DAYS (540) -> aging/MEDIUM.
    v = _v(published_at="2025-05-08")
    assert st.WATCH_DAYS <= v["age_days"] < st.STALE_DAYS
    assert v["status"] == "aging" and v["severity"] == "medium"
    assert v["status"] != "stale"             # not yet stale
    assert v["status"] != "fresh"             # not fresh either


def test_fresh_when_recent():
    v = _v(published_at="2026-06-01")         # 11 days old
    assert v["age_days"] == 11
    assert v["status"] == "fresh" and v["severity"] == "none"
    assert v["status"] != "aging" and v["status"] != "stale"


def test_future_timestamp_clamps_age_to_zero():
    # GitHub clock skew can yield a future published_at/pushed_at. Age must clamp to 0,
    # never go negative (QA Finding 2). A future timestamp is still "fresh".
    v = _v(published_at="2026-06-15")         # 3 days in the FUTURE relative to NOW (2026-06-12)
    assert v["age_days"] == 0                  # == clamped to 0
    assert v["age_days"] != -3                 # != the raw negative delta
    assert v["age_days"] >= 0                  # never negative
    assert v["status"] == "fresh" and v["severity"] == "none"


def test_threshold_boundary_is_inclusive_at_watch_days():
    # Exactly WATCH_DAYS old -> aging (>= is inclusive); one day younger -> fresh.
    import datetime as dt
    at_watch = (dt.date.fromisoformat(NOW) - dt.timedelta(days=st.WATCH_DAYS)).isoformat()
    below = (dt.date.fromisoformat(NOW) - dt.timedelta(days=st.WATCH_DAYS - 1)).isoformat()
    assert _v(published_at=at_watch)["status"] == "aging"
    assert _v(published_at=below)["status"] == "fresh"


# --- basis selection: more-recent of published_at / pushed_at ---------------
def test_recent_commit_keeps_old_release_fresh():
    # Release is 2 years old (would be stale) BUT pushed_at is recent -> fresh (live project).
    v = _v(published_at="2024-06-01", pushed_at="2026-06-05")
    assert v["status"] == "fresh"             # the recent commit wins
    assert v["status"] != "stale"
    assert v["basis"] == "pushed_at"          # age computed from the more-recent field
    assert v["age_days"] == 7


def test_release_basis_when_release_is_more_recent():
    v = _v(published_at="2026-06-05", pushed_at="2024-06-01")
    assert v["basis"] == "published_at" and v["age_days"] == 7
    assert v["status"] == "fresh"


# --- rule 6: unknown when no timestamps (404 latest_release + no pushed_at) --
def test_unknown_when_no_timestamps():
    v = _v(published_at=None, pushed_at=None)
    assert v["status"] == "unknown" and v["severity"] == "info"
    assert v["age_days"] is None              # cannot compute age
    assert v["basis"] is None
    assert v["status"] != "fresh"             # absence of data is NOT freshness


# --- degrade-never-raise: a null published_at falls back to pushed_at --------
def test_null_published_falls_back_to_pushed_at():
    v = _v(published_at=None, pushed_at="2026-06-05")
    assert v["basis"] == "pushed_at" and v["age_days"] == 7
    assert v["status"] == "fresh"


# --- output shape: closed-enum status + severity is a pure function of it ----
def test_verdict_shape_and_severity_maps_from_status():
    v = _v(published_at="2026-06-01")
    assert set(v.keys()) == {"tool", "status", "signal", "age_days", "severity", "basis", "checked"}
    assert v["tool"] == "owner/repo"
    assert v["checked"] == NOW
    # severity is derived from status, never an independent input -> they cannot disagree.
    for status, sev in st.SEVERITY_BY_STATUS.items():
        assert st._severity(status) == sev


def test_status_is_a_closed_enum():
    assert set(st.SEVERITY_BY_STATUS) == {
        "fresh", "aging", "stale", "archived", "eol", "unknown",
    }


# --- parse_github_json: the PARSERS-shaped entry point (recorded JSON, no net) -
def test_parse_github_json_merged_repo_and_release():
    import json
    raw = json.dumps({
        "full_name": "owner/repo",
        "archived": False,
        "disabled": False,
        "pushed_at": "2024-06-01T00:00:00Z",
        "latest_release": {"published_at": "2024-06-01T00:00:00Z"},
    })
    verdicts = st.parse_github_json(raw, now=NOW)
    assert len(verdicts) == 1
    assert verdicts[0]["tool"] == "owner/repo"
    assert verdicts[0]["status"] == "stale"   # 2-year-old release, no recent commit


def test_parse_github_json_archived_repo_without_release():
    import json
    raw = json.dumps({"full_name": "owner/dead", "archived": True,
                      "pushed_at": "2025-01-01T00:00:00Z"})   # no latest_release key (404)
    v = st.parse_github_json(raw, now=NOW)[0]
    assert v["status"] == "archived"          # archived wins; missing release must NOT raise
    assert v["tool"] == "owner/dead"


def test_parse_github_json_strips_timestamp_to_date():
    import json
    raw = json.dumps({"full_name": "o/r", "pushed_at": "2026-06-05T13:22:09Z"})
    v = st.parse_github_json(raw, now=NOW)[0]
    assert v["basis"] == "pushed_at" and v["age_days"] == 7   # 'T...Z' truncated to the date


# --- wh-fpy: degrade-never-raise on MALFORMED / hostile GitHub-API JSON --------
# The module's :58-59/:145 docstrings promise the parser NEVER raises on untrusted
# remote JSON. Each class of malformed input degrades (-> [] or a verdict), never
# raising JSONDecodeError / AttributeError / ValueError / RecursionError. Pinned
# both ways (Policy 9): malformed degrades AND a WELL-FORMED response is UNCHANGED.

def test_parse_github_json_invalid_json_returns_empty():
    # Malformed/truncated JSON must degrade to [], not raise JSONDecodeError (:154).
    assert st.parse_github_json("{bad", now=NOW) == []
    assert st.parse_github_json("", now=NOW) == []


def test_parse_github_json_array_of_non_dicts_returns_empty():
    # A JSON array of non-dicts must skip each element (no .get on an int) -> [].
    assert st.parse_github_json("[1, 2, 3]", now=NOW) == []
    assert st.parse_github_json('["a", "b"]', now=NOW) == []


def test_parse_github_json_bare_scalar_returns_empty():
    # A bare scalar (number / string) is not a dict -> skipped -> [].
    assert st.parse_github_json("5", now=NOW) == []
    assert st.parse_github_json('"x"', now=NOW) == []


def test_parse_github_json_garbage_timestamp_yields_verdict_not_raise():
    # A present-but-garbage timestamp must NOT raise ValueError; it degrades to
    # absent -> the verdict still resolves (here: unknown, since no usable date).
    import json
    raw = json.dumps({"full_name": "o/r", "published_at": "not-a-date"})
    v = st.parse_github_json(raw, now=NOW)
    assert len(v) == 1
    assert v[0]["status"] == "unknown"      # garbage date -> no usable timestamp
    assert v[0]["status"] != "fresh"        # garbage is NOT treated as recent


def test_parse_github_json_non_dict_latest_release_yields_verdict():
    # latest_release that is a string (e.g. a 404 body) must NOT raise AttributeError;
    # it degrades to {} and the repo's own pushed_at drives the verdict.
    import json
    raw = json.dumps({"full_name": "o/r", "latest_release": "oops",
                      "pushed_at": "2026-06-01T00:00:00Z"})
    v = st.parse_github_json(raw, now=NOW)
    assert len(v) == 1
    assert v[0]["status"] == "fresh"        # pushed 11 days ago drives it; release ignored
    assert v[0]["basis"] == "pushed_at"


def test_parse_github_json_deep_nested_returns_empty():
    # Deeply-nested JSON must degrade (RecursionError caught), never crash the parser.
    bomb = "[" * 20000 + "]" * 20000
    assert st.parse_github_json(bomb, now=NOW) == []


def test_parse_github_json_array_mixes_valid_and_invalid_elements():
    # An array with a valid dict next to a non-dict: the valid one yields a verdict,
    # the junk is skipped (both ways: the good survives AND the bad does not raise).
    import json
    raw = json.dumps([{"full_name": "o/r", "pushed_at": "2026-06-01T00:00:00Z"}, 42])
    v = st.parse_github_json(raw, now=NOW)
    assert len(v) == 1                      # the int element is dropped, not fatal
    assert v[0]["tool"] == "o/r" and v[0]["status"] == "fresh"


def test_to_date_degrades_on_garbage_and_non_str():
    import datetime as dt
    # Garbage / non-str inputs degrade to None instead of raising ValueError/TypeError.
    assert st._to_date("not-a-date") is None
    assert st._to_date(123) is None         # non-str (an int field) -> None, not TypeError
    assert st._to_date(None) is None
    assert st._to_date("") is None
    # ... but a WELL-FORMED date is UNCHANGED (the surgical guarantee, Policy 9).
    assert st._to_date("2026-06-01") == dt.date(2026, 6, 1)
    assert st._to_date("2026-06-05T13:22:09Z") == dt.date(2026, 6, 5)


def test_parse_github_json_well_formed_unchanged_after_hardening():
    # Regression pin: the hardening must NOT change well-formed behavior.
    import json
    archived = json.dumps({"full_name": "owner/dead", "archived": True,
                           "pushed_at": "2025-01-01T00:00:00Z"})
    assert st.parse_github_json(archived, now=NOW)[0]["status"] == "archived"
    fresh = json.dumps({"full_name": "o/r", "pushed_at": "2026-06-01T00:00:00Z"})
    assert st.parse_github_json(fresh, now=NOW)[0]["status"] == "fresh"
