"""Tests for the stdlib host-probe + concurrency cap (resource_probe.py, ADR-023).

The cap formula (RQ3) is `min(cores − HEADROOM, free_mb ÷ SUBAGENT_MB, HARD_CEILING)`, clamped ≥1,
dropping to 1 (sequential) when `load1 ≥ cores`. Real-host probes must return sane values on whatever
runs this (macOS or Linux CI); the formula behaviour is pinned deterministically via monkeypatch.
Each invariant pins BOTH `== expected` AND `!= wrong` (Policy 9).

Run: `uv run --project plugins/white-hacker/skills/_shared/scripts --with pytest \
      pytest plugins/white-hacker/skills/_shared/scripts/tests/test_resource_probe.py`
"""
from __future__ import annotations

import resource_probe as rp


# --- real-host probes: sane values on whatever runs this (macOS or Linux CI) ---
def test_cores_positive():
    c = rp.cores()
    assert c >= 1       # a real host always has at least one core


def test_load_nonneg():
    load = rp.load1()
    assert load >= 0.0  # load average is never negative


def test_free_mb_sane_or_none():
    fm = rp.free_mb()
    assert fm is None or fm > 0      # None only on an unknown OS; never 0/negative on a real host
    assert fm != 0                   # 0 would wrongly force the memory divisor to 1
    assert not isinstance(fm, str)   # a number or None, never a raw string


def test_suggested_at_least_one():
    s = rp.suggested_max_parallel()
    assert s >= 1       # always at least sequential


def test_probe_shape():
    p = rp.probe()
    assert set(p) == {"cores", "load1", "free_mb", "suggested_max_parallel", "constants"}
    assert set(p) != {"cores", "load1", "free_mb"}  # not a partial/legacy shape


# --- cap formula behaviour (RQ3), via monkeypatched probes — deterministic, host-independent ---
def test_cap_never_exceeds_ceiling(monkeypatch):
    monkeypatch.setattr(rp, "cores", lambda: 100)
    monkeypatch.setattr(rp, "free_mb", lambda: 100 * rp.SUBAGENT_MB)  # memory not the binding limit
    monkeypatch.setattr(rp, "load1", lambda: 0.0)
    cap = rp.suggested_max_parallel()
    assert cap == rp.HARD_CEILING       # a huge host clamps to the ceiling
    assert cap != 100 - rp.HEADROOM     # NOT the (much larger) core-based bound


def test_cap_drops_to_sequential_under_load(monkeypatch):
    monkeypatch.setattr(rp, "cores", lambda: 8)
    monkeypatch.setattr(rp, "free_mb", lambda: 64_000)
    monkeypatch.setattr(rp, "load1", lambda: 9.0)  # load1 >= cores → saturated
    cap = rp.suggested_max_parallel()
    assert cap == 1                     # saturated host → sequential
    assert cap != 8 - rp.HEADROOM       # NOT the unsaturated core-based bound


def test_cap_bounded_by_memory(monkeypatch):
    monkeypatch.setattr(rp, "cores", lambda: 8)           # 8−2 = 6, but memory binds tighter
    monkeypatch.setattr(rp, "free_mb", lambda: rp.SUBAGENT_MB * 2)  # exactly 2 subagents fit
    monkeypatch.setattr(rp, "load1", lambda: 0.0)
    cap = rp.suggested_max_parallel()
    assert cap <= 2                     # memory is the binding limit
    assert cap == 2                     # exactly 2 fit
    assert cap != 8 - rp.HEADROOM       # NOT the (looser) core bound of 6


def test_cap_bounded_by_cores(monkeypatch):
    monkeypatch.setattr(rp, "HEADROOM", 2)
    monkeypatch.setattr(rp, "cores", lambda: 3)           # 3−2 = 1, the binding limit
    monkeypatch.setattr(rp, "free_mb", lambda: 1_000_000)
    monkeypatch.setattr(rp, "load1", lambda: 0.0)
    cap = rp.suggested_max_parallel()
    assert cap <= 1                     # cores−HEADROOM binds
    assert cap == 1


def test_unknown_os_skips_memory_divisor(monkeypatch):
    # free_mb=None (unknown OS / unreadable) must NOT crash; cap falls back to cores/ceiling (ADR-003)
    monkeypatch.setattr(rp, "HEADROOM", 2)
    monkeypatch.setattr(rp, "cores", lambda: 6)
    monkeypatch.setattr(rp, "free_mb", lambda: None)
    monkeypatch.setattr(rp, "load1", lambda: 0.0)
    cap = rp.suggested_max_parallel()   # no ZeroDivisionError on the None path
    assert cap == 4                     # min(6−2, ceiling) with no memory bound
    assert cap != 1                     # NOT wrongly forced sequential by the missing divisor
