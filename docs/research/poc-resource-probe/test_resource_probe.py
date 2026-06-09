"""TDD for the throwaway resource-probe PoC (spike wh-bob). Run:
uv run --with pytest pytest docs/research/poc-resource-probe/ -q"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import resource_probe as rp  # noqa: E402


# --- real-host probes: must return sane values on whatever runs this (macOS or Linux CI) ---

def test_cores_positive():
    assert rp.cores() >= 1


def test_load_nonnegative():
    assert rp.load1() >= 0.0


def test_free_mb_sane_or_none():
    fm = rp.free_mb()
    assert fm is None or fm > 0  # never 0 or negative on a real host; None only on an unknown OS


def test_suggested_at_least_one():
    assert rp.suggested_max_parallel() >= 1


def test_probe_shape():
    p = rp.probe()
    assert {"cores", "free_mb", "load1", "suggested_max_parallel", "constants"} <= set(p)


# --- cap formula behaviour (RQ3), via monkeypatched probes — deterministic, host-independent ---

def test_cap_never_exceeds_ceiling(monkeypatch):
    monkeypatch.setattr(rp, "cores", lambda: 64)
    monkeypatch.setattr(rp, "free_mb", lambda: 1_000_000)
    monkeypatch.setattr(rp, "load1", lambda: 0.0)
    assert rp.suggested_max_parallel() == rp.HARD_CEILING  # huge host clamps to the ceiling


def test_cap_drops_to_sequential_under_load(monkeypatch):
    monkeypatch.setattr(rp, "cores", lambda: 8)
    monkeypatch.setattr(rp, "free_mb", lambda: 64_000)
    monkeypatch.setattr(rp, "load1", lambda: 9.0)  # load1 >= cores → saturated
    assert rp.suggested_max_parallel() == 1


def test_cap_bounded_by_memory(monkeypatch):
    monkeypatch.setattr(rp, "cores", lambda: 32)  # cores−2 = 30, but memory is the binding limit
    monkeypatch.setattr(rp, "free_mb", lambda: 3 * rp.SUBAGENT_MB)  # exactly 3 subagents fit
    monkeypatch.setattr(rp, "load1", lambda: 0.0)
    assert rp.suggested_max_parallel() == 3


def test_cap_bounded_by_cores(monkeypatch):
    monkeypatch.setattr(rp, "cores", lambda: 4)  # 4−2 = 2, the binding limit
    monkeypatch.setattr(rp, "free_mb", lambda: 1_000_000)
    monkeypatch.setattr(rp, "load1", lambda: 0.0)
    assert rp.suggested_max_parallel() == 2


def test_unknown_os_skips_memory_divisor(monkeypatch):
    # free_mb=None (unknown OS / unreadable) must NOT crash; cap falls back to cores/ceiling
    monkeypatch.setattr(rp, "cores", lambda: 6)
    monkeypatch.setattr(rp, "free_mb", lambda: None)
    monkeypatch.setattr(rp, "load1", lambda: 0.0)
    assert rp.suggested_max_parallel() == 4  # min(6−2, ceiling) with no memory bound
