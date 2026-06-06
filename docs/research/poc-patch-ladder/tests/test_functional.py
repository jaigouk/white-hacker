"""Existing functional tests — must pass on BOTH the vulnerable and the patched code.

These are the "tests pass" ladder rung: a correct fix must not regress legitimate behavior.
"""
from app.vuln import run_check, run_traceroute


def test_run_check_returns_check_line():
    assert "checking" in run_check("myhost")
    assert "myhost" in run_check("myhost")


def test_run_traceroute_returns_trace_line():
    assert "tracing" in run_traceroute("myhost")
    assert "myhost" in run_traceroute("myhost")
