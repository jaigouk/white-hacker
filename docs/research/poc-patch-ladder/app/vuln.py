"""Planted-vuln fixture for the sec-patch patch-ladder demo (poc-patch-ladder).

VULN (command injection): a user-controlled `host` is interpolated into a shell command run
with `shell=True`. There are TWO sinks of the same class — `run_check` and `run_traceroute` —
so the variant hunt must find the sibling, not just the first.

Offline + deterministic: uses `echo` (no network), and the PoC uses a benign `echo PWNED`
marker — no real exploit payload. NOT a runnable service.
"""
import subprocess


def run_check(host: str) -> str:
    """Return a check line for `host`. VULN: `host` is interpolated into a shell string."""
    return subprocess.run(
        f"echo checking {host}", shell=True, capture_output=True, text=True
    ).stdout


def run_traceroute(host: str) -> str:
    """Sibling sink (same class) — the variant hunt must catch this one too."""
    return subprocess.run(
        f"echo tracing {host}", shell=True, capture_output=True, text=True
    ).stdout
