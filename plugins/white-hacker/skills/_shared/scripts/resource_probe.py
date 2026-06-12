"""Stdlib-only host probe + concurrency cap (ADR-023).

Returns a reliable `suggested_max_parallel` so the agent caps concurrency instead of guessing
from inline shell heuristics. Zero third-party imports (ADR-021 zero-dep vendor; ADR-015 stdlib
floor): cores + load come from `os`; only free-mem needs ONE thin per-OS read.

- cores: Linux `os.sched_getaffinity(0)` (cgroup/affinity-aware → container-correct), else
  `os.cpu_count()`. load: `os.getloadavg()` (macOS + Linux). free-mem: Linux `/proc/meminfo`
  **MemAvailable** (counts reclaimable page cache, unlike MemFree); macOS `vm_stat` available proxy.
- cap (RQ3) = `min(cores − HEADROOM, free_mb ÷ SUBAGENT_MB, HARD_CEILING)`, clamped ≥1; drops to 1
  (SEQUENTIAL) when `load1 ≥ cores`. Constants are env-overridable.
- Degradation (ADR-003): an unknown OS / unreadable probe returns `free_mb=None` → the memory
  divisor is skipped (cap falls back to cores/ceiling), never raises (no ZeroDivisionError).
"""
from __future__ import annotations

import os
import platform
import re
import subprocess

HEADROOM = int(os.environ.get("WH_CAP_HEADROOM", "2"))        # cores reserved for the OS + main loop
HARD_CEILING = int(os.environ.get("WH_CAP_CEILING", "8"))     # never exceed, even on a huge host
SUBAGENT_MB = int(os.environ.get("WH_SUBAGENT_MB", "1536"))   # est. RAM per heavy LLM subagent (divisor)


def cores() -> int:
    try:
        return len(os.sched_getaffinity(0))  # Linux: respects cgroup/affinity (container-correct)
    except AttributeError:
        return os.cpu_count() or 1


def load1() -> float:
    try:
        return os.getloadavg()[0]  # macOS + Linux
    except (OSError, AttributeError):
        return 0.0


def free_mb() -> int | None:
    system = platform.system()
    if system == "Linux":
        return _linux_mem_available_mb()
    if system == "Darwin":
        return _macos_available_mb()
    return None  # unknown OS → skip the memory divisor (degrade, don't block)


def _linux_mem_available_mb() -> int | None:
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):  # reclaimable cache included (unlike MemFree)
                    return int(line.split()[1]) // 1024  # kB → MB
    except OSError:
        return None
    return None


def _macos_available_mb() -> int | None:
    try:
        out = subprocess.run(["vm_stat"], capture_output=True, text=True, timeout=2).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    page = 4096
    m = re.search(r"page size of (\d+) bytes", out)
    if m:
        page = int(m.group(1))

    def pages(label: str) -> int:
        mm = re.search(rf"{re.escape(label)}:\s+(\d+)\.", out)
        return int(mm.group(1)) if mm else 0

    # "available" proxy = reclaimable pages (free + inactive + speculative + purgeable)
    avail = pages("Pages free") + pages("Pages inactive") + pages("Pages speculative") + pages("Pages purgeable")
    return (avail * page) // (1024 * 1024)


def suggested_max_parallel() -> int:
    c = cores()
    cap = max(1, c - HEADROOM)
    fm = free_mb()
    if fm is not None:
        cap = min(cap, max(1, fm // SUBAGENT_MB))
    cap = min(cap, HARD_CEILING)
    if load1() >= c:  # host already saturated → sequential
        cap = 1
    return max(1, cap)


def probe() -> dict:
    return {
        "cores": cores(),
        "free_mb": free_mb(),
        "load1": round(load1(), 2),
        "suggested_max_parallel": suggested_max_parallel(),
        "constants": {"headroom": HEADROOM, "ceiling": HARD_CEILING, "subagent_mb": SUBAGENT_MB},
    }
