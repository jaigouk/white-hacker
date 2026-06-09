# Research: Resource-aware execution — measuring host capacity + capping concurrency (no OOM-freeze)

**Date:** 2026-06-09
**Author:** white-hacker (spike)
**Spike Ticket:** wh-bob
**Status:** Final

## Summary

**GO — build our own stdlib-only `resource_probe.py`** (re-scopes wh-00i); reject psutil (BSD-3, breaks
the zero-dep vendor invariant) and GNU parallel (GPL-3, can't bundle + wrong abstraction). The strong
prior is **confirmed empirically**: a throwaway PoC (`docs/research/poc-resource-probe/`,
stdlib-only, 10 tests green) probes cores + load + free-mem cross-platform with ZERO third-party
imports and computes a safe cap. On this (busy) host it returned `{cores:12, free_mb:10434,
load1:4.65, suggested_max_parallel:6}` — memory-bound at 6, **not** the naive `cores−2 = 10`, which is
exactly the OOM-avoidance the agent md prose asks for. RQ6 (machine-visible schema fields) →
**recommendation: report-only**, do NOT bump the keystone `finding-schema.json` now (separate ticket
only if the eval gate ever needs to consume `mode`).

## Research Question

RQ1 own script vs dep · RQ2 per-OS probe commands · RQ3 cap formula + constants · RQ4 pressure signal
per-OS · RQ5 the four-mode model · RQ6 output-contract (schema-visible vs report-only). See the spike
(wh-bob) for full text.

## Options Considered

| Option | License | Pros | Cons | Verdict |
| --- | --- | --- | --- | --- |
| **Own stdlib `resource_probe.py`** | our code (Apache-2.0) | `os.cpu_count`/`os.sched_getaffinity`/`os.getloadavg` cover cores+load with no shell; only free-mem needs one per-OS read; fits ADR-015 floor + ADR-021 zero-dep vendor + Policy 5; ships in the vendor manifest; **PoC proves it works** | we maintain the macOS free-mem parse; no PSI/Windows | **CHOSEN** |
| psutil dep | **BSD-3** (permissive, *not* MIT/Apache) | one call `virtual_memory().available`; Windows too; v7.2.2 active | **breaks ADR-021** ("vendoring installs ZERO Python packages"); license outside the MIT/Apache rule; overkill for 3 numbers | rejected |
| GNU `parallel --memfree/--load` | **GPL-3** (copyleft) | mature self-cap model; canonical prior art | GPL-3 → cannot bundle; not installed by default (violates ADR-003 "never block"); job-queue, not LLM-subagent orchestration | rejected (prior art only) |
| Behavioral prose only (status quo) | n/a | already shipped; zero code | non-deterministic (agent parses tool text each run — Policy 5 says code answers); "free ≠ available" easy to get wrong by hand | superseded by the helper |

## Per-OS probe commands (RQ2) — all stdlib except the macOS free-mem shell

| Signal | Linux | macOS |
| --- | --- | --- |
| cores | `os.sched_getaffinity(0)` (cgroup/affinity-aware → container-correct) | `os.cpu_count()` |
| free  | `/proc/meminfo` **MemAvailable** (reclaimable cache; NOT MemFree) | `vm_stat` → (free+inactive+speculative+purgeable)×page |
| load  | `os.getloadavg()[0]` | `os.getloadavg()[0]` |
| pressure (future) | cgroup v2 `memory.pressure` (PSI) — Linux-only, **deferred** | `memory_pressure` — **deferred** |

## Decisions

**RQ3 — cap formula + constants (validated by PoC).**
`suggested_max_parallel = clamp≥1( min(cores − HEADROOM, free_mb ÷ SUBAGENT_MB, HARD_CEILING) )`, and
**drop to 1 (SEQUENTIAL) when `load1 ≥ cores`** (host already saturated). Constants, env-overridable:
`HEADROOM=2` (reserve OS + main loop), `HARD_CEILING=8` (conservative for *heavy LLM subagents*; below
the `min(16, cores−2)` batch norm because each subagent is heavy), `SUBAGENT_MB=1536` (est. RAM per
heavy LLM subagent — the dominant fan-out cost, hence the divisor). On-host check: `min(10, 6, 8)=6`.

**RQ4 — pressure signal.** Use **MemAvailable/vm_stat (memory) + `load1` (saturation)** as the single
cross-platform pair. **PSI is deferred** (Linux-only → breaks cross-platform symmetry, adds a code
path; MemAvailable+load is sufficient for OOM-avoidance — Policy 2). Revisit PSI only if real OOMs slip
past MemAvailable. Note: `load1` is a *lagging* signal (GNU parallel rejects it as a primary gate), so
it is the **saturation backstop**, not the primary cap — memory is the primary divisor.

**RQ5 — modes (locked).** Four, as already in agent md § "Execution budget"; the probe *bounds*
whichever runs, it does not select it: **ESSENTIALS/pre-commit** (secrets + diff high-yield, sequential)
· **CRITICAL-ONLY** (high-severity, bounded-parallel) · **FULL** (whole loop, cap-bounded) · **DEFERRED**
(queue heavy for CI/later). Default to the lighter mode when unsure; ask on costly/risky scope.

**RQ6 — output contract → REPORT-ONLY (recommendation).** Do **not** add `mode`/`checks_skipped[]` to
`finding-schema.json` now: it is `additionalProperties:false` (`:7,:12`) and the keystone the eval gate
(`validate_findings.py`, `evals/score.py`) + the (already-stale) baseline validate against — a breaking
bump for human-read resource metadata. Surface resource posture in `SECURITY-REPORT.md` + the existing
`tools_unavailable`-style honesty. A schema bump is a **separate** ticket only if the eval gate ever
needs to consume `mode`.

## Recommendation

**GO with the own stdlib helper.** It is the only option that satisfies all of: MIT/Apache-only bundling
(our Apache-2.0 code), ADR-021 zero-dep vendor, ADR-015 stdlib floor, ADR-003 graceful degradation
(unknown OS → `free_mb=None` → memory divisor skipped, never blocks), and Policy 5 (code answers the
deterministic question). The PoC is the implementation spec for wh-00i.

## References

- GNU parallel design (load-avg rejected as too slow) — https://www.gnu.org/software/parallel/parallel_design.html
- GNU parallel man (--memfree/--load/--jobs), 20260422 — https://www.gnu.org/software/parallel/man.html
- GNU parallel is GPL-3 (FSF) — https://www.gnu.org/software/parallel/
- psutil 7.2.2, BSD-3 — https://pypi.org/project/psutil/
- cgroup v2 PSI pressure metrics — https://facebookmicrosites.github.io/cgroup2/docs/pressure-metrics.html
- MemAvailable < MemFree (Oracle) — https://blogs.oracle.com/linux/memavailable-less-than-memfree
- Python os.getloadavg/sched_getaffinity portability — https://github.com/python/cpython/issues/105972

## Follow-up Tasks

- [x] PoC at `docs/research/poc-resource-probe/` (stdlib-only, 10 tests green; real probe validated on macOS)
- [ ] **ADR-023** appended to `docs/ARD.md` (RQ1–RQ5; RQ6 recorded as report-only recommendation)
- [ ] **wh-00i re-scoped** to build `_shared/scripts/resource_probe.py` from this PoC (package shape +
      TDD + vendor-manifest entry); the agent md § "Execution budget" then points at it
- [ ] (conditional) RQ6 schema-bump ticket — **NOT created** (report-only chosen); open only if the
      eval gate later needs machine-visible `mode`
