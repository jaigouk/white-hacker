# Beads Epic Template

Use this template when creating an epic with beads:

```bash
bd create "Epic: <Title>" -p 0
```

---

> **Before Starting:** Always groom the epic first. Ensure the goal is clear,
> success metrics are measurable, scope is well-defined, and child tasks are planned.

## Goal / Problem

High-level problem statement and desired outcome.

_Example (duration checks): Ensure duration-check logic is well tested and validated against sample DPAs._

## Success Metrics

- Metric 1 (measurable)
- Metric 2

## Scope

**In scope**

- Item 1
- Item 2

**Out of scope**

- Item 1

## Phases / Milestones

1. Phase 1 - Research / design
2. Phase 2 - Implementation
3. Phase 3 - Validation / rollout

## Child Tasks (planned)

Create child tasks under this epic:

```bash
bd create "Task title" --parent <epic-id>
```

_Example (duration checks):_

- Add/expand duration-check test cases (owner TBD)
- Run duration check against sample DPAs and document results
- Add or update benchmarks/expectations for duration checks

## Execution Waves (MANDATORY for epics with > 1 child)

Group the child tickets into **waves** — ordered sets a team can work in parallel.
A wave is the unit of a team launch: each wave maps to one `/launch-team <ticket-ids>`.
The epic description MUST show the waves and their order, so a reader can launch teams
without re-deriving the dependency graph.

**A valid wave grouping satisfies:**

- Tickets **within** a wave are **parallel-safe** — no dependency between them AND **disjoint
  File Ownership** (no shared file across the wave's tickets). Verify against `bd graph <epic-id>`
  and each ticket's File Ownership table.
- Wave N+1 starts only after Wave N closes (its tickets are blocked by Wave N output).
- Every child ticket appears in **exactly one** wave; waves are numbered in execution order.

**Template:**

> **Wave 1 — start now (no blockers · N parallel tracks):**
> - `<id>` — <one-line> *(doc | code)*
> - `<id>` — <one-line> *(doc | code)*
>
> **Wave 2 — after Wave 1 (M parallel tracks):**
> - `<id>` — <one-line> *(doc | code)* — blocked by `<wave-1 id>`

Launch each wave with `/launch-team <wave-N ids…>`; end each wave with `/handoff wave-N-<epic-id>`.

## Dependencies

- Dependency 1
- Dependency 2

## Risks / Unknowns

- Risk 1
- Unknown 1

## Acceptance Criteria

- [ ] **Execution Waves defined** — every child ticket is in exactly one wave; within-wave tickets are parallel-safe (no intra-wave dependency, disjoint File Ownership); wave order matches `bd graph <epic-id>`; each wave is launchable via `/launch-team`.
- [ ] All child tasks closed (`bd close <id>`) — each child must have passed quality gates and QA before close
- [ ] Documentation updated where required
- [ ] For all code changes (in child tasks), quality gates were run before each task was closed:
  - [ ] `uv run ruff check src/ tests/` (linting)
  - [ ] `PYTHONPATH=src uv run mypy src/` (type checking)
  - [ ] `uv run pytest tests/ -v --cov=src --cov-fail-under=80` (tests with 80% coverage)
- [ ] QA was done for each child task before close (happy path, edge cases, error handling, no regressions)
