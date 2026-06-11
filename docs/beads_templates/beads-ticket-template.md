# Beads Ticket Template

Use this template for **implementation work** (follows Red/Green/Refactor). When creating a task with beads:

```bash
bd create "Task title"
# Or as a child of an epic:
bd create "Task title" --parent <epic-id>
```

---

> **Before Starting:** Always groom the ticket first. Ensure the goal is clear,
> acceptance criteria are testable, and steps are well-defined before assigning work.

## Goal / Problem

Describe the user/system problem and the outcome needed.

## Background / Context

- Links to research, docs, or prior decisions.
- Relevant services, ports, or environments.

## Workflow (Red / Green / Refactor)

Per-package, stdlib-first (the Read/Grep/Glob floor — ADR-015). Replace `<skill>` with the
package you touch (e.g. `sec-detect`, `deps-scan`, `hooks`). Always `uv run`, never bare `pytest`.

1. **RED** - Write failing tests first

   - Add/update tests that define expected behavior (pin BOTH `== expected` AND `!= wrong` — Policy 9)
   - Run `nice -n 10 uv run --project plugins/white-hacker/skills/<skill>/scripts --with pytest pytest plugins/white-hacker/skills/<skill>/scripts/tests -q` - tests should FAIL

2. **GREEN** - Make tests pass with minimal code

   - Implement the minimum change to satisfy expectations (Policy 2 — nothing speculative)
   - Re-run the package test command above - tests should PASS

3. **REFACTOR** - Improve code quality
   - Clean up code, improve naming, reduce duplication (surgical — Policy 3, never bundle an unrelated refactor)
   - Ensure all quality gates pass (see below)

## Steps (with description)

1. Step 1 - What will be changed and why.
2. Step 2 - What will be changed and why.
3. Step 3 - What will be changed and why.

## Acceptance Criteria

- [ ] Criterion 1 (testable, measurable)
- [ ] Criterion 2
- [ ] Criterion 3

## Quality Gates (must pass before `bd close`)

The white-hacker gates are **pytest + manifest + plugin validate — NOT ruff / mypy / coverage**
(`.claude/CLAUDE.md` Policy 12; `.claude/commands/launch-team.md` § Quality Gates). Only close the
task when every gate is green **and** QA is complete (see QA Before Push). Resource discipline
(`CLAUDE.md`): prefix heavy runs with `nice -n 10`, cap parallelism at `-n 4`, never "all cores".

```bash
# 1. Per touched package (repeat for each skill/package you changed)
nice -n 10 uv run --project plugins/white-hacker/skills/<skill>/scripts --with pytest \
  pytest plugins/white-hacker/skills/<skill>/scripts/tests -q

# 2. Plugin / marketplace layout
uv run python packaging/validate_manifest.py .

# 3. Official plugin validation
claude plugin validate ./plugins/white-hacker

# 4. Outer-loop changes ONLY (KB / registry / eval corpus): score then gate, never auto-merge
#    uv run python evals/score.py --findings <FINDINGS.json> --corpus evals/corpus/cases
#    uv run python evals/keep_or_revert.py --baseline evals/baseline.json --candidate <CANDIDATE.json>
```

- [ ] Each touched package's tests pass (`uv run`, bounded `-n 4` / `nice`)
- [ ] `validate_manifest.py` green
- [ ] `claude plugin validate` green
- [ ] Outer-loop edits scored + gated (N/A for inner-loop code) — Policy 12: a non-zero gate keeps the task `in_progress`

## QA Before Push

Before pushing, manually verify:

- [ ] Happy path works as expected
- [ ] Edge cases covered (empty input, invalid data, boundary conditions)
- [ ] Error handling tested (what happens when things fail?)
- [ ] No regressions in existing functionality

> **Tip:** AI agents may miss edge cases. Always review and test manually before push.

## Commit Message Format

```
<type>: <description>

Types:
- feat: New feature
- fix: Bug fix
- test: Adding/updating tests
- refactor: Code improvement without behavior change
- docs: Documentation changes
- chore: Maintenance tasks
```

Do **not** add AI attribution trailers (e.g. `Co-authored-by: Cursor`) to commit messages.

## Risks / Dependencies

- Risk 1
- Dependency 1

## Notes / Open Questions

- Question 1
