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

1. **RED** - Write failing tests first

   - Add/update tests that define expected behavior
   - Run `uv run pytest tests/ -v` - tests should FAIL
   - Commit: `test: Add failing tests for <feature>`

2. **GREEN** - Make tests pass with minimal code

   - Implement minimum changes to satisfy expectations
   - Run `uv run pytest tests/ -v` - tests should PASS
   - Commit: `feat: Implement <feature>`

3. **REFACTOR** - Improve code quality
   - Clean up code, improve naming, reduce duplication
   - Ensure all quality gates pass (see below)
   - Commit: `refactor: Clean up <feature>`

## Steps (with description)

1. Step 1 - What will be changed and why.
2. Step 2 - What will be changed and why.
3. Step 3 - What will be changed and why.

## Acceptance Criteria

- [ ] Criterion 1 (testable, measurable)
- [ ] Criterion 2
- [ ] Criterion 3

## Quality Gates (must pass before `bd close`)

Only close the task when all gates pass **and** QA is complete (see QA Before Push).

> **Note:** Requires dev dependencies: `uv sync --extra dev`

```bash
# 1. Linting
uv run ruff check src/ tests/

# 2. Type checking
PYTHONPATH=src uv run mypy src/

# 3. All tests with coverage (must be >= 80%)
uv run pytest tests/ -v --cov=src --cov-fail-under=80
```

- [ ] Lint passes
- [ ] Type check passes
- [ ] All tests pass with >= 80% coverage

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
