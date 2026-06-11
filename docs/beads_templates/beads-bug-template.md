# Beads Bug Template

Use this template for **bug tickets** — a defect in shipped behavior (wrong result, crash, hang,
missed/false finding, DoS). Bugs differ from tasks: the load-bearing sections are **Reproduction**,
**Expected vs Actual**, and a concrete **Root-cause hypothesis** (a `file:line`, not "something with X").
A bug is not done until a **regression test** fails before the fix and passes after.

```bash
bd create --type=bug --title="<short imperative: what's wrong>"
# Or as a child of an epic:
bd create --type=bug --parent <epic-id> --title="..."
```

> **Design via `/design-ticket --type=bug`.** It reads `git log` around the suspected files, recent
> commits, and related tests, and fills the sections below from the real repo state. Don't hand-author
> a bug body from the description alone — verify the repro and the root cause against the code.

---

## Goal / Problem

One or two sentences: what behaves wrong, for whom, and the impact. If security-relevant, name the
**threat model** (e.g. "review untrusted repos") and the class (CWE-NNN / OWASP / the KB technique id).

## Reproduction

The exact, copy-pasteable steps that trigger the bug on a **fresh checkout** (Policy 8 — verified, not
assumed). Prefer a runnable command or a minimal fixture over prose.

```bash
# e.g. a failing probe, a CLI invocation, or a fixture + the command that mis-handles it
nice -n 10 uv run --project plugins/white-hacker/skills/<skill>/scripts python -c "..."
```

## Expected vs Actual

- **Expected:** what the correct behavior is.
- **Actual:** what happens instead (paste the output / exit code / hang / wrong finding).

## Suspected Root Cause

A concrete hypothesis tied to code — **`file:line` + the specific construct**, not "something with X"
(Policy 8). State *why* it produces the Actual behavior. If unknown, say so and scope a spike instead.

- e.g. `detect_tools.py:417` `_read_manifest_text` uses uncapped `p.read_text()` with no `is_file()`
  guard → a FIFO/device read blocks; runs on every `build_scan_plan` via `_match_signals`.

## Files in Scope (the fix surface)

- `plugins/white-hacker/skills/<skill>/scripts/<mod>.py` — the fix
- `plugins/white-hacker/skills/<skill>/scripts/tests/test_<mod>.py` — the regression test

> This is the source of truth for scope (sequential-mode self-contained execution — see
> `.claude/commands/design-ticket.md`). A file not listed here will not be touched. Keep the fix
> **surgical** (Policy 3): a bug fix never bundles an unrelated refactor — stale neighbours get a NEW ticket.

## Workflow (Red / Green / Refactor)

1. **RED** — write the regression test that reproduces the bug; it must FAIL on the current tree
   (a test that can't fail when the bug is present is wrong — Policy 9). Pin BOTH directions where it
   applies (the bad input is rejected/handled AND a legitimate look-alike still works).
2. **GREEN** — the minimum fix to make it pass. Re-run the package tests.
3. **REFACTOR** — only what the fix itself needs; nothing speculative.

## Acceptance Criteria

- [ ] A regression test FAILS before the fix and PASSES after (name it / its probe).
- [ ] Both directions pinned where relevant (`== expected` AND `!= the wrong value`).
- [ ] No regression: the touched package's existing tests stay green.
- [ ] (If security) the threat-model probe is closed — the malicious input no longer triggers the defect.

## Quality Gates (must pass before `bd close`)

The white-hacker gates are **pytest + manifest + plugin validate — NOT ruff / mypy / coverage**
(`.claude/CLAUDE.md` Policy 12). `nice -n 10`, `-n 4` cap (resource discipline).

```bash
nice -n 10 uv run --project plugins/white-hacker/skills/<skill>/scripts --with pytest \
  pytest plugins/white-hacker/skills/<skill>/scripts/tests -q
uv run python packaging/validate_manifest.py .
claude plugin validate ./plugins/white-hacker
```

- [ ] Touched package tests pass · `validate_manifest.py` green · `claude plugin validate` green
- [ ] Policy 12 — a non-zero gate keeps the bug `in_progress`; never check an AC whose probe is SKIP not PASS

## Severity ↔ Priority

Set `--priority` to match impact (design-ticket.md bug check 4):

- **P0** — review pipeline broken, or a missed/false vuln that defeats the product's purpose.
- **P1** — a core flow produces wrong results for common input.
- **P2** — blocks one flow, or a live security defect (e.g. a DoS reachable on the standing threat model).
- **P3** — narrow / cosmetic / stale-string; no behavioral impact on a real scan.

## Commit Message Format

```
fix: <description>          # bug fixes use `fix:`
```

Commit conventions per `.claude/CLAUDE.md` Policy 12. A security-relevant fix gets a dogfood review (QA flow).

## Rollback

`git revert` the fix hunk. Note any data/migration the revert must also undo (usually none for a
surgical bug fix).

## Risks / Dependencies

- Risk 1 (e.g. the fix narrows a heuristic — confirm it doesn't drop legitimate cases).
- Dependency 1 (e.g. serialize vs another ticket that edits the same file — NEVER co-wave).

## Notes / References

- `docs/research/…` (if a spike/PoC backs the root cause) · the discovering review / dogfood finding
- The `file:line` you actually read (Policy 8 — uncited "verified" is a grooming defect).
