---
name: review
description: Structured CODE review of a completed wave's diff — bugs, clarity, the 12 policies, capability interfaces, artifact chain, model-for-judgment-only, tests-verify-intent. Run AFTER wave work is done. Code quality, NOT security (the white-hacker did that in-wave).
allowed-tools: Read, Grep, Glob, Bash
---

# /review <target>

A structured **code review** of a diff — correctness, clarity, conventions, and test quality, aligned
to this repo's `.claude/CLAUDE.md` 12 policies and the ADRs.

**Run it AFTER a wave's work is done** (post-`/handoff`), as a final code-quality pass over the wave's
diff. **This is a CODE review, not a security review** — the **white-hacker** is part of the wave and
already did the security pass in-wave (Phase 3: untrusted-input / confinement / injection / agent-as-target),
and the **qa-engineer** ran the 4 tiers. `/review` answers *is the code correct, clear, well-tested, and
true to our conventions* — it does NOT re-run the security review. (A glaring secret or unsafe-shell still
gets flagged as basic hygiene, but depth is not the goal here.)

## Usage

```
/review                          # all uncommitted changes (staged + unstaged)
/review --staged                 # only staged changes
/review <commit-sha>             # a specific commit
/review <branch>                 # branch diff vs main
/review <path>                   # a specific file/dir
/review <ticket-id>              # all commits whose message references the ticket
```

## Process

### Step 1 — Gather the Diff

- No target / `--staged`: `git diff` (all uncommitted) or `git diff --cached` (staged)
- Commit: `git show <sha>` · Branch: `git diff main...<branch>` · Path: `git diff HEAD -- <path>` + read the full file
- Ticket: `git log --all --grep="<ticket-id>" --oneline` → review those commits

List changed files with `git diff --stat` for the range.

### Step 2 — Read Changed Files

For EACH changed file read: the full diff, the full file (context), and the package's tests
(`scripts/tests/test_<mod>.py`). Know the package shape (`scripts/{<mod>.py,pyproject.toml,conftest.py,tests/}`).

### Step 3 — Review Checklist

Report findings per file, by category.

#### A. Bugs & Correctness
- [ ] Off-by-one / boundary conditions; empty/None handling
- [ ] Exceptions: the right ones caught, none swallowed silently (a bare `except: pass` that hides a real failure)
- [ ] Return correctness in ALL branches; no fail-OPEN where it should fail-CLOSED (gates/hooks default to block)
- [ ] State mutation / TOCTOU on a path that is also read (a check-then-use gap is a correctness bug, not just a security one)

#### B. Missing Elements
- [ ] Missing test for new/changed behavior (every changed branch has a test)
- [ ] Missing edge cases: empty input, very large input (resource bound), special chars, untrusted bytes
- [ ] Missing validation at boundaries (file I/O, parsed manifests, event JSON on stdin)
- [ ] Missing `tools_unavailable` / degrade path when a capability is absent (ADR-015 — never block on a missing tool)

#### C. Clarity & Complexity
- [ ] Misleading names; functions doing > 1 thing; nesting > 3 deep
- [ ] Magic numbers/strings that should be named constants (e.g. a read-cap, a depth-cap)
- [ ] Dead/commented-out code, unused imports

#### D. The 12 Policies (cite the binding, don't re-debate)
- [ ] **P2 Simplicity** — minimum code, nothing speculative; no env var / flag for one caller; stdlib-first (the Read/Grep/Glob floor)
- [ ] **P3 Surgical** — the diff does ONE thing; no bundled refactor; a stale neighbour got a NEW ticket, not a drive-by
- [ ] **P5 Model for judgment ONLY** — NO LLM in deterministic code: `evals/score.py`, `evals/keep_or_revert.py`, `sec-detect/detect_tools.py`, the `hooks/*` parsers, schema/manifest validation. A pure function must stay a pure function.
- [ ] **P6 Budgets** — `SKILL.md` < 500 lines; `description`+`when_to_use` ≤ 1,536; `reference/` one level deep (ADR-005). `.claude/CLAUDE.md` < 200 lines.
- [ ] **P9 Tests verify intent** — each invariant pins BOTH `== expected` AND `!= the wrong value`; a test that can't fail when the logic changes is wrong; mocked-only tests don't prove an external shape
- [ ] **P11 Conventions** — package shape; the artifact chain `THREAT_MODEL→SCAN-PLAN→VULN-FINDINGS→TRIAGE→PATCHES`; findings validate against `_shared/reference/finding-schema.json`; tickets follow the templates
- [ ] **P12 Fail loud** — no skipped gate reported as green; non-zero gate keeps the ticket `in_progress`; no `git commit --no-verify`

#### E. Capability Interfaces & Artifact Chain (ADR-015, ADR-008)
- [ ] Depends on a CAPABILITY (SAST/SCA/secrets/AI-redteam), never a brand; degrades to the floor (`tool_assisted:false`, confidence capped, `tools_unavailable` listed)
- [ ] Artifact JSON conforms to its schema; doesn't fork the chain shape
- [ ] Discovery (recall) and triage (precision) stay separate; the decision step sees only `{file,line,category,diff}` — no untrusted prose leaks into the gate (ADR-008)

#### F. Test Quality
- [ ] RED first (the test fails before the fix); independent tests (no shared mutable state)
- [ ] Names describe the scenario; happy path AND the ticket's edge cases
- [ ] Mocks minimal — never mock the thing under test; pair a load-bearing external shape with a PoC/fixture (Policy 9)
- [ ] Ran via `uv run` (never bare `pytest`); xfail/skip is visible and justified, never a hidden green

#### G. Commit Hygiene
- [ ] Each commit does ONE thing; refactor separate from fix/feature; message explains WHY
- [ ] Commit author + no-attribution + no-corporate-email per `.claude/CLAUDE.md` Policy 12
- [ ] No machine data in committed files (paths/usernames/tool locations) — repo-relative POSIX only (`finding-schema` rejects an absolute `file`)

#### H. Basic hygiene (a code-review baseline — the in-wave white-hacker already did the security depth)
- [ ] No secrets / credentials / PII / tokens in code, comments, or logs
- [ ] No unbounded read of untrusted bytes; no `subprocess`/shell with unsanitized input; file paths validated
- [ ] Error messages don't leak internal state
- [ ] No machine data in committed files — repo-relative POSIX paths only (see also G)

### Step 4 — Produce Report

```
## Review: <target>

### Summary
- Files changed: N · Verdict: [APPROVE | REQUEST CHANGES | DISCUSS] · Risk: [LOW | MEDIUM | HIGH]

### Findings
#### <repo-relative path>
| # | Severity | Category | file:line | Finding |
|---|----------|----------|-----------|---------|
| 1 | CRITICAL | Bugs/A | path:42 | … |
| 2 | MAJOR | P5/D | path:15 | … |

### Quality Gates (the REAL gates)
| Gate | Result |
|------|--------|
| `uv run --project plugins/white-hacker/skills/<skill>/scripts --with pytest pytest …/tests -q` | PASS/FAIL |
| `uv run python packaging/validate_manifest.py .` | PASS/FAIL |
| `claude plugin validate ./plugins/white-hacker` | PASS/FAIL |
| outer-loop: `evals/score.py` + `evals/keep_or_revert.py` (KB/eval edits only) | PASS / N/A |

### Recommendations
1. <actionable, file:line> 2. <actionable, file:line>
```

### Severity Definitions

| Severity | Meaning | Action |
|----------|---------|--------|
| **CRITICAL** | Bug / fail-open gate / data or watchlist poisoning / a missed-or-false finding that defeats the product | Must fix before close |
| **MAJOR** | A 12-policy violation (esp. P5 LLM-in-deterministic, P3 bundled refactor, P9 can't-fail test), missing test, broken artifact-chain contract | Should fix before close |
| **MINOR** | Naming, clarity, a small convention slip | Fix if easy, else note |
| **NIT** | Preference / optional | Author's discretion |

### Verdict Rules
- **APPROVE** — zero CRITICAL, zero MAJOR (only MINOR/NIT).
- **REQUEST CHANGES** — any CRITICAL or MAJOR.
- **DISCUSS** — an architectural question needing the user / an ADR before deciding (Policy 1: don't re-debate a settled ADR; cite it).

## Rules

1. **It's a CODE review, run post-wave.** Correctness, clarity, conventions, tests. The white-hacker is part of the wave and already did the security pass — don't re-run it; a basic-hygiene flag (§H) is fine, depth is not the goal.
2. **Cite `file:line` and the binding.** Every finding names the path:line and, for a convention call, the policy/ADR — not "feels off" (Policy 8).
3. **The real gates, not ruff/mypy/coverage.** Run/report `uv run` package tests + `validate_manifest` + `plugin validate`. SKIP is never PASS (Policy 12).
4. **Don't re-debate settled ADRs.** If `docs/ARD.md` decided it, cite the ADR; a genuine conflict is a DISCUSS, not a silent override (Policy 7 — source wins).

## References

- `.claude/CLAUDE.md` — the 12 policies (the spine of this checklist) + QA flow
- [`.claude/commands/launch-team.md`](launch-team.md) — the wave this runs AFTER; the white-hacker (security) + qa-engineer (tiers) already reviewed in-wave
- [`.claude/commands/handoff.md`](handoff.md) — the wave's handoff; run `/review` on the same diff once it's written
- `docs/ARD.md` — the ADRs to cite instead of re-arguing
