# Phase 5 — Patch + re-attack (opt-in, capability-removed writes)

> **Theme:** add the remediation arm — `sec-patch` — as an **opt-in** stage that proposes fixes via the
> patch ladder (build → original PoC stops → tests pass → **re-attack** with a fresh agent), fixes the
> root cause, hunts variants, and writes **only** to `./PATCHES/`. Safety is structural: white-hacker has
> no working-tree write / `git apply` capability (ADR-010).
> **Maps to:** PLAN §8.1 P5, §2.3 (capability-removed), Portability seam (oracle/PoC/build/scope); ADR-010.
>
> **Loop position:** INNER (final stage). Opt-in; never the default for side projects.
> **Exit condition:** on a triaged HIGH, `sec-patch` emits a minimal root-cause diff under `PATCHES/`,
> records a re-attack verdict in `PATCH-STATE.json`, lists sibling variant call-sites, and demonstrably
> cannot write outside `PATCHES/`.

---

### T-5.1 · Implement `sec-patch` body (the patch ladder)
- **Goal:** `sec-patch/SKILL.md` documents: opt-in only; read `TRIAGE.json`; for each accepted finding
  produce a **root-cause** minimal diff; ladder = build → original PoC no longer triggers → existing
  tests pass → **re-attack with a fresh agent**; **variant hunt** (sibling call-sites + same class) as a
  standard post-fix step; write only to `./PATCHES/`; emit `PATCH-STATE.json`.
- **Artifact:** `.claude/skills/sec-patch/SKILL.md`
- **Depends on:** T-1.1
- **Verification criteria:**
  - [ ] Body documents all four ladder rungs in order + variant hunt — `for k in 'build' 'PoC' 'tests pass\|existing tests' 're-attack\|reattack' 'variant'; do grep -qiE "$k" .claude/skills/sec-patch/SKILL.md || echo MISSING:"$k"; done` prints nothing
  - [ ] States opt-in + writes whitelisted to `./PATCHES/` only — `grep -qi 'opt-in' .claude/skills/sec-patch/SKILL.md && grep -q 'PATCHES/' .claude/skills/sec-patch/SKILL.md`
  - [ ] Declares `PATCH-STATE.json` output — `grep -q 'PATCH-STATE.json' .claude/skills/sec-patch/SKILL.md`
  - [ ] De-stubbed; `SKILL.md` < 500 lines — `! grep -q 'STATUS: STUB' .claude/skills/sec-patch/SKILL.md`
- **Status:** todo

### T-5.2 · Define + validate the `PATCH-STATE.json` schema
- **Goal:** a schema for `PATCH-STATE.json` recording per-finding: `finding_id`, `patch_path`,
  `ladder{build, poc_stopped, tests_passed, reattack}` each ∈ `{pass,fail,n/a}`, `variants[]` (sibling
  call-sites), and an overall `verdict`. Keeps verification **class** separate from severity (PLAN §6.1).
- **Artifact:** `.claude/skills/sec-patch/patch-state-schema.json` (+ test in `scripts/tests/`)
- **Depends on:** T-5.1
- **Verification criteria:**
  - [ ] A sample `PATCH-STATE.json` validates; a missing ladder rung is rejected — `uv run pytest .claude/skills/sec-patch/scripts/tests/test_patch_state_schema.py` (>1 test, edge cases)
  - [ ] Ladder fields are tri-state enums `{pass,fail,n/a}` — asserted in a test
  - [ ] `sec-patch/SKILL.md` references the schema — `grep -q 'patch-state-schema.json' .claude/skills/sec-patch/SKILL.md`
- **Status:** todo

### T-5.3 · Enforce write-confinement to `./PATCHES/` (capability-removal, not instruction)
- **Goal:** structurally guarantee `sec-patch` cannot touch the working tree: a `PreToolUse` guard (the
  Phase-8 confinement hook, scoped here for `sec-patch`) denies any `Write`/`Edit` whose path is outside
  `./PATCHES/`, and the agent `tools:` line excludes working-tree write / `git apply` (ADR-010).
- **Artifact:** `.claude/hooks/confine_patch_writes.sh` (+ `tests/`), referenced from `settings.local.json`
- **Depends on:** T-5.1
- **Verification criteria:**
  - [ ] The hook denies (exit 2) a write to `./src/x` and allows a write to `./PATCHES/x` — `uv run pytest .claude/hooks/tests/test_confine_patch_writes.py` (or a shell test harness; >1 case incl. path-traversal `./PATCHES/../src`)
  - [ ] Path-traversal escape (`PATCHES/../`) is denied — negative test
  - [ ] Agent definition exposes no working-tree write — `grep -E '^tools:' .claude/agents/white-hacker.md` shows no `Write`/`Edit`/`git apply`
- **Status:** todo

### T-5.4 · Patch-ladder demonstration on a planted-vuln fixture
- **Goal:** prove the ladder end-to-end on a buildable fixture with a planted vuln, a failing-on-vuln
  test, and a known PoC: `sec-patch` emits a `PATCHES/` diff, the PoC stops, tests pass, the re-attack
  agent finds no bypass, and a sibling variant is identified.
- **Artifact:** `docs/research/poc-patch-ladder/` (buildable fixture + PoC + `README.md` ladder log)
- **Depends on:** T-5.1, T-5.2, T-5.3
- **Verification criteria:**
  - [ ] After applying the proposed `PATCHES/` diff to a scratch copy, the original PoC no longer triggers — documented runnable command in README returns the "blocked" result
  - [ ] Existing tests pass on the patched scratch copy — `uv run pytest` (or fixture's native test cmd) green, logged
  - [ ] `PATCH-STATE.json` records `ladder.reattack: pass` and a non-empty `variants[]` — `uv run python` schema check + manual read logged
  - [ ] No file outside `PATCHES/` was modified by `sec-patch` (confinement held) — `git status` on the fixture shows only `PATCHES/` additions, logged
- **Status:** todo
