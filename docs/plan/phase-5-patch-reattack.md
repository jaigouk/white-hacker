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

## Grooming (re-groomed 2026-06-06, after Phase 4)

**Readiness:** ✅ READY *after spike-06* (hook protocol — see DoR). Phases 0–4 are `done (verified)`.

**Definition of Ready — reconciled against what Phases 0–4 actually built:**
- **The finding contract `sec-patch` consumes exists.** `TRIAGE.json` validates against
  `_shared/reference/finding-schema.json` via `validate_findings.py`. `sec-patch` reads the *accepted*
  (non-excluded, report-gate) findings.
- **The agent already exposes NO `Write`/`Edit`.** `.claude/agents/white-hacker.md` `tools:` is
  `Read, Grep, Glob, Bash, SendMessage, ToolSearch`. So T-5.3's "no working-tree write tool" VC is
  **already true for Write/Edit** — the residual write surface is **`Bash`** (redirection / `tee` /
  `cp`/`mv` / `git apply`). This reframes T-5.3 (see reconciliation #1).
- **`settings.local.json` exists but has only a permission allowlist — no `hooks` block yet.** T-5.3
  adds the first `hooks.PreToolUse` wiring.
- **PoC-fixture pattern is established** (`docs/research/poc-*/` with `README.md` + tests, e.g.
  `poc-ai-review`); reuse it for T-5.4's buildable fixture.
- **Re-attack uses a fresh agent.** The ladder's re-attack rung spawns a fresh-context subagent
  (Agent tool) to try to bypass the fix; its verdict lands in `PATCH-STATE.json.ladder.reattack`.

**Reconciliation sub-tasks (drift Phases 0–4 left for Phase 5 — own them explicitly):**
1. **Confinement boundary is `Bash`, not `Write`/`Edit` (re-scopes T-5.3).** Because the agent has no
   Write/Edit, a PreToolUse guard on those tools alone confines nothing — and the **artifact chain
   itself is written via Bash** (skills `scripts/` emit `SCAN-PLAN.json`/`VULN-FINDINGS.json`/… by
   redirection). So a naive "deny every write outside `PATCHES/`" would **break the pipeline**. The
   guard must therefore be a **`PreToolUse` hook on `Bash`** (plus Write/Edit as defense-in-depth) that:
   (a) **allows** writes to the artifact-chain allowlist (`THREAT_MODEL.md`, the `*.json` artifacts,
   `SECURITY-REPORT.md`, `*.sarif`) and to `PATCHES/**`; (b) **denies** any write resolving outside
   that allowlist (working-tree/source); (c) **denies git mutation verbs** (`git apply|am|commit|push|
   checkout --|reset --hard|restore|clean`). Implement the decision in a **testable Python module**
   behind a thin `.sh` wrapper that reads the PreToolUse tool-input JSON on stdin and exits `2` to deny.
   Be honest about the residual: Bash-command parsing is heuristic; the *strong* guarantee remains the
   structural baseline (no Write/Edit tool, no `git apply`, human applies patches). Document the limit.
2. **Phase 8/9 overlap — keep hooks separate + composable.** T-5.3's `confine_patch_writes.sh` is the
   **patch-write** confinement; Phase 9 builds the **general** trifecta/egress confinement guardrails.
   Register both independently under `hooks.PreToolUse` (don't fold one into the other, don't duplicate).
3. **`PATCH-STATE.json` validator is new.** Mirror the `validate_kb.py`/`validate_findings.py` pattern:
   a `patch-state-schema.json` (Draft 2020-12, tri-state ladder enums) + a `scripts/` validator with
   pytest. No new runtime deps beyond `jsonschema`.

**Task sizing & sequencing (reconciled):**
| Step | Size | Type | Order | Notes |
|------|------|------|-------|-------|
| **spike-06** PreToolUse hook protocol | S | research | **first (DoR for T-5.3)** | verify CC hook I/O: stdin JSON shape, exit-2-denies semantics, `settings` registration — don't assume from memory |
| T-5.1 `sec-patch` body (ladder + opt-in + PATCHES/-only) | M | docs | after spike (T-5.2/5.3 reference it) | ladder rungs in order + variant hunt |
| T-5.2 `patch-state-schema.json` + validator + tests | S | code+tests | after T-5.1 | tri-state `{pass,fail,n/a}`; >1 test |
| T-5.3 confinement hook (**Bash guard + allowlist**, re-scoped) | M | code+tests | after spike-06 + T-5.1 | biggest task; path-traversal + git-verb negative tests |
| T-5.4 patch-ladder fixture e2e | L | code+fixture+tests | last | buildable vuln + failing test + PoC + re-attack + variant |

Order: **spike-06 → T-5.1 → T-5.2 → T-5.3 → T-5.4.**

**Risks / open questions:**
- *Hook protocol (top risk):* the Claude Code PreToolUse hook I/O contract (stdin JSON keys, exit-code
  semantics, `settings.json` `hooks` schema) must be **verified by spike-06** before T-5.3 — assuming it
  from memory is exactly the "verify before concluding" trap.
- *Heuristic Bash parsing:* the confinement can be bypassed by exotic write vectors (e.g. a python
  one-liner that opens a file for write). Mitigate with a conservative deny-by-default for recognized
  write verbs + the structural baseline; **state the residual risk in the hook header** and let Phase 9
  harden. Do **not** claim airtight confinement.
- *VC drift:* T-5.3's original third VC ("agent exposes no Write/Edit") is already satisfied; it is
  **rewritten below** to also require the hook to deny `git apply`/source writes (the real boundary).

**Definition of Done (phase):** all four tasks `done (verified)` + spike-06 resolved; `sec-patch`
documents the four ladder rungs in order + variant hunt + opt-in + PATCHES/-only + `PATCH-STATE.json`;
the schema validates a sample and rejects a missing/!tri-state rung; the confinement hook **allows**
PATCHES/ + the artifact-chain allowlist and **denies** source/working-tree writes, path-traversal
(`PATCHES/../src`), and git-mutation verbs (all tested); the patch-ladder fixture demonstrates
PoC-stops + tests-pass + reattack-pass + a named variant + confinement-held (only `PATCHES/` added);
living docs + statuses updated. Then **re-groom Phase 6** (rolling-wave).

---

## Grooming refinement (deepened 2026-06-06 — 9-agent verification workflow)

> Delta on the re-groom above, from a verification workflow (spike-06 resolved + confinement red-team).
> **spike-06 RESOLVED (HIGH):** `docs/research/spike-06-claude-code-hooks-protocol-2026-06.md` (sourced to
> code.claude.com/docs). A PreToolUse hook gets `{…, tool_name, tool_input}` on stdin (for Bash,
> `tool_input.command` is the full string; `cwd` to canonicalize); **exit 2 = hard block** (stderr→Claude);
> registered under `hooks.PreToolUse[].{matcher:"Bash", hooks[].{type:"command",command}}`; the
> `permissions.deny` list parses compound commands and checks each sub-command (strips
> `timeout/time/nice/nohup/stdbuf/xargs`), so `Bash(git apply *)` etc. are enforced by CC's own parser.

**Red-team verdict on T-5.3 (load-bearing):** a verb+path Bash hook is **NOT** a real boundary — 16
verified bypasses (symlink-through-allowlist, `mv`/`cp` laundering, `python3 -c`/`perl -e`/`sed -i`/
`awk 'print>f'`, heredoc traversal, `patch -p1 <diff` which is a git-apply equivalent off the verb list).
**Re-frame T-5.3 as defense-in-depth, strongest first:** (1) **STRUCTURAL baseline** — no Write/Edit tool
(already), no *granted* apply capability, `sec-patch` emits a diff under `PATCHES/` and a **human applies
it** (the only real guarantee — lead with it); (2) **`permissions.deny`** for git/patch mutation verbs
(CC-parsed, robust); (3) a conservative deny-by-default Bash **hook as a tripwire** that
realpath-canonicalizes then matches a pinned allowlist and denies interpreters / laundering verbs /
`.claude/**` writes. Hook header + phase DoD carry the verbatim residual-risk statement.

## Decisions on open questions (jkim defaults — 2026-06-06, "go through phases automatically"; all reversible)
1. **Re-attack = a fresh `/security-review` / `/sec-patch` invocation in a clean session** — NOT adding
   `Task`/`Agent` to white-hacker's `tools:` (keeps the capability surface minimal; honors ADR-008
   fresh-context). T-5.4's `reattack:pass` is a transcribed one-time live demo, not a CI gate.
2. **`PATCH-STATE.json` is a live-run artifact → gitignored** (like `VULN-FINDINGS.json`/`TRIAGE.json`);
   the fixture's tracked verdict is `EXPECTED-PATCH-STATE.json`.
3. **Confinement backstop ships in a COMMITTED `.claude/settings.json`** (not the gitignored
   `settings.local.json`), so the ADR-010 guard survives a fresh clone.
4. **Personal `settings.local.json` allows left as-is** (per-author, gitignored); the shipped guard is the
   committed deny-list + hook + no-Write/Edit. Interpreter/laundering writes during a patch run are caught
   by layer (3).
5. **Policy promoted to ADR-016** (append-only) — git/patch-apply denial is hook+permissions-enforced (not
   capability-absent), with the residual-risk statement recorded.
6. **`verdict` enum = `{patched, patch_failed, wont_fix, needs_human}`** (T-5.2 — done).

---

### T-5.1 · Implement `sec-patch` body (the patch ladder)
- **Goal:** `sec-patch/SKILL.md` documents: opt-in only; read `TRIAGE.json`; for each accepted finding
  produce a **root-cause** minimal diff; ladder = build → original PoC no longer triggers → existing
  tests pass → **re-attack with a fresh agent**; **variant hunt** (sibling call-sites + same class) as a
  standard post-fix step; write only to `./PATCHES/`; emit `PATCH-STATE.json`.
- **Artifact:** `.claude/skills/sec-patch/SKILL.md`
- **Depends on:** T-1.1
- **Verification criteria:**
  - [x] Body documents all four ladder rungs in order + variant hunt — *(grep fixed: plain `|`, not `\|`, under `grep -E`)* `for k in 'build' 'PoC' 'tests pass|existing tests' 're-attack|reattack' 'variant'; do grep -qiE "$k" .claude/skills/sec-patch/SKILL.md || echo MISSING:"$k"; done` prints nothing
  - [x] States opt-in + writes whitelisted to `./PATCHES/` only — `grep -qi 'opt-in' .claude/skills/sec-patch/SKILL.md && grep -q 'PATCHES/' .claude/skills/sec-patch/SKILL.md`
  - [x] Declares `PATCH-STATE.json` output + references the schema — `grep -q 'PATCH-STATE.json' … && grep -q 'patch-state-schema.json' .claude/skills/sec-patch/SKILL.md`
  - [x] De-stubbed; `SKILL.md` < 500 lines (65) — `! grep -q 'STATUS: STUB' .claude/skills/sec-patch/SKILL.md`
  - [x] Re-attack spawn mechanism documented (fresh `/security-review`/`/sec-patch` invocation) — `grep -qiE 'fresh (agent|session)|/security-review|/sec-patch' .claude/skills/sec-patch/SKILL.md`; accepted-finding selector (`excluded_by` absent + report-gate) documented; opt-in `/sec-patch` command exists at `.claude/commands/sec-patch.md`
- **Status:** done

### T-5.2 · Define + validate the `PATCH-STATE.json` schema
- **Goal:** a schema for `PATCH-STATE.json` recording per-finding: `finding_id`, `patch_path`,
  `ladder{build, poc_stopped, tests_passed, reattack}` each ∈ `{pass,fail,n/a}`, `variants[]` (sibling
  call-sites), and an overall `verdict`. Keeps verification **class** separate from severity (PLAN §6.1).
- **Artifact:** `.claude/skills/sec-patch/patch-state-schema.json` (+ test in `scripts/tests/`)
- **Depends on:** T-5.1
- **Verification criteria:**
  - [x] A sample `PATCH-STATE.json` validates; a missing ladder rung is rejected — `uv run --with jsonschema --with pytest pytest .claude/skills/sec-patch/scripts/tests/test_patch_state_schema.py` *(16 tests)*
  - [x] Ladder fields are tri-state enums `{pass,fail,n/a}` (exactly) — `test_tri_state_enum_is_exactly_pass_fail_na`; `verdict` enum `{patched,patch_failed,wont_fix,needs_human}` (`test_verdict_enum_is_class_not_severity`); `patch_path` must be under `PATCHES/` (`test_patch_path_must_be_under_patches`); schema carries **no severity** field (`test_schema_carries_no_severity_field`, PLAN §6.1)
  - [x] `sec-patch/SKILL.md` references the schema — `grep -q 'patch-state-schema.json' .claude/skills/sec-patch/SKILL.md`
- **Status:** done

### T-5.3 · Enforce write-confinement (capability-removal, not instruction) — re-scoped to a Bash guard
> **Re-groom note (2026-06-06):** the agent already exposes no `Write`/`Edit` (`tools: Read, Grep,
> Glob, Bash, SendMessage, ToolSearch`), so the residual write surface is **`Bash`**, and the artifact
> chain is itself written via Bash. The hook therefore guards **Bash** with an artifact-chain
> allowlist (reconciliation #1), not a Write/Edit path. Depends on **spike-06** (hook I/O protocol).
- **Goal:** structurally stop `sec-patch` (and the agent) from touching the working tree: a
  `PreToolUse` hook on **`Bash`** (plus Write/Edit as defense-in-depth) **allows** writes to the
  artifact-chain allowlist (`THREAT_MODEL.md`, `*.json` artifacts, `SECURITY-REPORT.md`, `*.sarif`) and
  `PATCHES/**`, and **denies** (exit 2) any other write target **and** git-mutation verbs (`git apply|
  am|commit|push|checkout --|reset --hard|restore|clean`). The agent `tools:` line already excludes
  Write/Edit; `git apply` is denied by the hook (ADR-010). Honest residual risk documented in-hook.
- **Artifact:** `.claude/hooks/confine_patch_writes.sh` + a testable `confine_patch_writes.py` (+
  `scripts/`/`tests/`), registered under `hooks.PreToolUse` in `.claude/settings.local.json`
- **Depends on:** spike-06, T-5.1
- **Verification criteria:**
  - [ ] Denies (exit 2) a Bash write to `./src/x` (`echo x > src/x`, `tee src/x`, `cp a src/x`) and **allows** a write to `./PATCHES/x` and to the artifact allowlist (`SCAN-PLAN.json`) — `uv run pytest .claude/hooks/tests/test_confine_patch_writes.py` (>1 case)
  - [ ] Path-traversal escape (`PATCHES/../src`, abs paths, `$PWD/src`) is denied — negative test
  - [ ] Git-mutation verbs (`git apply`, `git commit`, `git push`) are denied; read-only git (`git status`/`diff`/`log`) is allowed — asserted in tests
  - [ ] Agent definition still exposes no working-tree write tool — `grep -E '^tools:' .claude/agents/white-hacker.md` shows no `Write`/`Edit`; and the hook is registered in `settings.local.json`
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
