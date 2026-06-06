# Phase 6 — Team mode + CI (bridge the loops; ship in the workflow)

> **Theme:** make white-hacker usable in the TL/QA/Dev team workflow and in CI. Sequential/subagent mode
> is the default; team mode is opt-in. Add the gate hooks (`PreToolUse exit 2` to block dangerous Bash;
> `TaskCompleted`/`TeammateIdle` for team gating) and the CI GitHub Action sharing the same prompt with
> pinned model + pinned deps + SHA-pinned actions.
> **Maps to:** PLAN §8.1 P6, §7 (team integration), §7.3 (return contract), §7.4 (posture); ADR-006
> (pinning), ADR-009 (one definition, three carriers).
>
> **Loop position:** BRIDGE — packages the inner loop for humans/CI and prepares the harness surface the
> outer loop will extend (Phases 8–9 add capture + confinement to the same hooks file).
> **Exit condition:** the CI Action runs the review on a PR diff and gates on `counts.high == 0` with all
> deps/actions/model pinned; team-mode spawn prompts route findings to the tech-lead and exit cleanly on
> WAIT; the report contract returns only triaged JSON + the report path.

---

## Grooming (re-groomed 2026-06-06, after Phase 5)

**Readiness:** ✅ READY. Phases 0–5 are done (Phase 5 modulo the human-auth settings.json registration).

**Reconciliations against what Phases 0–5 actually built (own these explicitly):**
1. **T-6.4 overlaps Phase 5's `confine_patch_writes` hook — split by concern, don't duplicate.**
   T-5.3 already ships a PreToolUse Bash hook that confines *writes* (denies source writes, `git
   apply`/`push`, `patch`). T-6.4 is the *review-posture* guard: deny destructive Bash (`rm -rf`),
   **reads of secrets** (`**/.env`, private keys — the Agents-Rule-of-Two leg `confine_patch_writes`
   does NOT cover), and network egress beyond an allow-list. **Decision:** add a **sibling**
   `guard_bash.py` focused on read-secret + destructive + egress; let `git push`/`apply` stay denied
   by `confine_patch_writes` + `permissions.deny` (benign overlap). Both register as **composable**
   `hooks.PreToolUse` Bash entries (reconciliation holds with ADR-016 §composability).
2. **Hook-registration is human-auth-blocked — cross-phase (6, 8, 9).** Writing `.claude/settings.json`
   is self-modifying startup config; the harness requires explicit operator authorization (ADR-016).
   So **hook LOGIC + tests are the done-gate** for T-6.4/T-6.5 (and Phase 8/9 hooks); their
   **settings.json registration is batched into one human-auth approval** alongside T-5.3's. VCs that
   assert "registered in settings" are marked **pending(human-auth)**, not done.
3. **VC drift: `settings.local.json` → committed `.claude/settings.json`.** T-6.4/T-6.5 VCs name the
   gitignored `settings.local.json`; per ADR-016 the backstop must live in **committed** `settings.json`
   (survives a clone). Rewrite those VCs accordingly (and pending-auth per #2).
4. **`sec-report` reuses the existing contract — no new schema.** `TRIAGE.json` already carries
   `owasp[]`, `first_link`, `summary.tools_unavailable`, `summary.counts`. T-6.2's `ci_gate.py`
   validates against `_shared/reference/finding-schema.json` (via the existing `validate_findings`)
   *before* gating, and mirrors that script's pyproject/conftest/test layout.
5. **Model pin (T-6.3):** pin `claude-opus-4-8` (current Opus id, 2026-06); SHA-pin every `uses:`;
   pin `@anthropic-ai/claude-code`; `permissions: contents: read`; require approval for external
   contributors. The CI review is **floor-only + read-only** (Phase 0 contract); **`/sec-patch` is
   never run in CI** (opt-in only).

**Currency to verify during build (don't assert from memory):** the agent-teams env flag
(`CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS`) + min CC version, and the `claude-code` GitHub Action input
schema (T-6.3) — confirm via `claude-code-guide`/docs before finalizing T-6.3/T-6.5 (mirror spike-06).

**Task sizing & order:** T-6.1 (M, docs) → T-6.2 (S, code+tests) → then T-6.3 (S, yaml) ∥
T-6.4 (M, code+tests, reconciled w/ T-5.3) ∥ T-6.5 (M, docs+hook+tests).

**Definition of Done (phase):** `sec-report` renders the Phase-1 `TRIAGE.json` fixture to a non-empty
report (OWASP IDs, triaged-only); `ci_gate.py` exits 1 on `counts.high>0` (tested, threshold-overridable,
rejects malformed JSON); `security-review.action.yml` is valid + fully pinned + least-privilege;
`guard_bash.py` + `gate_review.sh` are implemented + tested (registration **pending human-auth**);
`team-mode.md` documents both modes + the verified env flag/version + route-to-tech-lead + WAIT exit.
Then **re-groom Phase 7**.

---

### T-6.1 · Implement `sec-report` body (TRIAGE.json → SECURITY-REPORT.md + machine JSON)
- **Goal:** `sec-report/SKILL.md` renders `TRIAGE.json` to a human `SECURITY-REPORT.md` (OWASP IDs,
  precondition list, `first_link`, `tools_unavailable`) and emits the machine JSON for CI; pure reasoning
  (`allowed_tools=[]`). It returns only triaged findings, never raw discovery (PLAN §7.3).
- **Artifact:** `.claude/skills/sec-report/SKILL.md`
- **Depends on:** T-1.1
- **Verification criteria:**
  - [x] Body documents markdown + machine-JSON outputs and OWASP-ID mapping — `grep -q 'SECURITY-REPORT.md' … && grep -qi 'owasp' …`
  - [x] States the CI gate `counts.high == 0` and "triaged-only, never raw discovery" — greps pass
  - [x] De-stubbed; renders the Phase-1 `TRIAGE.json` fixture to a non-empty report — `docs/research/poc-floor-review/run/SECURITY-REPORT.md` (40 lines, tracked)
- **Status:** done

### T-6.2 · CI gate script (consume report JSON, exit non-zero on HIGH)
- **Goal:** a small tested script that reads the machine JSON and exits 1 when `summary.counts.high > 0`
  (configurable threshold), so the CI Action can fail a PR deterministically.
- **Artifact:** `.claude/skills/sec-report/scripts/ci_gate.py` (+ `pyproject.toml`, `tests/`)
- **Depends on:** T-6.1, T-1.1
- **Verification criteria:**
  - [x] Exits 1 on `counts.high > 0`, 0 otherwise; threshold overridable — `uv run --with jsonschema --with pytest pytest .claude/skills/sec-report/scripts/tests/test_ci_gate.py` *(12 tests; medium-only passes, `--max-high` override, real deduped fixture → exit 1)*
  - [x] Rejects malformed/non-schema JSON with a clear error (exit 2) — `test_main_malformed_json_rejected`, `test_main_non_schema_json_rejected`
- **Status:** done

### T-6.3 · Populate the CI GitHub Action (pinned model + deps + SHA-pinned actions)
- **Goal:** `ci/security-review.action.yml` runs the review on the PR diff, invokes the gate script, and
  follows ADR-006 hygiene: model pinned to a dated Opus id, `@anthropic-ai/claude-code` pinned, all
  `uses:` pinned to commit SHA, least-privilege `permissions: contents: read`, and "require approval for
  external contributors".
- **Artifact:** `ci/security-review.action.yml`
- **Depends on:** T-6.1, T-6.2
- **Verification criteria:**
  - [x] Valid YAML — `uv run --with pyyaml python -c 'import yaml; yaml.safe_load(open("ci/security-review.action.yml"))'`
  - [x] Every `uses:` is SHA-pinned (40-hex), model + claude-code pinned — `actions/checkout@df4cb1c…` (v6.0.3, verified) + `@anthropic-ai/claude-code@2.1.167` + `claude-opus-4-8`; no tag/branch pins
  - [x] `permissions: contents: read` + external-contributor approval (fork-skip `if:` + repo-setting note) present
  - [x] De-stubbed — `! grep -qi 'stub'`
- **Status:** done *(SHA pins resolved live via the GitHub API; CI runs our `/security-review` then `ci_gate.py` — ADR-009)*

### T-6.4 · `PreToolUse` dangerous-Bash guard
- **Goal:** a `PreToolUse` hook that blocks (exit 2) destructive/exfil Bash during a review (e.g. `git
  push`, `git apply`, network egress beyond allow-list, `rm -rf`, reads of `**/.env` / private keys),
  enforcing the posture preamble structurally. This is the first hook in the shared `settings` hooks
  block that Phases 8–9 extend.
- **Artifact:** `.claude/hooks/guard_bash.{py,sh}` (+ `tests/`); registration staged for committed
  `.claude/settings.json` (ADR-016; reconciliation #3 — not `settings.local.json`).
- **Depends on:** —
- **Verification criteria:**
  - [x] Denies `git push`/`apply`/`am`, `rm -rf`, secret-file refs (`.env`, `id_rsa`, `*.pem`, `~/.ssh`, `~/.aws/credentials`, `.npmrc`), and exfil-shaped egress; allows benign read-only Bash, `uv run`, `.env.example` — `uv run --with pytest pytest .claude/hooks/tests/test_guard_bash.py` *(10 tests)*
  - [ ] **(pending human-auth)** registered under `hooks.PreToolUse` (Bash matcher) in committed `.claude/settings.json` — batched with T-5.3's registration (self-modifying startup config; awaits operator OK)
- **Status:** blocked(human-auth: settings.json registration) — guard logic + 10 tests done; only registration pending.

### T-6.5 · Team-mode spawn prompts + gate hooks
- **Goal:** document the two execution modes (sequential/subagent default; team mode opt-in behind
  `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`) with spawn prompts that route findings to the **tech-lead**
  (not the dev) via SendMessage, exit cleanly on WAIT, and a `TaskCompleted`/`TeammateIdle` gate hook so
  the lead blocks merge until the review returns. Operational detail goes in the spawn prompt (subagent
  `skills`/`mcpServers` don't carry to teammates — PLAN §7.1).
- **Artifact:** `docs/team-mode.md` (spawn prompts + mode matrix) + `.claude/hooks/gate_review.sh`
  (+ `tests/`)
- **Depends on:** T-6.1
- **Verification criteria:**
  - [x] `docs/team-mode.md` documents both modes, the env flag (+ min-CC-version verify caveat), and "route to tech-lead" — greps pass
  - [x] States the carry-over caveat (subagent skills/mcpServers don't apply as teammate) — greps pass
  - [x] Gate hook blocks "review complete" until `TRIAGE.json` exists and returns only the summary + report path — `uv run --with pytest pytest .claude/hooks/tests/test_gate_review.py` *(6 tests)*
  - [x] WAIT-state clean-exit behavior documented (matches agent §Team-workflow) — grep passes
- **Status:** done *(gate-hook registration shares the T-5.3/T-6.4 human-auth settings.json step)*
