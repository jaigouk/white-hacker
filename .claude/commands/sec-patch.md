---
name: sec-patch
description: OPT-IN remediation. Propose verified, root-cause fixes for the ACCEPTED findings in TRIAGE.json via the patch ladder (build → PoC stops → tests pass → re-attack), writing diffs ONLY to ./PATCHES/. Never applies or pushes — a human applies. Run only when explicitly asked to propose patches.
argument-hint: "[TRIAGE.json]   (defaults to ./TRIAGE.json)"
---

# /sec-patch $ARGUMENTS

Explicit, **opt-in** entry point for the remediation stage. This is **separate from**
`/security-review` (which stops at the triaged report) and must be invoked deliberately. Delegate
the work to the **white-hacker** agent (`.claude/agents/white-hacker.md`) running the **sec-patch**
skill (`.claude/skills/sec-patch/SKILL.md`) — that skill is the behavioral source of truth.

## Scope
- **Input:** `$ARGUMENTS` if provided (a `TRIAGE.json` path); otherwise `./TRIAGE.json`. Patch **only
  accepted** findings — `excluded_by` absent **and** report-gate met. Never patch excluded/below-gate
  candidates.
- Read-only on the working tree. Proposed diffs go **only** under `./PATCHES/`; a **human applies**
  them (capability-removed writes — ADR-010 / ADR-016).

## Contract — climb the patch ladder per finding
Run the rungs in order and record each in `PATCH-STATE.json` (validates against
`.claude/skills/sec-patch/patch-state-schema.json`): **build → original PoC stops → existing tests
pass → re-attack** (a *fresh* `/security-review` or `/sec-patch` invocation in a clean session —
ADR-008 fresh context — attempts a bypass). Then run the **variant hunt** for sibling call-sites.
A root-cause, minimal diff per finding; `verdict ∈ {patched, patch_failed, wont_fix, needs_human}`.

## Outputs
- `PATCHES/<finding-id>-*.diff` (one unified diff per finding) + `PATCH-STATE.json`.
- The command **does not** apply, commit, or push anything.

## Verification criteria
- [ ] Runs only when explicitly invoked; **not** triggered by `/security-review`.
- [ ] Patches only accepted findings (no `excluded_by`, report-gate met).
- [ ] Emits `PATCHES/*.diff` + `PATCH-STATE.json` (schema-valid); no working-tree/source write.
- [ ] Re-attack rung uses a fresh-session invocation; ladder + variants recorded.
