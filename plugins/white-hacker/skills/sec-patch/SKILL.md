---
name: sec-patch
description: Generate candidate fixes (opt-in). Patch ladder: build -> original PoC stops -> tests pass -> re-attack with a fresh agent. Root-cause fix, variant hunt, minimal diff. Writes ONLY to ./PATCHES/. Use only when explicitly asked to propose patches.
---

# sec-patch — remediation with verification (opt-in, capability-removed writes)

The inner loop's **final, optional** stage. It proposes fixes; it never applies or pushes them.
Safety is **structural, not instructional** (ADR-010 / ADR-016): white-hacker has no `Write`/`Edit`
tool and is granted no patch-apply capability, so `sec-patch` can only emit a unified diff under
`./PATCHES/` for a **human to apply**. Run it **only when explicitly asked**.

> **Opt-in dispatch.** This stage does **NOT** run during `/security-review` (that command stops at
> the triaged report). It is invoked separately via the **`/sec-patch`** command (see
> `.claude/commands/sec-patch.md`) — an explicit, opt-in step. Never auto-run after triage.

## Inputs
- **`TRIAGE.json`** — reads only the **accepted** findings: an item is in scope iff it has **no
  `excluded_by`** (not demoted by an exclusion rule) **and** meets the report gate (triage outcome
  `ACCEPT`, severity/confidence above threshold). Do **not** patch excluded or below-gate candidates
  — a body that patches *every* finding is wrong.

## The patch ladder (run the rungs IN ORDER; record each in `PATCH-STATE.json`)
For each accepted finding, produce a **root-cause**, minimal diff (fix the cause, not the symptom;
prefer the smallest change that removes the source→sink reachability), then climb:

1. **build** — the patched tree still builds/compiles (or `n/a` for an interpreted project with no
   build step). A fix that breaks the build fails the rung.
2. **PoC stops** — the **original PoC / failing-on-vuln test no longer triggers** the vulnerability
   against the patched code. This is the core oracle: the exploit must be demonstrably blocked.
3. **tests pass** — the project's **existing tests** still pass on the patched tree (no regression);
   `n/a` only if the project genuinely has no tests.
4. **re-attack** — hand the patched code to a **fresh agent in a clean session** to attempt a
   bypass. Because white-hacker carries no `Task`/`Agent` tool (minimal capability surface), the
   re-attack is a **separate fresh `/security-review` (or `/sec-patch`) invocation** on the patched
   tree (fresh context, no shared state — ADR-008). `reattack: pass` means the fresh agent found no
   bypass; `fail` means it did (loop back to rung 1 with the bypass as the new PoC).

**Variant hunt (standard post-fix step).** After a fix holds, search for **sibling call-sites and
same-class occurrences** elsewhere in the repo (the same dangerous sink pattern, the same missing
check) and record them in `variants[]`. One fixed instance rarely means the class is gone.

## Output — `PATCH-STATE.json` (+ the diffs under `PATCHES/`)
- Proposed diffs are written **only** under `./PATCHES/` (one file per finding). No write ever
  touches the working tree / source (ADR-010); the human reviews and applies.
- `PATCH-STATE.json` records, per finding: `finding_id`, `patch_path` (under `PATCHES/`), the
  tri-state `ladder{build, poc_stopped, tests_passed, reattack}` ∈ `{pass,fail,n/a}`, `variants[]`
  (sibling call-sites), and an overall `verdict` ∈ `{patched, patch_failed, wont_fix, needs_human}`.
  It validates against [`patch-state-schema.json`](patch-state-schema.json) via
  `scripts/validate_patch_state.py`. The ladder records a verification **class**, never a severity
  (PLAN §6.1) — severity stays in `TRIAGE.json`.

## Confinement (why writes are safe — ADR-010 / ADR-016)
Defense-in-depth, strongest first: (1) **structural** — no `Write`/`Edit` tool and no granted
apply capability, so the agent *cannot* write source; (2) **`permissions.deny`** in the committed
`.claude/settings.json` blocks git/patch mutation verbs (`git apply|am|commit|push|reset --hard|
restore|checkout --|clean`, `patch`); (3) a **PreToolUse Bash tripwire** (`confine_patch_writes`)
denies writes outside a pinned artifact allowlist + `PATCHES/`. The hook is a tripwire, not the
boundary — the strong guarantee is structural.

## Verification criteria (definition of done for this skill)
- [ ] Documents the four ladder rungs in order + the variant hunt; opt-in; writes only to `PATCHES/`;
      declares `PATCH-STATE.json` and references `patch-state-schema.json`.
- [ ] The re-attack spawn mechanism (fresh `/security-review`/`/sec-patch` invocation) is documented.
- [ ] No secret values ever written to output.
