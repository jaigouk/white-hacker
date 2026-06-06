# Phase 0 — Skeleton (generic agent + `/security-review` on the floor)

> **Theme:** stand up the generic agent identity and a thin `/security-review` command that runs
> **discovery → triage → report inline** on the diff using only the Read/Grep/Glob **floor** (no
> external tools). This alone beats the legacy single-pass Go agent on any language.
> **Maps to:** PLAN §8.1 P0, §5.1 (core checklist), §7.4 (posture preamble); ADR-001, ADR-003,
> ADR-009, ADR-014. Self-improvement context: si-08 (none yet — inner-loop foundation).
>
> **Loop position:** INNER. Builds the floor the whole inner loop degrades to (ADR-003).
> **Exit condition:** `/security-review <path>` produces a `SECURITY-REPORT.md` + machine JSON of
> triaged-only findings on a fixture repo, with zero external scanners installed.

The agent (`.claude/agents/white-hacker.md`) is **already the full generic identity** — Phase 0 does
**not** rewrite it; it wires the command to it, ports the core checklist into loadable reference, and
proves the floor works end-to-end with a fixture.

---

### T-0.1 · Port the core (language-agnostic) checklist into `_shared/reference/core-checklist.md`
- **Goal:** the 11 root-cause categories from PLAN §5.1 (injection, authN/authZ, SSRF, crypto/secrets,
  deser/RCE, XSS/output, config/headers/CORS, supply-chain, error-handling, data-exposure, resource-
  consumption) exist as a loadable checklist mapped to OWASP Web 2025 IDs, replacing the 3-line stub.
- **Artifact:** `.claude/skills/_shared/reference/core-checklist.md`
- **Depends on:** —
- **Verification criteria:**
  - [ ] File contains a section per category with at least one OWASP Web 2025 ID each — `grep -cE '^#' .claude/skills/_shared/reference/core-checklist.md` returns ≥ 11
  - [ ] Every PLAN §5.1 category name appears — `for c in injection authz ssrf crypto deserialization xss config supply-chain error data-exposure resource; do grep -qi "$c" .claude/skills/_shared/reference/core-checklist.md || echo MISSING:$c; done` prints nothing
  - [ ] `STATUS: STUB` banner is gone — `grep -L 'STATUS: STUB' .claude/skills/_shared/reference/core-checklist.md` lists the file
  - [x] File ≤ 400 lines (reference cap, ADR-005) — `awk 'END{exit !(NR<=400)}' .claude/skills/_shared/reference/core-checklist.md`
- **Status:** done (verified 2026-06-06; all VCs pass)

### T-0.2 · Populate `_shared/reference/severity-rubric.md` (precondition-counted severity)
- **Goal:** the precondition-counting rubric (0 preconds + unauth-remote → HIGH; 1–2/authn → MEDIUM;
  3+/local → LOW; threat-model bumps ≤ 1 step; `severity = min(precond_score, access_score)`) and the
  swappable scoring-standard note (CVSS 3.1/4.0/OWASP/org bug-bar) are written out (PLAN §6.1).
- **Artifact:** `.claude/skills/_shared/reference/severity-rubric.md`
- **Depends on:** —
- **Verification criteria:**
  - [ ] All four severity tiers + the bump rule + the `min(...)` formula are present — `grep -qi 'precondition' .claude/skills/_shared/reference/severity-rubric.md && grep -qi 'min(' .claude/skills/_shared/reference/severity-rubric.md && grep -qiE 'high|medium|low' .claude/skills/_shared/reference/severity-rubric.md`
  - [ ] Verification **class** vs **outcome** vs **severity_label** separation is documented (PLAN §6.1) — `grep -qiE 'static_review_only|ladder_passed' .claude/skills/_shared/reference/severity-rubric.md`
  - [x] `STATUS: STUB` banner gone — `! grep -q 'STATUS: STUB' .claude/skills/_shared/reference/severity-rubric.md`
- **Status:** done (verified 2026-06-06; all VCs pass)

### T-0.3 · Populate `_shared/reference/exclusion-rules.md` (the DO-NOT-REPORT list)
- **Goal:** the ~18 harness exclusion rules (PLAN §6.2 / agent FP-discipline list) are written verbatim
  as a config-extendable list, cross-referencing `config/fp-rules.example.md`.
- **Artifact:** `.claude/skills/_shared/reference/exclusion-rules.md`
- **Depends on:** —
- **Verification criteria:**
  - [ ] ≥ 16 distinct DO-NOT-REPORT rules — `grep -cE '^\s*[-*0-9]' .claude/skills/_shared/reference/exclusion-rules.md` returns ≥ 16
  - [ ] Names the config hook for extension — `grep -q 'fp-rules' .claude/skills/_shared/reference/exclusion-rules.md`
  - [ ] Signature exclusions present — `for r in 'rate-lim' 'test' 'TOCTOU' 'log spoof' 'documentation'; do grep -qi "$r" .claude/skills/_shared/reference/exclusion-rules.md || echo MISSING:"$r"; done` prints nothing
  - [x] `STATUS: STUB` banner gone — `! grep -q 'STATUS: STUB' .claude/skills/_shared/reference/exclusion-rules.md`
- **Status:** done (verified 2026-06-06; all VCs pass)

### T-0.4 · Wire `/security-review` command to the agent (floor-only inline loop)
- **Goal:** `.claude/commands/security-review.md` becomes a working thin entry point: takes an optional
  target path (defaults to working-tree diff), delegates to the white-hacker agent, and instructs it to
  run discovery → triage → report **inline with Read/Grep/Glob only**, returning triaged-only findings.
- **Artifact:** `.claude/commands/security-review.md`
- **Depends on:** T-0.1, T-0.2, T-0.3
- **Verification criteria:**
  - [ ] Frontmatter has `name: security-review` + a `description` ≤ 1,024 chars — `awk '/^---$/{n++} n==1&&/^description:/{print length($0)}' .claude/commands/security-review.md`
  - [ ] References the agent and the two artifacts it emits — `grep -q 'white-hacker' .claude/commands/security-review.md && grep -q 'SECURITY-REPORT.md' .claude/commands/security-review.md`
  - [ ] States the floor-only / triaged-only contract — `grep -qiE 'Read.*Grep.*Glob|floor' .claude/commands/security-review.md && grep -qi 'triag' .claude/commands/security-review.md`
  - [x] `STUB` banner gone — `! grep -q 'STUB' .claude/commands/security-review.md`
- **Status:** done (verified 2026-06-06; all VCs pass)

### T-0.5 · Floor smoke-test fixture (one planted vuln per major language)
- **Goal:** a tiny fixture repo (Go/Py/TS + a clean look-alike) with one obvious planted vuln each,
  so the floor-only review can be demonstrated to flag the planted issues and not the clean ones. This
  is the seed the Phase 7/9 eval corpus later absorbs.
- **Artifact:** `docs/research/poc-floor-review/` (fixtures + `README.md` documenting expected findings)
- **Depends on:** T-0.4
- **Verification criteria:**
  - [ ] Fixture dir contains ≥ 3 language sub-fixtures each with a documented planted-vuln location — `ls docs/research/poc-floor-review/` shows ≥ 3 sub-dirs; `README.md` lists `file:line` per planted vuln
  - [ ] A Grep for each planted sink matches exactly in the vulnerable file and not the clean look-alike — documented as a runnable `grep` per fixture in the README, each returning the expected count
  - [x] Running `/security-review docs/research/poc-floor-review/<lang-vuln>` reports the planted finding and `/security-review docs/research/poc-floor-review/<lang-clean>` reports none (manual demonstration logged in README)
- **Status:** done (verified 2026-06-06; live agent run: TP=3, FP=0, FN=0)

### T-0.6 · Phase-0 posture & degradation self-check
- **Goal:** confirm the agent honors the posture preamble (read-only, untrusted-input, no-push) and the
  degradation contract when zero external tools are present — i.e. it emits `tools_unavailable` and caps
  confidence rather than failing (ADR-003).
- **Artifact:** `docs/research/poc-floor-review/README.md` (degradation-run notes)
- **Depends on:** T-0.5
- **Verification criteria:**
  - [ ] A floor-only run records `"tool_assisted": false` on heuristic findings and a non-empty `tools_unavailable` list in its JSON output (logged in README)
  - [ ] No working-tree write occurs during the run — agent `tools:` line excludes Write/Edit/`git apply` — `grep -E '^tools:' .claude/agents/white-hacker.md` shows no `Write`/`Edit`
  - [x] No secret value appears in any emitted artifact (manual check logged)
- **Status:** done (verified 2026-06-06; read-only run, no writes; Write/Edit hardening tracked for T-6.4/T-8.4)
