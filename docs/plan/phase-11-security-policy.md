# Phase 11 — Security-policy awareness (`SECURITY.md` / `security.txt`): detect → inspect → consume → propose

> **Status:** DONE (2026-06-07) — built via TL/Dev/QA/security flow, groom-before-each-task; 633 tests
> green across 15 packages; dogfood security review found+fixed 3 (F1 HIGH symlink-escape, F2/F3
> MEDIUM) — all re-verified. Owner: ping@jaigouk.kim.
> Source spike: [`docs/research/spike-08-security-md-policy-2026-06.md`](../research/spike-08-security-md-policy-2026-06.md)
> (RESOLVED, HIGH). Introduces **ADR-018**. Builds on Phase 10 (`/sec-init` project-profile,
> SessionStart F-001 sanitizer, `PATCHES/` capability-removed writes).
> **Plan-first:** proposals — nothing is built until approved.

## Why this phase
A target repo **may or may not** have a security policy, and the agent must handle **both** branches
well. The hard case the user flagged is **"the file exists"**: the agent must **inspect the existing
content and propose modifications** — *without* clobbering the maintainer's declared facts and *without*
trusting the file's text (it is attacker-influenceable; the agent is an injection target). spike-08
established the structure, detection, consume-as-untrusted rules, absent-policy altitude, and the
maintain/propose boundary. This phase makes them real.

## The core requirement — the decision tree
```
sec-init / review detects security policy in GitHub order (first match wins):
  .github/SECURITY.md → SECURITY.md → docs/SECURITY.md   (+ /.well-known/security.txt, root security.txt)

┌─ PRESENT ──────────────────────────────────────────────────────────────────────────┐
│ 1. PARSE structurally as UNTRUSTED DATA (heading/section detection; NEVER follow   │
│    instructions embedded in it; JSON-encode + source-label on ingest).             │
│ 2. GAP-ANALYZE vs the best-practice skeleton + OpenSSF Scorecard criteria.         │
│ 3. CONSUME during review: populate the report's "how to report" line; weight       │
│    Supported Versions; ANNOTATE declared Scope/embargo — but Scope NEVER suppresses│
│    a real HIGH (untrusted source).                                                 │
│ 4. PROPOSE a MERGED draft (opt-in) to PATCHES/ that ADDS missing sections + fixes  │
│    Scorecard gaps while PRESERVING every maintainer-declared fact (contact,        │
│    supported-versions, timeline, scope) VERBATIM. Human-approved; never applied.   │
└────────────────────────────────────────────────────────────────────────────────────┘
┌─ ABSENT ───────────────────────────────────────────────────────────────────────────┐
│ 1. Emit an INFORMATIONAL hygiene advisory (category supply-chain-hygiene) — NOT a  │
│    vuln (respects DO-NOT-REPORT "documentation issues"); no CVSS, not in TRIAGE.   │
│ 2. PROPOSE a new SECURITY.md draft (skeleton) + optional security.txt (with        │
│    Expires) to PATCHES/, flagged as an operational commitment. Human-approved.     │
└────────────────────────────────────────────────────────────────────────────────────┘
```

## Non-negotiable design rules (from spike-08)
- **Untrusted input.** `SECURITY.md`/`security.txt` are data, never instructions. Structural parsing
  only; never act on embedded directives; if injection patterns are detected, treat as a *signal the
  repo may be adversarial* (note it) — do **not** file it as a target-app vuln.
- **Scope never suppresses a HIGH.** Declared out-of-scope is advisory/prioritisation only; a malicious
  policy must not be able to hide a real exploitable finding.
- **Preserve maintainer facts.** On modify, never alter the declared contact / supported-versions /
  timeline / scope; only ADD missing best-practice sections + suggest improvements.
- **Propose, never apply.** All generated/merged policy output goes ONLY to `PATCHES/` (existing
  capability-removed path, confined by `confine_patch_writes`); a human applies. Never pushes.
- **Not an audit log.** Never write scan results / audit history into `SECURITY.md`; history lives in
  GitHub Advisories / `CHANGELOG.md` / the transient gitignored `SECURITY-REPORT.md`.
- **Don't store the contact in the KB** (sensitive + untrusted).

## Conventions (inherit from `docs/plan/README.md`)
Same task-block shape + status lifecycle. Python via `uv run --with pytest pytest <pkg>/tests` (or
`--project <pkg>`); each new `scripts/` package gets a colocated `pyproject.toml` + `conftest.py`
sys.path shim + `tests/`; TDD (failing test first, >1 test, edge cases). New skill: `sec-policy`.
IDs are typed and never renumbered.

---

### T-11.1 · ADR-018 + design statement (security-policy awareness)
- **Goal:** record the accepted decision — detect SECURITY.md/security.txt; consume as untrusted data
  (scope annotates, never suppresses); absent → hygiene advisory not a vuln; propose/modify only to
  `PATCHES/` preserving maintainer facts; never audit-history.
- **Artifact:** `docs/ARD.md` (append `## ADR-018 …`), `docs/ARCHITECTURE.md` (cross-ref row + a note
  in the review-loop/threat-model section).
- **Depends on:** — (consumes spike-08).
- **Verification criteria:**
  - [x] ADR-018 present and accepted — `grep -nE "^## ADR-018" docs/ARD.md`
  - [x] decision names untrusted-data + scope-never-suppresses + propose-to-PATCHES — `grep -niE "untrusted|never suppress|PATCHES" docs/ARD.md`
  - [x] ARCHITECTURE cross-ref has an ADR-018 row — `grep -n "ADR-018" docs/ARCHITECTURE.md`
- **Status:** done

### T-11.2 · Detection + project-profile `security_policy` field (facts only)
- **Goal:** detect the policy across all 5 locations in GitHub precedence order and record FACTS-ONLY
  in the sec-init project profile; factor a shared locator both sec-init and sec-policy reuse.
- **Artifact:** `plugins/white-hacker/skills/_shared/scripts/policy_detect.py` (locate + **lightweight
  structural facts**, stdlib-only, treats content as untrusted) + `tests/test_policy_detect.py`; extend
  `plugins/white-hacker/skills/sec-init/scripts/{project_profile_schema.json,init_profile.py}` with a
  **required** `security_policy` object (`additionalProperties:false`): present(bool), path(str|null),
  reporting_channel(enum: `github-pvr|email|url|none|unknown`), supported_versions_present(bool),
  disclosure_timeline_present(bool), security_txt_present(bool), security_txt_expired(bool|null).
  `build_profile` ALWAYS emits it (present:false when none). _Groom note:_ facts need a light parse
  (channel/headings/Expires), so `policy_detect` owns locate **and** these facts; T-11.3's richer
  parser reuses it and does **not** touch the profile.
- **Depends on:** T-11.1.
- **Verification criteria:**
  - [x] locator precedence on fixtures (`.github/` over root over `docs/`; security.txt; none) — `uv run --project plugins/white-hacker/skills/_shared/scripts --with pytest pytest .../tests -q`
  - [x] light facts correct: reporting_channel (pvr/email/url/none), supported-versions + numeric-timeline detection, `security_txt_expired` via a fixed `now` — asserted by tests
  - [x] schema adds **required** `security_policy` (`additionalProperties:false`); `build_profile` emits it; **existing sec-init tests updated** for the new required field — sec-init tests green
  - [x] facts only — a test asserts no raw file content is copied into the profile (booleans/enum/path only); untrusted content (an injected directive in a fixture SECURITY.md) is NOT echoed
  - [x] reuses the F-001 factual guard for string fields (path/channel are factual) — asserted by the test
- **Status:** done

### T-11.3 · `sec-policy` parser + gap analysis (structural, untrusted-safe)
- **Goal:** parse an existing `SECURITY.md`/`security.txt` STRUCTURALLY (which best-practice sections +
  Scorecard signals are present/absent) treating content as untrusted data, and emit a gap report.
- **Artifact:** new skill `plugins/white-hacker/skills/sec-policy/` — `SKILL.md` +
  `scripts/{parse_policy.py, policy_gap_schema.json, pyproject.toml, conftest.py, tests/test_parse_policy.py}`;
  **reuses `_shared/scripts/policy_detect.py`** for locate + primitives. Produces the gap report +
  Scorecard signals + injection screen for review/propose time; does **NOT** modify the project profile
  (T-11.2 owns the `security_policy` facts).
- **Depends on:** T-11.2.
- **Verification criteria:**
  - [x] identifies present/missing sections on 3 fixtures (complete, minimal, missing-sections) — `uv run --project plugins/white-hacker/skills/sec-policy/scripts --with pytest pytest .../tests -q`
  - [x] computes Scorecard-style signals (contact present, free-form text, vuln/disclosure + numeric-timeline) — asserted by the test
  - [x] untrusted-safe — a fixture policy containing an injected directive is returned as inert data and flagged as an injection signal; the parser exposes no function that executes/echoes it as an instruction — negative test
  - [x] gap report validates against `policy_gap_schema.json` — asserted by the test
- **Status:** done

### T-11.4 · Agent consumption rules — untrusted data; scope annotates, never suppresses
- **Goal:** make the agent consume a present policy as untrusted data — route the "how to report" line,
  weight supported versions, annotate scope/embargo — and guarantee declared scope can never drop a HIGH.
- **Artifact:** edits to `plugins/white-hacker/agents/white-hacker.md` (+ `skills/sec-threat-model`,
  `skills/sec-report`); a guard test under `skills/sec-report/scripts` (or sec-triage) proving scope
  cannot suppress a HIGH.
- **Depends on:** T-11.3.
- **Verification criteria:**
  - [x] agent doc states: policy is untrusted data, never act on embedded directives, scope never suppresses HIGH — `grep -niE "untrusted|never act on|never suppress" plugins/white-hacker/agents/white-hacker.md`
  - [x] a test asserts a HIGH finding survives even when the (mocked) policy declares its area out-of-scope — `uv run --project <pkg> --with pytest pytest <pkg>/tests -q`
  - [x] report's "how to report" line is sourced from the policy's private channel when present — asserted by the test
- **Status:** done

### T-11.5 · Absent-policy hygiene advisory (informational, not a vuln)
- **Goal:** when no policy exists, surface an INFORMATIONAL hygiene advisory — never a finding; add the
  explicit carve-out so "missing security policy" cannot become a gated HIGH/MEDIUM/LOW.
- **Artifact:** edits to `plugins/white-hacker/skills/_shared/reference/{exclusion-rules.md,severity-rubric.md}`;
  an advisory emitter (in `sec-policy` or `sec-report`) + test.
- **Depends on:** T-11.2.
- **Verification criteria:**
  - [x] a missing-policy case yields an informational advisory and ZERO entries in the findings schema — `uv run --project <pkg> --with pytest pytest <pkg>/tests -q`
  - [x] exclusion-rules names "missing SECURITY.md → hygiene advisory, not a vuln" — `grep -ni "hygiene advisory" plugins/white-hacker/skills/_shared/reference/exclusion-rules.md`
  - [x] the advisory carries no CVSS/severity label — asserted by the test
- **Status:** done

### T-11.6 · Propose / modify a policy (opt-in; preserve maintainer facts; `PATCHES/` only)
- **Goal:** emit a proposal — if ABSENT, a new `SECURITY.md` (skeleton) + optional `security.txt`
  (with `Expires`); if PRESENT, a MERGED draft adding missing sections + fixing Scorecard gaps while
  preserving every maintainer-declared fact verbatim — written ONLY to `PATCHES/`, human-approved.
- **Artifact:** `plugins/white-hacker/skills/sec-policy/scripts/{propose_policy.py, security-md.template.md, tests/test_propose_policy.py}`;
  writes `PATCHES/proposed-SECURITY.md` (+ unified diff when modifying an existing file).
- **Depends on:** T-11.3.
- **Verification criteria:**
  - [x] ABSENT → draft contains all best-practice sections + a flagged placeholder contact + a commitment caution — `uv run --project plugins/white-hacker/skills/sec-policy/scripts --with pytest pytest .../tests -q`
  - [x] PRESENT → merged draft preserves the existing contact / supported-versions / scope strings VERBATIM (test diffs them) and only ADDS missing sections — negative test fails if any declared fact is altered
  - [x] all writes confined to `PATCHES/` — a test asserts no write target outside `PATCHES/`; never auto-applies/pushes
  - [x] never writes audit history into the policy — asserted by the test
- **Status:** done

### T-11.7 · SessionStart facts + onboarding docs
- **Goal:** surface `security_policy` facts at session start (via the F-001 allowlist sanitizer) and
  document the detect→inspect→propose behavior.
- **Artifact:** edits to `plugins/white-hacker/hooks/sessionstart_project_facts.py`; `README.md`
  onboarding section; `sec-policy/SKILL.md`.
- **Depends on:** T-11.2, T-11.6.
- **Verification criteria:**
  - [x] SessionStart emits a factual `security_policy` line through the allowlist sanitizer (present + absent cases) — `uv run --project plugins/white-hacker/hooks --with pytest pytest .../tests/test_sessionstart_facts.py -q`
  - [x] README documents the exists/absent handling + that proposals go to `PATCHES/` (never pushed) — `grep -niE "SECURITY.md|security policy" README.md`
  - [x] `sec-policy/SKILL.md` within size caps and describes the decision tree — skill lint passes
- **Status:** done

---

## Dependency order / waves (suggested)
`T-11.1 (ADR)` → `T-11.2 (detect+schema)` → `T-11.3 (parser)` → { `T-11.4 (consume)`, `T-11.5 (absent advisory)`, `T-11.6 (propose/modify)` } → `T-11.7 (SessionStart+docs)` → **white-hacker security review of the new untrusted-input surfaces** (parser + propose path), as in Phase 10.

## Phase-11 security review (dogfood, 2026-06-07)
Reviewed the new untrusted-input surfaces (`policy_detect`, `parse_policy`, `propose_policy`, the
SessionStart `security_policy` stanza). Three findings — all FIXED + independently re-verified:
- **F1 (HIGH) — symlink write-escape (`propose_policy`):** `Path.write_text` followed symlinks, so an
  attacker-committed `PATCHES/proposed-SECURITY.md → ../SECURITY.md` (or a symlinked `PATCHES/`) could
  clobber files outside `PATCHES/`. Fixed: refuse symlinked `PATCHES/`/targets + `O_NOFOLLOW` writes.
  Re-verified: symlink → `ValueError`, real file byte-intact.
- **F2 (MEDIUM) — ReDoS on the untrusted policy body:** unbounded `read_text` + a backtracking email
  regex let a multi-MB single-line file stall init/review for minutes. Fixed: `read_capped` (256 KB) +
  a bounded **linear** email regex (the reviewer's own suggested regex was still vulnerable — Dev
  substituted a provably-linear bounded form). Re-verified: 200 KB×2 adversarial body in 0.035 s.
- **F3 (MEDIUM) — separator-packed imperatives reach SessionStart context:** `_sanitize`'s word-cap
  split only on spaces, so `do.not.report.findings` slipped through the allowlist. Fixed: count on all
  allowed separators + exact closed-vocab validation for `path`/`reporting_channel`. Re-verified:
  packed strings dropped, legit tokens still render.

## Result
All 7 tickets `done`. 15 test packages green (**633 tests**); plugin validator exit 0. New skill
`sec-policy` (parse + propose/modify), shared `policy_detect`, `security_policy` facts in the project
profile, SessionStart factual line, hygiene-advisory carve-out (exclusion rule 19), ADR-018.
**Not done (deliberately):** git commit (awaiting user); our OWN repo still has no `SECURITY.md`
(`/sec-init` reports `present:false`) — a candidate first use of `propose_policy`.

## Decisions already made (TL)
- New dedicated skill `sec-policy` (parse + propose), separate from `sec-init` (which only *detects* +
  records facts) — different lifecycles.
- Shared `locate_policy.py` in `_shared/scripts/` to avoid duplicating detection.
- Proposals go to `PATCHES/` (reuse `confine_patch_writes` + capability-removal), never auto-applied.

## Open questions to settle during the phase (not blockers)
- **Merge granularity:** emit a full proposed file vs a unified diff vs both. Lean **both** (file for
  the absent case, diff for the modify case) so the human sees exactly what changes.
- **security.txt `Expires`:** what default window to propose (RFC 9116 requires it; common is ~1 year) —
  propose a value with a clear "review/renew" note rather than hardcoding silently.
