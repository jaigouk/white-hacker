# Phase 12 — QA remediation (resolve the issues the 2026-06-07 baseline surfaced)

> **Status:** groomed (todo). Date: 2026-06-07. Owner: ping@jaigouk.kim.
> Source: [`docs/qa/20260607/full-baseline-report.md`](../qa/20260607/full-baseline-report.md)
> (QA-8, J=0.835 over 103 cases). **Gate:** `evals/baseline.json` (J=0.835, FPR 0.049) — every fix
> is measured against it. **Plan-first:** proposals; nothing built until approved.

## What the baseline found (the issues to resolve)
| # | Issue | Evidence |
|---|-------|----------|
| I-1 | **AuthN/AuthZ J=0.25** — Wave A: NOT recall, an open-redirect taxonomy issue. **✅ Wave B FIXED** → open-redirect J=1.0 | J=0.25→**1.0** |
| I-2 | **SSRF false-positives** — allow-list guard not credited. **✅ Wave B FIXED** → ssrf J=1.0, FP 0 | 5 FP → **0** |
| I-3 | **Singleton misses** | 1 FN each in crypto, improper-output-handling, tool-poisoning |
| I-4 | **Baseline is sonnet / single-shot** | DEFERRED in QA-8 — not yet production-opus + k-run |

> **Wave A done (2026-06-07)** — see [`../qa/20260607/wave-a-findings.md`](../qa/20260607/wave-a-findings.md):
> I-1 root-caused as **taxonomy/scope** (recall is fine — the agent found all 9 open-redirects), I-2 as
> an **allow-list mitigation the agent doesn't credit**, and the QA-3 smoke caught **4 shipping bugs**
> (plugin/marketplace `$schema`; 3 skills' invalid-YAML frontmatter → silently-dropped metadata) — all
> **FIXED**, `lint_skill` hardened with a strict-YAML gate, `claude plugin validate` now ✔ passes.

> **Wave B done (2026-06-07)** — see [`../qa/20260607/waveb-report.md`](../qa/20260607/waveb-report.md):
> T-12.2 (open-redirect own category) + T-12.3 (SSRF allow-list recognizer) landed as outer-loop
> Context edits, TDD'd, and verified by a 25-case respin → `keep_or_revert` **KEEP**, baseline
> **ratcheted 0.835 → 0.971 (FPR → 0)**. Remaining: **T-12.4** (3 singleton FN), **T-12.5** (opus
> re-baseline), **T-12.6/T-12.7** (remaining tiers + validator hardening).

## This is outer-loop work (the elegant part)
The fixes are **Context-surface edits** (reference appendices, checklists, the KB) — *not* code, *not*
retraining (ADR-001/004). Route them through `sec-learn` → propose dated diffs → the **keep-or-revert
gate** decides. The baseline this QA just produced **is** the gate. Loop closed.

## The measurement loop (every fix obeys this)
1. **Root-cause first** (DDD) — never patch a symptom. Distinguish three causes for each miss/FP:
   (a) a real **agent-recall/precision gap** (fixable via Context), (b) an **eval-harness artifact**
   (the blind per-file pair strips cross-function context a real `/security-review` would have — see
   I-1 caution), or (c) a **label/scope issue** (e.g. architectural classes on the DO-NOT-REPORT line).
2. **Edit the Context** (reference/checklist/KB) — minimal, surgical.
3. **Re-measure**: re-run the agent over the affected subset via the QA harness (neutralized
   filenames), `evals/score.py`, then `evals/keep_or_revert.py` vs `evals/baseline.json`.
4. **Gate:** KEEP only if the target class improves AND overall **J ≥ 0.835** AND **FPR not worse**.
   REVERT otherwise. Runs cost tokens (subscription, no key) — scope to the affected subset.

## Conventions
Inherit `docs/plan/README.md`. TDD for any executable change; reference/KB edits are size-capped
(ADR-005) and pass `validate_kb`/`lint_skill`. IDs typed, never renumbered.

---

### T-12.1 · Root-cause the AuthN/AuthZ misses (analysis-first; harness vs agent vs label)
- **Goal:** explain WHY 9/12 authz cases were missed and decide the cause class (a/b/c above) per case.
- **Artifact:** `docs/qa/20260607/wave-a-findings.md` — per-finding root cause, cause class, fix hypothesis.
- **Depends on:** — (consumes QA-8).
- **Verification criteria:**
  - [x] all 9 authz FN analysed — ALL are `*-open-redirect-*`: the agent flagged them (right line) but categorized `improper-output-handling` vs the label's `AuthN/AuthZ`. Real authz (BOLA/BOPLA/JWT) = TP. Cause = **(c) taxonomy/scope**.
  - [x] harness-artifact hypothesis **REJECTED** — the agent flagged every case; not a recall/batching gap (full-case re-review unnecessary).
  - [x] fix hypothesis: relabel open-redirect to its own category + agent vocab + reconcile exclusion-rule 18 (→ T-12.2).
- **Status:** done — see `docs/qa/20260607/wave-a-findings.md`.

### T-12.2 · Lift AuthN/AuthZ recall via the outer loop (Context edit + re-measure)
- **Goal (reframed by T-12.1):** make open-redirect score correctly — a **taxonomy/scope** fix, NOT a recall fix (the agent already finds all 9). Give open-redirect its own category + reconcile scope with exclusion-rule 18.
- **Artifact:** relabel the 9 `*-open-redirect-*` corpus `label.json` `category` `AuthN/AuthZ`→`open-redirect`; add `open-redirect` to the agent's category vocabulary (review prompt / reference); decide exclusion-rule 18 (keep user-controlled open-redirect as a LOW finding); re-measured run under `docs/qa/<date>/`.
- **Depends on:** T-12.1.
- **Verification criteria:**
  - [x] the 9 open-redirect cases score **TP** (category aligned) on the re-run — `evals/score.py`: open-redirect J=1.00
  - [x] overall **J 0.835→0.971**, **FPR 0.049→0.0** — `keep_or_revert` returned **KEEP**; baseline ratcheted
  - [x] exclusion-rule 18 decision recorded (user-controlled open-redirect = LOW `open-redirect`; inert excluded); corpus + core-checklist consistent; TDD `test_open_redirect_taxonomy.py`
- **Status:** done — see `docs/qa/20260607/waveb-report.md`.

### T-12.3 · Cut the SSRF false-positives (the 5 `py-ssrf*` benigns)
- **Goal:** stop flagging safe SSRF look-alikes (allow-list + DNS-pin + no server-side fetch) without missing real SSRF.
- **Artifact:** edits to `_shared/reference/` SSRF guidance + `exclusion-rules.md` ("mitigated SSRF" recognizer; path-only-SSRF already excluded); re-measured ssrf subset.
- **Depends on:** — (Wave-A root cause done: the agent doesn't credit a host allow-list `assert urlparse(url).hostname in ALLOW` immediately before the fetch; flagged at conf 0.75, borderline).
- **Verification criteria:**
  - [x] the 5 `py-ssrf*` benigns are NOT flagged on the re-run (ssrf **fp 5→0**) — `score.py`
  - [x] ssrf true-positives unchanged (**tp = 16**, no new FN); overall J ≥ 0.835 — `keep_or_revert` KEEP
  - [x] pinned by the corpus allow-list benigns (now clean) + core-checklist §3 + exclusion-rule 20 + `test_open_redirect_taxonomy.py::test_ssrf_allowlist_guard_is_excluded`
- **Status:** done — see `docs/qa/20260607/waveb-report.md`.

### T-12.4 · Resolve the singleton "misses" (crypto, improper-output-handling, tool-poisoning)
- **Goal (reframed in Wave-C grooming):** NOT recall — the agent found all 3 (conf 0.95, right line); each is a defensible **category mismatch**. Decide the canonical category per case (or accept synonyms via T-12.8), and teach the LLM05 precedence for `py-llm05-ssrf`.
- **Artifact:** `docs/qa/20260607/wave-a-findings.md` (root cause); per-case decision + (if chosen) the `score.py` alias map (T-12.8) and/or a core-checklist note that model/tool-output→sink ⇒ `improper-output-handling`.
- **Depends on:** T-12.8 (if the alias-map route is chosen).
- **Verification criteria:**
  - [x] 3 FN root-caused (Wave-C): `py-hardcoded-secret` crypto↔config; `py-llm05-ssrf` improper-output-handling↔ssrf (real LLM05-framing gap); `py-mcp-tokenpassthrough` tool-poisoning↔data-exfil — all *found*, miscategorized
  - [ ] decision recorded + applied (per-case align vs alias-map vs accept); re-measured — `keep_or_revert` KEEP, no FPR regression
  - [ ] `py-llm05-ssrf`: the agent categorizes model/tool-output→sink as `improper-output-handling` (the flagship AI check)
- **Status:** done — all 3 category nits resolved as correctness fixes (LLM05; hardcoded-secret→`crypto`; `py-mcp-tokenpassthrough` relabeled `tool-poisoning`→`data-exfil`) → **J 0.971→1.0**, `keep_or_revert` KEEP, baseline ratcheted. See `docs/qa/20260607/wavec-report.md`.

### T-12.5 · Production re-baseline (opus + k-run bootstrap) — the DEFERRED QA-8 item
- **Goal:** replace the sonnet single-shot baseline with a production-opus, k-run paired-bootstrap baseline so the gate is production-grade.
- **Artifact:** refreshed `evals/baseline.json` (model=opus, k≥3 aggregated), `evals/runs/`, a new `docs/qa/<YYYYMMDD>/` cycle.
- **Depends on:** T-12.2/12.3/12.4 (re-baseline AFTER the fixes land, so the gate reflects the improved agent). Token-budget gated; subscription, no key.
- **Verification criteria:**
  - [ ] baseline.json `model` = opus, k≥3 runs aggregated; drift-guard (`test_baseline_tracks_corpus`) green
  - [ ] refresh documented in `docs/release-checklist.md`; cost recorded
- **Status:** DEFERRED (2026-06-07) — trigger: before the first tagged release (production ships `model: opus`). Not now: sonnet already saturates the corpus (J=1.0) and an opus k-run ≈ multi-M tokens. Pairs with T-12.9.

### T-12.6 · Close the remaining QA tiers (from `qa-flows.md`)
- **Goal:** finish the live/adversarial tiers still open after the 2026-06-07 cycle.
- **Artifact:** updates under `docs/qa/<date>/`.
- **Depends on:** —.
- **Verification criteria:**
  - [ ] QA-3 live: `claude plugin validate` (and/or `--plugin-dir`) loads the plugin; skills namespaced; hooks register
  - [ ] QA-6 live: the first GitHub Actions run (post-push) observed green; fix any runner-specific issue
  - [ ] QA-5 live: a real team-mode handoff (white-hacker → tech-lead via SendMessage, WAIT-exit) exercised
  - [x] QA-7 **reviewed-code** ingestion: agent resists stand-down + FP prompt-injection (`obeyed_any_injected_instruction=false`) — done 2026-06-07. [ ] remaining ingestion points (KB text, feed content)
- **Status:** todo

---

### T-12.7 · Harden `validate_manifest.py` to match `claude plugin validate` (QA-3 follow-up)
- **Goal:** the CI floor validator must reject **unknown top-level keys** in `plugin.json` / `marketplace.json` — the gap that let `$schema` ship past CI until the official `claude plugin validate` caught it (Wave A).
- **Artifact:** `packaging/validate_manifest.py` + tests.
- **Depends on:** — (QA-3 finding).
- **Verification criteria:**
  - [x] an unknown top-level key → validation error (negative test); real repo validates clean — `validate_manifest.py .` exit 0; packaging suite 29→40
  - [~] (optional) CI step invokes `claude plugin validate` when present — deferred (CLI/auth not guaranteed in CI)
- **Status:** done — see `docs/qa/20260607/wavec-report.md`.

### T-12.8 · (optional) `score.py` category-alias map — stop penalizing defensible synonyms
- **Goal:** credit a finding whose category is a defensible synonym of the label's (Wave-C finding: the
  agent's recall is ~100%; every FN is a category-NAME disagreement). Add an alias/overlap map so e.g. a
  `config` finding matches a `crypto` hardcoded-secret — WITHOUT masking genuinely-wrong categories.
- **Artifact:** `evals/score.py` (conservative alias map + matching) + tests; a documented alias table.
- **Depends on:** — (QA-8 / Wave-C finding).
- **Verification criteria:**
  - [ ] TDD: the alias map credits the defined synonyms; a clearly-wrong category (e.g. `xss` for an SSRF) still scores FN — negative test
  - [ ] re-score the snapshot → J rises only via accepted synonyms; baseline refreshed transparently (drift-guard green)
  - [ ] the alias table is conservative + documented (which pairs, and why)
- **Status:** DECLINED (2026-06-07) — an alias-map masks real miscategorizations (e.g. hardcoded-secret, where the *agent* was the loose one). Resolved instead by per-case correctness alignment in T-12.4.

### T-12.9 · Restore eval headroom — add harder corpus cases (J=1.0 saturation follow-up)
- **Goal:** the corpus is saturated (J=1.0; recall ~100%) — add discriminating cases so the eval can
  *measure* agent improvement again, not only catch regressions.
- **Artifact:** new `evals/corpus/cases/*` paired cases — subtle cross-function/ownership authz,
  **bypassable** mitigations (weak allow-lists, partial sanitizers), multi-step/chained sinks, broader
  AI/MCP variety; refreshed baseline + drift-guard.
- **Depends on:** — (pairs with T-12.5 opus re-baseline).
- **Verification criteria:**
  - [x] ≥ N new harder paired cases (labeled, neutralization-safe); corpus count + drift-guard updated
        — **12 `hard-*` cases** (corpus 103→115), no answer-leaking comments, pinned by
        `evals/tests/test_hard_cases_t129.py`; `baseline.json` n_cases 103→115 (J=1.0, FPR 0);
        snapshot 103→115; `test_baseline_tracks_corpus` reproduces. `uv run --project evals --with
        pytest --with jsonschema pytest evals/tests -q` → green.
  - [ ] DEFERRED (→ **T-12.9b**) — the **current sonnet+reference agent still scores J=1.0** on the
        full 115-case set (incl. all 12 hard cases); single-file synthetic pairs do not trip a
        senior-level reviewer. **Headroom is demonstrated, not exercised:** on the 5 subtle FN/FP
        cases an ablated shallow reviewer scored **J=0.8 vs 1.0** (missed authN-present/authZ-missing
        IDOR), proving the metric responds to agent quality. Exercising headroom vs the top agent
        needs multi-file/whole-repo + real-CVE-in-context cases → T-12.9b. See
        `docs/qa/20260607/t-12.9-report.md`.
- **Status:** done — 12 harder cases shipped + baseline refreshed (115, J=1.0) + drift-guard green;
  headroom demonstrated via ablation (1.0 vs 0.8). Residual "trip the top agent" carved out as T-12.9b.

### T-12.9b · Exercise headroom vs the top agent — multi-file / real-CVE-in-context cases (carved from T-12.9)
- **Goal:** make the **current** sonnet+reference agent score < 1.0 (real measurable headroom), which
  single-file synthetic pairs cannot — a senior reviewer aces them (T-12.9 proved this).
- **Artifact:** corpus cases that need **cross-file taint** (source and sink in different modules →
  the reviewer must build a call graph), **real un-patched CVE diffs in surrounding noise**
  (distractors, business logic — not minimal snippets), and **genuinely-ambiguous** severity/category
  pairs that test triage, not just detection. May require a multi-file case shape (extend the harness
  beyond one-file-per-side) + score.py file-set matching.
- **Depends on:** T-12.9. Pairs with T-12.5 (opus + k-run re-baseline before the first tagged release).
- **Verification criteria:**
  - [ ] ≥ 3 multi-file / CVE-in-context cases the current agent does NOT trivially ace (J < 1.0 on the
        expanded subset), measured the same neutralized way; baseline + drift-guard updated
- **Status:** todo (opt-in; budget-gated — live agent runs)

## Wave C — groomed (2026-06-07)
Re-examined against the post-Wave-B state (baseline now **J=0.971 / FPR 0**). Grounded, not guessed.

**Headline finding (reframes T-12.4):** the 3 remaining FN are the *same* pattern as open-redirect —
the agent **found all 3** (vulnerable=true, right line, conf 0.95) but assigned a defensible-but-different
category. ⇒ **the agent's detection recall on this corpus is ~100%; every J<1.0 is a category-NAME
disagreement, not a missed vuln.** That changes "remediation" from "improve recall" to "reconcile taxonomy."

**Re-sequenced by readiness:**
- **T-12.7 (do first)** — gap **confirmed** (a `BOGUS_UNKNOWN_KEY` plugin.json passes `validate_manifest`
  today). Deterministic, in-session, cheap; closes the CI floor-validator gap. No live run.
- **T-12.4 / T-12.8 — a DECISION, low urgency** (J=0.971 already). Pick one: (1) per-case align — small
  but `crypto/config` & `tool-poisoning/data-exfil` are genuinely ambiguous, so partly arbitrary;
  (2) **T-12.8 alias-map** — general root-cause fix, risk of masking real miscategorizations;
  (3) teach the **LLM05 precedence** (model/tool-output→sink ⇒ `improper-output-handling`) for
  `py-llm05-ssrf` only. **TL lean:** T-12.8 alias-map for the 2 ambiguous cases + option-3 for
  `py-llm05-ssrf` (it's the flagship AI check — worth the right category).
- **T-12.5 (opus re-baseline) — cost-flagged.** 103 × opus × k≥3 ≈ multi-M tokens; sonnet already hits
  0.971 with ~perfect recall, so opus's marginal value is mostly *fidelity*. Options: opus **single-shot
  first** (bound cost) → k-run later; or **defer** until a release needs a production-grade gate.
- **T-12.6 split by feasibility:** **QA-7** (untrusted-input red-team) doable **in-session now**;
  **QA-5** (live team-mode) needs `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS` + the white-hacker agent type
  (disconnected this session) → **env-dependent**; **QA-6** (observe CI) needs `gh`/Actions → **manual**.

**Groomed Wave-C order:** T-12.7 (now) → T-12.4 decision (+ T-12.8 if chosen) → QA-7 (in-session) →
T-12.5 / QA-5 / QA-6 (env- or budget-gated, opt-in).

**Wave C done + decisions resolved (2026-06-07)** — see [`../qa/20260607/wavec-report.md`](../qa/20260607/wavec-report.md):
**T-12.7 DONE** (validator rejects unknown keys; packaging 40 tests). **T-12.4 DONE** — all 3 category
nits resolved as correctness fixes (LLM05 model-output→`improper-output-handling`; hardcoded-secret→
`crypto`; `py-mcp-tokenpassthrough` relabeled `tool-poisoning`→`data-exfil`, the label was wrong per
ai-llm §4) → **J 0.971→1.0**, `keep_or_revert` KEEP, baseline ratcheted. **T-12.8 DECLINED**
(alias-map masks real miscategorizations). **QA-7 DONE** (agent resists stand-down + FP injection in
reviewed code). **T-12.5 DEFERRED** (opus, before a tagged release). **651 tests green.**
**⚠️ J=1.0 = corpus SATURATED** (recall was ~100%; gains were category corrections) → headroom to
*measure* improvement is gone, only regression-catching remains → **T-12.9: add harder cases.**

## Priority / ordering
**I-1/I-2 first** (highest-impact agent-quality issues), starting with **T-12.1 root-cause** — it may
show part of I-1 is a *harness artifact* (per-file context-stripping), which would change the fix from
"edit the checklist" to "give the eval more context / document the limitation." Then T-12.2/12.3 in
parallel (different reference sections), T-12.4, then T-12.5 re-baseline once the agent improves, with
T-12.6 (remaining tiers) opportunistic. Each quality fix is a small `sec-learn` diff measured against
the gate — the outer loop doing exactly what it was built for.

## Team execution — grouped waves (TL / Devs / QA / white-hacker)
**Roles.** **TL** — sequence the waves, own each keep-or-revert gate decision, the re-baseline, and
integration. **Devs** — the Context edits + per-case analysis. **QA** — run the measurement loop
(re-run the agent over the affected subset → `score.py` → `keep_or_revert.py`) + the drift-guard.
**white-hacker/security** — review any edit touching untrusted-input/confinement; owns QA-7 adversarial.

**Parallelism rule.** Devs edit **different reference files** (authz: `api.md`/`core-checklist.md` ·
ssrf: ssrf reference + `exclusion-rules.md` · singletons: `crypto`/`ai-llm` reference) → no file
collision. QA measures each fix **in isolation on its subset**, then one **combined full 103-run**
before merge. The gate (overall **J ≥ 0.835**, **FPR ≤ 0.049**) is checked per-fix and on the combined run.

| Wave | Run together | Owners | Gate |
|------|--------------|--------|------|
| **A — analysis** (no gate) | **T-12.1** authz root-cause (incl. harness-vs-agent re-review) · **T-12.3 step 1** ssrf-FP root-cause · **T-12.6 partial** (QA-3 plugin smoke, QA-6 observe CI) | Dev-1+QA · Dev-2 · QA | — |
| **B — fixes** (parallel, after A) | **T-12.2** authz recall · **T-12.3 step 2** ssrf FP fix · **T-12.4** singletons | Dev-1 · Dev-2 · Dev-3; white-hacker reviews ssrf/exclusion + untrusted-input edits; QA measures each | per-fix + combined: KEEP vs `baseline.json` |
| **C — groomed (see Wave-C section)** | **T-12.7** (do first, in-session) → **T-12.4**+**T-12.8** taxonomy decision → **QA-7** (in-session) → **T-12.5** / **QA-5** / **QA-6** (budget/env-gated, opt-in) | Dev (T-12.7/12.8) · TL decides T-12.4 · white-hacker (QA-7) | T-12.7: validate rejects unknown keys · T-12.4/12.8: keep_or_revert KEEP · T-12.5: drift-guard green |

**Dependency DAG:** `T-12.1 → {T-12.2, T-12.4}` · `T-12.3` independent (own analysis) ·
`{T-12.2, T-12.3, T-12.4} → T-12.5` · `T-12.6` opportunistic. Wave A and the cheap T-12.6 items can
start immediately; Wave B fans out 3 Devs once T-12.1 classifies the misses (agent-gap vs harness vs label).
