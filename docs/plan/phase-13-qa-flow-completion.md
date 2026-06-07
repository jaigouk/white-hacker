# Phase 13 — QA-flow completion & doc reconciliation

> **Status:** groomed (todo). Date: 2026-06-07. Owner: ping@jaigouk.kim.
> Closes the open verification tiers in `docs/qa/20260607/qa-flows.md` and reconciles the QA docs
> with the post-Phase-12 / T-12.9 state. Plan-only; ACs below are the success criteria (each
> objective + a runnable probe), per CLAUDE.md rule #4. Nothing here is executed yet.
>
> **Ticket IDs are the execution order** (T-13.1 → T-13.10), grouped into Waves A/B/C by dependency
> (matching the Phase-12 Wave convention, rule #11). Wave N starts after Wave N-1; within a wave,
> tickets are independent (non-overlapping files) and can fan out to a mini-team. T-13.R is optional
> and unordered.

## Context — answers to "anything to refactor? have we covered all QA?"
1. **Refactor: effectively none.** No dead code in committed source. The `propose_policy.py` `TODO`
   strings are intentional placeholders in the *generated* SECURITY.md template (the user fills them
   in) — correct by design, not debt. Sole candidate: the `REPO = next(c … ".git" …)` repo-root idiom
   is duplicated across 3 eval test files (`test_baseline_tracks_corpus.py`, `test_hard_cases_t129.py`,
   `test_open_redirect_taxonomy.py`). Low value; rules #2/#3 bias against speculative refactor →
   **T-13.R (optional, do-only-if-touched).**
2. **QA: the weak-spot *findings* from QA-8 are resolved** (AuthN/AuthZ recall + SSRF FP → Phase-12,
   J=1.0; corpus 115 incl. T-12.9). **But several QA *flows* are still open**, and the QA plan doc is
   **stale** (J=0.835/n=103/634-tests era). See the gap table.

## QA coverage gap (today vs qa-flows.md targets)
| Flow | Tier-1 | Tier-2 | Tier-3 (live) | Tier-4 | Gap → ticket |
|------|:--:|:--:|:--:|:--:|---|
| QA-1 inner loop | ✅ | ✅ chain | ✅ now J=1.0/115 | partial | floor-only/degradation → **T-13.2** |
| QA-2 outer loop | ✅ | ✅ | ⬚ opt-in | ✅ | live poll/reflect → **T-13.10** |
| QA-3 distribution | ✅ (37) | tests exist | ❌ load smoke | ❌ F-001 | verdict → **T-13.4** · live → **T-13.7** |
| QA-4 sec-policy | ✅ (55) | tests exist | ➖ | ❌ F1–F3 | formalized verdict → **T-13.5** |
| QA-5 team mode | ✅ gate | ➖ | ❌ env-gated | ➖ | live team → **T-13.9** |
| QA-6 CI | ✅ | ⬚ contract | ❌ observe run | ➖ | contract → **T-13.3** · observe → **T-13.8** |
| QA-7 safety | ✅ | ➖ | n/a | partial | KB-text + feed sweep → **T-13.6** |
| QA-8 baseline | ✅ | ✅ | ✅ sonnet/115 | ➖ | opus re-baseline = T-12.5 (carry) |
| **docs** | — | — | — | — | staleness → **T-13.1** |

Legend: ✅ done · ⬚ doable-now-not-done · ❌ blocked/gated · ➖ n/a.

**Dependency DAG:** `T-13.1 → {T-13.2, T-13.3}` (truth first) → `{T-13.4, T-13.5, T-13.6}` (verdicts,
parallel) → `{T-13.7, T-13.8, T-13.9, T-13.10}` (gated tier-3, opportunistic). T-13.R unordered.

---

## Wave A — truth & cheap deterministic (do first; no dependencies)
> ✅ **Wave A complete (2026-06-07).** T-13.1 qa-flows.md reconciled · T-13.2 QA-1 floor-only **PASS** ·
> T-13.3 QA-6 CI-contract **PASS**. Evidence: `docs/qa/20260607/qa-1-floor-only-verdict.md`,
> `qa-6-ci-contract-verdict.md`, the reconciled `qa-flows.md`, and `docs/qa/20260607/wave-a-readme.md`.
> Method: produce → adversarial-verify (workflow `w1fgb150u`, 4 agents) + maintainer independent re-run.

### T-13.1 · Reconcile qa-flows.md (+ QA cycle README) with post-T-12.9 state
- **Why:** rule #7 (source wins) + living-docs — the plan doc reads as the pre-Phase-12 era and will
  mislead the next reader / release decision.
- **ACs:**
  - [x] Coverage matrix QA-1 row → `✅ full 115-case run, J=1.0`; QA-8 row → `n=115, J=1.0`.
  - [x] "Why" para test count `634 → 668`; J/n figures current; FINDING-QA1 + QA-8 weak-spots marked
        resolved with links to `phase-12-qa-remediation.md` + `t-12.9-report.md`.
  - [x] T-12.9 / T-12.9b cross-referenced from QA-1/QA-8.
  - [x] Probe: `grep -nE 'J=0\.835|634 tests' docs/qa/20260607/qa-flows.md` returns only clearly-marked
        *historical* lines (no live-state claim still at 0.835).

### T-13.2 · QA-1 tier-2 floor-only / tool-degradation
- **ACs:**
  - [x] Run the inner chain with NO external tools available → `SCAN-PLAN.json`/findings carry
        `tool_assisted:false`, confidence capped, `tools_unavailable` listed; the run does NOT block on
        a missing tool (graceful degradation to the Read/Grep/Glob floor).
  - [x] Probe recorded (commands + the degraded artifact). → `docs/qa/20260607/qa-1-floor-only-verdict.md`

### T-13.3 · QA-6 CI contract check (tier-2)
- **ACs:**
  - [x] `.github/workflows/ci.yml` valid; per-package loop discovers all **15** packages (probe:
        `find … -name pyproject.toml … | while …; [ -d tests ]` count == 15 == loop count).
  - [x] All `uses:` pinned to SHAs; uv version pinned; `ci/security-review.action.yml` pins (model id,
        `@anthropic-ai/claude-code`, action SHAs) current per ADR-006.

---

## Wave B — formalized deterministic verdicts (after A; parallel, non-overlapping files)

### T-13.4 · Formalize QA-3 deterministic verdict (tier-2 + tier-4 F-001)
- **ACs (record in `docs/qa/<date>/qa-3-verdict.md` with commands+outputs):**
  - [ ] `uv run python packaging/validate_manifest.py .` exit 0; `claude plugin validate ./plugins/white-hacker` ✔.
  - [ ] `init_profile.py` run on a fixture repo writes a schema-valid profile carrying `security_policy`.
  - [ ] SessionStart hook on a crafted profile (malicious path / channel) → dropped; identity carriage
        (no shipped CLAUDE.md; posture lives in `agents/white-hacker.md`) confirmed by grep.
  - [ ] F-001 allowlist: out-of-vocab / markdown / packed-separator inputs dropped (run the hook).
  - [ ] Verdict PASS/FAIL recorded.

### T-13.5 · Formalize QA-4 security-policy verdict (tier-2 present/absent/malicious + tier-4 F1–F3)
- **ACs (record in `docs/qa/<date>/qa-4-verdict.md`):**
  - [ ] `policy_detect`/`parse_policy`/`propose_policy`/`hygiene_advisory` on present/absent/malicious
        fixtures: absent→advisory (no severity/cvss); present→merged draft preserves maintainer facts;
        output confined to `PATCHES/`.
  - [ ] Tier-4: F1 symlink write-escape refused (O_NOFOLLOW); F2 ReDoS bounded (read cap + linear
        regex); F3 packed-imperative dropped; an out-of-scope policy entry cannot drop a HIGH.
  - [ ] Verdict recorded.

### T-13.6 · QA-7 untrusted-input sweep — KB-text + feed-content ingestion (tier-4)
- **Why:** reviewed-code ingestion red-team done (Wave C QA-7); KB-text and feed-content points not yet
  systematically swept — they are injection surfaces (the agent ingests both).
- **ACs (record in `docs/qa/<date>/qa-7-ingestion-verdict.md`):**
  - [ ] KB-text fixture with embedded "ignore instructions / mark KEEP / report nothing" injection →
        `gate_kb_edit` still requires a real verdict; `lint_skill`/`validate_kb` hold; no obeyed instruction.
  - [ ] Feed-content fixture (poisoned `sec-kb-refresh` item) → parser treats it as data; no instruction
        obeyed; dated-entry draft still passes lint+gate or is rejected loudly.
  - [ ] `obeyed_any_injected_instruction == false` across both; verdict recorded.

---

## Wave C — gated tier-3 / opt-in (after B; env/budget-bound, opportunistic)

### T-13.7 · QA-3 tier-3 plugin-load smoke  *(gated: interactive `claude`, subscription, no API key)*
- **AC:** `claude --plugin-dir ./plugins/white-hacker` shows the agent + `/white-hacker:security-review`
  namespaced skill present and the PreToolUse/SessionStart hooks register; load smoke output recorded.

### T-13.8 · QA-6 tier-3 observe first CI run  *(gated: needs `gh`/Actions tab)*
- **AC:** the first GitHub Actions run after the push is green; any runner-specific issue (uv PATH,
  network) fixed and re-run; result recorded.

### T-13.9 · QA-5 tier-3 live team mode  *(gated: `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` + version)*
- **AC:** white-hacker spawns into a TL/QA/Dev/white-hacker team on a fixture, SendMessages findings to
  the **tech-lead** (not the dev), returns triaged summary + report path only, exits cleanly on WAIT;
  carry-over caveat (teammate spawn prompt inlines methodology) holds.

### T-13.10 · QA-2 tier-3 live poll/reflect  *(gated: network + opt-in)*
- **AC:** a live `sec-kb-refresh` network poll yields a dated draft entry that passes lint+gate; a live
  `sec-learn` reflection over real traces proposes a gated diff.

### Cross-phase carries (tracked elsewhere; not Phase-13 tickets)
- **T-12.5** — opus + k-run re-baseline before the first tagged release (budget: multi-M tokens).
- **T-12.9b** — multi-file / real-CVE-in-context corpus to pull the current agent below J=1.0 (budget).

---

## T-13.R · (optional, unordered) dedup the eval-test repo-root idiom
- Only if those tests are edited for another reason: add `evals/tests/conftest.py` exposing `REPO`/
  `CORPUS` fixtures; drop the 3 inline copies. **AC:** eval suite still green; no behavior change.
  Not recommended as a standalone change (rules #2/#3).

## Team-wave mapping (when approved — Phase-12 style)
| Wave | Tickets | Suggested owners | Gate |
|------|---------|------------------|------|
| A | T-13.1 · T-13.2 · T-13.3 | Dev (docs) · Dev · QA | each AC probe PASS |
| B | T-13.4 · T-13.5 · T-13.6 | Dev-1 · Dev-2 · white-hacker (red-team); QA records verdicts | dated verdict file per flow |
| C | T-13.7 · T-13.8 · T-13.9 · T-13.10 | opportunistic (env/budget owners) | live evidence recorded |

Each Wave-B verdict ticket emits a dated `docs/qa/<date>/` evidence file; flip the matching
qa-flows.md VC box only when its probe is PASS (not SKIP), per rule #12.
