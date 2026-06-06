# Phase 9 — Eval guardrails (frozen corpus; keep-or-revert gate; passive-drift)

> **Theme:** harden the Phase-7 baseline into the **frozen, agent-read-only** corpus + the asymmetric
> **keep-or-revert gate** that every outer-loop self-write must pass before merge. This is the ratchet
> that lets the OUTER loop edit the KB without drifting: a candidate KB version is kept **only** if it
> strictly improves (or holds) without regressing any locked case.
> **Maps to:** si-08 §6 (corpus/scoring/thresholds), §3.4 (loop guardrails), §5.2 (pre-commit checklist),
> §6.5 (CI layers + passive-drift); ADR-004 (gate before autonomy), ADR-001 (outer-loop gate).
>
> **Loop position:** OUTER (the gate). **Gating dependency:** no `sec-learn`/`sec-kb-refresh` change
> merges until this phase exists (README ordering note; si-08 §7 "nothing graduates to autonomy until the
> corpus exists"). Build Phase 8 (proposers) and Phase 9 (gate) up to the merge boundary, then the gate
> closes.
> **Exit condition:** the gate script, given a candidate KB diff, runs the frozen corpus, computes the
> asymmetric verdict, and **blocks** any change that regresses recall/precision/severity or breaks a
> locked case — wired as a CI check **and** a `PreToolUse`/`Stop` hook on KB edits.

---

### T-9.1 · Freeze the corpus (read-only to the agent, signed, ≥ 100 paired cases)
- **Goal:** grow the Phase-7 corpus to ≥ 100 paired cases (vulnerable + benign look-alike; AI/LLM sinks
  covered separately; CVE regression anchors from si-08 §6.1 incl. vLLM CVE-2026-22807 / CVE-2026-22778,
  LangChain CVE-2025-68664), mark it **frozen** (signed commit), and enforce agent-write-block via the
  Phase-8 confinement hook (T-8.4). Add a `evals/corpus/LOCKED` marker listing the locked case ids.
- **Artifact:** `evals/corpus/` (grown), `evals/corpus/LOCKED`, `evals/corpus/README.md` (provenance +
  freeze note)
- **Depends on:** T-7.1, T-8.4
- **Verification criteria:**
  - [ ] ≥ 100 case dirs, each with all four files + valid `label.json` — `[ $(ls -d evals/corpus/cases/*/ | wc -l) -ge 100 ] && uv run pytest evals/tests/test_labels.py`
  - [ ] CVE regression anchors present — `for c in CVE-2026-22807 CVE-2026-22778 CVE-2025-68664; do grep -rq "$c" evals/corpus/cases/ || echo MISSING:$c; done` prints nothing
  - [ ] The confinement hook denies an agent write under `evals/corpus/**` — `uv run pytest .claude/hooks/tests/test_confine_self_writes.py -k corpus`
  - [ ] `evals/corpus/LOCKED` enumerates the locked case ids — `test -s evals/corpus/LOCKED`
- **Status:** todo

### T-9.2 · `keep_or_revert.py` — asymmetric gate (agent cannot edit it)
- **Goal:** the gate (si-08 §6.4): given baseline vs candidate scores, **HARD REVERT** if `recall_loss >
  2pp` OR `FPR_gain > 1pp` OR any single locked case regresses; **KEEP only if** J non-inferior AND
  (J improves > 0.01 OR new sink coverage added); SECURITY GATE: severity-weighted recall ≥ baseline AND
  precision ≥ baseline − epsilon. 3-valued verdict (Pass/Fail/Inconclusive) from a paired bootstrap,
  k=3–5 runs/case (runs are non-deterministic). Regression = recall drop · precision drop · severity
  inversion · fix-target-break-other. The script itself is **read-only to the agent** (hook-blocked).
- **Artifact:** `evals/keep_or_revert.py` (+ `evals/tests/test_keep_or_revert.py`)
- **Depends on:** T-7.2, T-9.1
- **Verification criteria:**
  - [ ] Each threshold fires correctly on crafted score pairs (recall −2.5pp → REVERT; FPR +1.5pp → REVERT; J +0.02 no-regress → KEEP; locked-case regress → REVERT) — `uv run pytest evals/tests/test_keep_or_revert.py` (one test per branch)
  - [ ] Returns the 3-valued verdict; "fix target while breaking any other case" → REVERT — dedicated test (si-08 §6.3)
  - [ ] Paired-bootstrap with k≥3 runs produces a stable verdict on a deterministic synthetic input — determinism/stability test
  - [ ] The confinement hook denies an agent write to `evals/keep_or_revert.py` — `uv run pytest .claude/hooks/tests/test_confine_self_writes.py -k keep_or_revert`
- **Status:** todo

### T-9.3 · Wire the gate as a merge gate + PreToolUse/Stop hook on KB edits
- **Goal:** express the gate as DeepEval-style pytest assertions for clean CI diffing, run it in the CI
  Action on any PR that touches `ai-attack-kb/**` or `_shared/reference/**`, **and** wire it as a
  `PreToolUse`/`Stop` hook so an in-session KB edit is gated before it can be proposed. A failing gate
  blocks the merge; a passing gate plus a green pre-commit safety checklist (T-9.4) allows the draft PR.
- **Artifact:** `evals/tests/test_gate_ci.py` (DeepEval assertions), CI step in
  `ci/security-review.action.yml`, `.claude/hooks/gate_kb_edit.sh` (+ test)
- **Depends on:** T-9.2, T-6.3, T-8.4
- **Verification criteria:**
  - [ ] CI gate step runs `keep_or_revert.py` and fails the job on a REVERT verdict — `uv run pytest evals/tests/test_gate_ci.py`; CI YAML has the step — `grep -q 'keep_or_revert' ci/security-review.action.yml`
  - [ ] The `PreToolUse` hook gates a KB-edit event (blocks on REVERT, allows on KEEP) — `uv run pytest .claude/hooks/tests/test_gate_kb_edit.py`
  - [ ] A simulated regressing KB diff is blocked end-to-end (logged demonstration) — `evals/audit-log.md` records the REVERT verdict + diff
- **Status:** todo

### T-9.4 · Pre-commit safety checklist enforcement (the 10 gates)
- **Goal:** enforce the si-08 §5.2 mandatory checklist as a single PreToolUse-blocked self-write gate:
  schema/spec caps · references one-level-deep · source-linking present · dedup passed · identity
  preservation (no edit to agent role/`.claude/rules/`/CLAUDE.md) · confinement · self-critique passed ·
  promotion eligibility (≥ 3 sessions) · regression gate green · it is a PR on a feature branch (not
  default, not autocommit). On any failure: do not write, log to `evals/rejected.md`.
- **Artifact:** `.claude/skills/ai-attack-kb/scripts/precommit_safety.py` (+ `tests/`), `evals/rejected.md`
  (seed), `evals/audit-log.md` (seed)
- **Depends on:** T-8.1, T-8.2, T-9.2
- **Verification criteria:**
  - [ ] All 10 gates implemented; a self-write failing any one is blocked and logged to `rejected.md` — `uv run pytest .claude/skills/ai-attack-kb/scripts/tests/test_precommit_safety.py` (≥ 1 test per gate)
  - [ ] An edit touching the agent role / `.claude/rules/` / CLAUDE.md is **always** blocked (identity preservation, non-negotiable) — dedicated negative test
  - [ ] A clean, sourced, deduped, gate-green PATCH on a feature branch passes all 10 — positive test
  - [ ] Rejections append to `evals/rejected.md` so the loop never re-proposes a known loser — test asserts the append
- **Status:** todo

### T-9.5 · Passive-drift re-score + nightly red-team + second ratchet
- **Goal:** a weekly scheduled full-corpus re-score against the same thresholds (catches silent
  regression when the underlying model/provider updates, not just on self-edits); a nightly red-team
  layer (AI-redteam capability — illustrative: promptfoo redteam + Inspect) added as a CI/scheduled
  check; and the **second ratchet** — newly-confirmed true findings (+ labels) promoted INTO the frozen
  corpus so the bar keeps rising (si-08 §3.4 / §6.5).
- **Artifact:** `docs/self-improvement/eval-ops.md` (drift re-score + red-team schedule + ratchet
  procedure) + `evals/scripts/promote_finding.py` (+ test)
- **Depends on:** T-9.2, T-8.7
- **Verification criteria:**
  - [ ] Doc defines the weekly passive-drift re-score against `baseline.json` thresholds — `grep -qi 'passive.drift\|weekly' docs/self-improvement/eval-ops.md && grep -q 'keep_or_revert\|baseline' docs/self-improvement/eval-ops.md`
  - [ ] Red-team layer documented behind the AI-redteam **capability** (degradable, not a hard tool dep) — `grep -qi 'red.team' docs/self-improvement/eval-ops.md && grep -qi 'capability\|optional\|degrad' docs/self-improvement/eval-ops.md`
  - [ ] `promote_finding.py` adds a confirmed finding as a new locked case + label and is itself outside agent write-scope (must be run by the human/CI identity) — `uv run pytest evals/tests/test_promote_finding.py`
- **Status:** todo

### T-9.6 · Graduated-autonomy policy (earn it per-step)
- **Goal:** document the graduation policy (si-08 §7 Phase 5): everything human-gated first; only after a
  clean track record (e.g. ≥ 20 PRs where human approval matched the gate verdict) may the **lowest-risk,
  highest-precision** class be loosened — auto-merge **feed-sourced PATCH-only** fast-tier entries that
  pass the gate green, add no new sink, carry valid source+url+retrieved. CREATE, checklist edits, and any
  rule/CLAUDE.md change **remain human-gated indefinitely** (identity preservation non-negotiable).
- **Artifact:** `docs/self-improvement/autonomy-policy.md`
- **Depends on:** T-9.3, T-9.4
- **Verification criteria:**
  - [ ] Policy states the track-record threshold + the exact auto-merge-eligible class (feed-sourced PATCH-only, fast-tier, gate-green, no new sink, sourced) — `grep -qi 'patch-only\|patch only' docs/self-improvement/autonomy-policy.md && grep -qi 'feed-sourced\|fast tier' docs/self-improvement/autonomy-policy.md`
  - [ ] States CREATE / checklist / rule / CLAUDE.md edits stay human-gated indefinitely — `grep -qi 'indefinit\|human-gated' docs/self-improvement/autonomy-policy.md && grep -qi 'identity' docs/self-improvement/autonomy-policy.md`
  - [ ] References the second ratchet keeps running as autonomy widens — `grep -qi 'ratchet' docs/self-improvement/autonomy-policy.md`
- **Status:** todo
