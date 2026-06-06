# Phase 8 — Self-improvement (KB structure & lint; `sec-learn`; `sec-kb-refresh`; capture hooks)

> **Theme:** build the **OUTER loop** — the machinery that *edits* the knowledge base over time, all on
> the Context + Harness surfaces (no retraining; every change a reviewable git diff). Three parts:
> (1) KB structure & lint (size caps, schema, dedup, staleness); (2) the `sec-learn` reflective loop
> (trace → reflect → propose dated diffs → PR); (3) the `sec-kb-refresh` feed + tool poller; plus the
> deterministic capture hooks and `PreToolUse` confinement guardrails that make the loop safe.
> **Maps to:** si-08 §1–§5; ADR-001 (outer loop), ADR-004 (Context+Harness, human-in-loop first),
> ADR-005 (size caps), ADR-012 (living KB), **ADR-015** (registry self-updates with the KB).
>
> **Loop position:** OUTER. The inner loop *consumes* the KB (Phase 4); this phase *edits* it.
> **Build order:** Phase 8 (capture + structure + propose) → Phase 9 (the gate). **No self-write may
> merge until Phase 9's frozen corpus + keep-or-revert gate exist** (README ordering note; si-08 §7).
> **Exit condition:** capture hooks log traces deterministically; confinement hooks deny out-of-scope
> writes; `lint_skill`/`validate_kb`/`dedupe_kb`/`staleness_check` pass in CI and as PreToolUse gates;
> `sec-learn` and `sec-kb-refresh` each produce a **draft PR** (never auto-merge) of dated, sourced diffs.

> **Key principle (si-08 §1):** guardrails belong in the **harness**, never in memory. Confinement of
> self-writes, secret-read blocking, and egress control are enforced by `PreToolUse` hooks +
> `settings` `permissions.deny`, not advised in CLAUDE.md.

---

## Grooming (re-groomed 2026-06-06, after Phase 7)

**Readiness:** ✅ READY. Phases 0–7 done. (Outer-loop *self-writes* still must not merge until
Phase 9's frozen corpus + keep-or-revert gate exist — README ordering note.)

**Reconciliations (own these):**
1. **`validate_kb.py` already exists** (built in T-4.1, 18 tests: schema, mandatory
   `source`+`url`+`retrieved`, controlled enums, size caps, unique ids). So **T-8.1 = ADD
   `lint_skill.py` only** (ADR-005 caps over *all* skills) + confirm `validate_kb` already satisfies
   its schema-gate VCs. Likely fix: trim any skill `description` that exceeds the caps.
2. **Hook registration is the same human-auth blocker (Phases 5/6/8).** T-8.3 (capture) and T-8.4
   (`confine_self_writes`) hooks are **implemented + tested** as the done-gate; their committed
   `.claude/settings.json` registration is **batched into the one operator-authorized approval**
   alongside T-5.3/T-6.4/T-6.5. `confine_self_writes` composes as a **3rd** `PreToolUse` Bash entry
   with `confine_patch_writes` (T-5.3) + `guard_bash` (T-6.4); its allow-set is the outer-loop one
   (KB `reference/**`, `.claude/rules/**`, `PATCHES/**`, memory) and it **denies `evals/corpus/**` +
   the gate scripts** (frozen, separate identity) — reconcile so the three hooks don't conflict.
3. **⚠️ T-8.7 conflicts with the operator's standing "no autonomous schedulers" preference.**
   Resolution: **T-8.7 is DOCUMENT-ONLY.** Write `refresh-routine.md` (cadence tiers + how the
   operator creates/disables the Routine via `/schedule`); **do NOT create a live scheduled task.**
   All T-8.7 VCs are doc-greps, satisfiable without scheduling anything. (Honors the preference; the
   refresh poller `poll_feeds.py` still exists and can be run manually.)
4. **Capture hooks (T-8.3):** append-only JSONL + **secret redaction** (a `.env`-read event yields a
   redacted line) — never write a secret value to a trace.
5. **`poll_feeds.py` (T-8.6):** tests use **recorded fixtures, no network**; live polling honors the
   egress allow-list enforced by `guard_bash`/`confine_self_writes`.
6. **Traces live under `evals/traces/`** but the **frozen** corpus/gate (`evals/corpus/**`,
   `evals/keep_or_revert.py`) are agent-read-only — `confine_self_writes` must allow `evals/traces/**`
   while denying `evals/corpus/**` (Phase 9 builds the gate script).

**Order:** T-8.1 → T-8.2 → (T-8.3 ∥ T-8.4) → (T-8.5 ∥ T-8.6) → T-8.7 (doc). **DoD:** lint/validate/
dedupe/staleness green over the seed KB + all skills; capture + confinement hooks tested (registration
batched for auth); `sec-learn`/`sec-kb-refresh` bodies de-stubbed + `harvest.sh`/`poll_feeds.py` tested
(no network); `refresh-routine.md` written (no live schedule). Then **re-groom Phase 9**.

---

## 8a — KB structure & lint (the size/schema/dedup spine)

### T-8.1 · `lint_skill` + `validate_kb` size-cap & schema gate (TDD)
- **Goal:** a tested validator enforcing ADR-005 caps (`description`+`when_to_use` ≤ 1,536; `description`
  ≤ 1,024; `name` ≤ 64 (ADR-005; a skill's *command* comes from its directory name, not `name`); `SKILL.md` < 500 lines; `reference/` one
  level deep) **and** the KB entry schema from T-4.1 (mandatory `source`+`url`+`retrieved` regex-matched,
  controlled `technique_class`, `status` enum, summary ≤ 120 words). Refuses to pass an unsourced threat
  claim. This is the script every "lint passes" criterion in earlier phases refers to.
- **Artifact:** `.claude/skills/ai-attack-kb/scripts/{lint_skill.py,validate_kb.py}` (+ `pyproject.toml`,
  `tests/` with fixtures: a passing skill, an over-cap skill, an unsourced KB entry)
- **Depends on:** T-4.1
- **Verification criteria:**
  - [ ] All caps + schema rules enforced; passing & failing fixtures behave correctly — `uv run pytest .claude/skills/ai-attack-kb/scripts/tests/test_lint_skill.py .claude/skills/ai-attack-kb/scripts/tests/test_validate_kb.py`
  - [ ] An unsourced AI-threat entry (no `metadata.source`) is **rejected** — dedicated negative test (si-08 §2.2 blocking rule)
  - [ ] Running `lint_skill` over **all** current skills passes — `uv run python .claude/skills/ai-attack-kb/scripts/lint_skill.py .claude/skills/` exits 0
  - [ ] Running `validate_kb` over the seed KB passes — `uv run python .claude/skills/ai-attack-kb/scripts/validate_kb.py .claude/skills/ai-attack-kb/reference/` exits 0
- **Status:** todo

### T-8.2 · `dedupe_kb` + `staleness_check` (anti-drift)
- **Goal:** two tested scripts: `dedupe_kb.py` (controlled `technique_class` vocab + shared-xref / title-
  similarity flagging; CI fails on duplicate `id`s; merges via `supersedes` lineage) and
  `staleness_check.py` (flags entries past `review_by`; moves to `archive/`, never deletes). Cadence rule
  baked in: the refresh routine touches the **fast tier (`ai-attack-kb/reference/`) only**; stable
  `_shared/reference/` checklists are out of its scope (README layout reconcile).
- **Artifact:** `.claude/skills/ai-attack-kb/scripts/{dedupe_kb.py,staleness_check.py}` (+ `tests/`),
  `.claude/skills/ai-attack-kb/archive/` (created)
- **Depends on:** T-8.1
- **Verification criteria:**
  - [ ] Duplicate `id` across entries fails the run; a shared-xref pair is flagged for merge — `uv run pytest .claude/skills/ai-attack-kb/scripts/tests/test_dedupe_kb.py` (>1 case)
  - [ ] An entry with `review_by` in the past is flagged stale; a future one is not — `uv run pytest .claude/skills/ai-attack-kb/scripts/tests/test_staleness_check.py`
  - [ ] Aging-out moves to `archive/` (no delete) — test asserts the file is relocated, content preserved
  - [ ] Seed KB has no duplicate ids and no stale entries — `uv run python .claude/skills/ai-attack-kb/scripts/dedupe_kb.py .claude/skills/ai-attack-kb/reference/ && uv run python .claude/skills/ai-attack-kb/scripts/staleness_check.py .claude/skills/ai-attack-kb/reference/` both exit 0
- **Status:** todo

## 8b — Capture hooks + PreToolUse confinement guardrails (the harness)

### T-8.3 · Deterministic capture hooks (traces, failures, corrections) — JSONL, ~0 cost
- **Goal:** wire `PostToolUse` / `PostToolUseFailure` / `SessionEnd` / `Stop` hooks (async, no LLM cost)
  that append each tool call, each failed exploit attempt, and user corrections to
  `evals/traces/findings-YYYY-MM.jsonl`; `SessionStart` injects the CVE/freshness digest produced by the
  refresh routine. Schema verified in si-08 §3.1 / Appendix B.
- **Artifact:** `.claude/hooks/{append_trace.sh,log_failed_exploit.sh,log_corrections.sh,
  inject_cve_digest.sh,save_learnings_nudge.sh}` (+ `tests/`), wired in `.claude/settings.local.json`
- **Depends on:** —
- **Verification criteria:**
  - [ ] Each hook script, fed a sample hook-event JSON on stdin, appends a well-formed JSONL line / emits the digest — `uv run pytest .claude/hooks/tests/test_capture_hooks.py` (one case per hook)
  - [ ] Hooks are registered under the correct events with valid schema — `python -c 'import json;h=json.load(open(".claude/settings.local.json"))["hooks"];assert all(k in h for k in ["PostToolUse","SessionEnd","Stop"])'`
  - [ ] Capture is append-only and never writes a secret value (redaction) — negative test: a `.env` read event yields a redacted trace line
- **Status:** todo

### T-8.4 · `PreToolUse` confinement + secret-block + egress guardrails
- **Goal:** a `PreToolUse` hook (exit 2 / `permissionDecision: deny`) that: denies any `Write`/`Edit`
  outside `ai-attack-kb/**`, `.claude/rules/**`, `PATCHES/**`, and the auto-memory dir; denies reads of
  `**/.env`, `**/secrets/**`, private keys; denies network egress except the allow-listed feed hosts;
  and **blocks agent writes to `evals/corpus/**` and the gate scripts** (frozen, separate identity —
  si-08 §3.4). Extends the same hooks block from Phase 6. Deny wins, merges across scopes.
- **Artifact:** `.claude/hooks/confine_self_writes.sh` (+ `tests/`), `.claude/settings.local.json`
  `permissions.deny`
- **Depends on:** T-6.4 (shares the hooks block)
- **Verification criteria:**
  - [ ] Denies a write to `src/x`, `evals/corpus/x`, `evals/keep_or_revert.py`; allows a write to `ai-attack-kb/reference/x.md` and `PATCHES/x` — `uv run pytest .claude/hooks/tests/test_confine_self_writes.py` (≥ 3 deny + ≥ 2 allow cases incl. `../` traversal)
  - [ ] Denies a read of `.env` / private key and any egress outside the feed allow-list — dedicated negative tests
  - [ ] `settings.local.json` `permissions.deny` lists the corpus + gate-script paths — `python -c 'import json;d=json.load(open(".claude/settings.local.json"));print(d["permissions"]["deny"])'` includes `evals/corpus` and `keep_or_revert`
- **Status:** todo

## 8c — The reflective loop + the feed/tool poller (the proposers)

### T-8.5 · Implement `sec-learn` body (reflect → propose dated diffs → PR)
- **Goal:** `sec-learn/SKILL.md` runs the GEPA *control flow* (si-08 §3.2) in a forked context: harvest
  this week's traces + corrections; for each FP/miss emit **structured rationale** (`why_missed` /
  `why_fp_fired`, root cause, minimal edit); pre-gate (seen ≥ 3 sessions, same fix, 1–2 sentences, system
  unchanged); self-critique (generalizable, not overfit); **default PATCH over CREATE**; propose dated,
  sourced diffs to KB / `_shared/reference/` checklists / **`tool-registry.md`** (ADR-015 — new tools
  too); write to a branch and open a PR with evidence (session ids, motivating FP/miss, before/after
  score table). Never writes the live KB; never merges itself.
- **Artifact:** `.claude/skills/sec-learn/SKILL.md` (+ `scripts/harvest.sh` with a test)
- **Depends on:** T-8.1, T-8.3
- **Verification criteria:**
  - [ ] Body documents reflect → pre-gate (N≥3) → self-critique → PATCH-over-CREATE → branch+PR-with-evidence — `for k in 'why_missed\|why_fp' 'seen.*3\|≥ *3\|>= *3' 'self-crit\|overfit' 'patch over create\|default.*patch' 'PR\|branch'; do grep -qiE "$k" .claude/skills/sec-learn/SKILL.md || echo MISSING:"$k"; done` prints nothing
  - [ ] States it proposes tool-registry additions, not just KB/checklist (ADR-015) — `grep -q 'tool-registry' .claude/skills/sec-learn/SKILL.md`
  - [ ] `harvest.sh` collates traces+corrections into the reflection input — `uv run pytest .claude/skills/sec-learn/scripts/tests/test_harvest.py`
  - [ ] States "never auto-merge / behind the eval gate" and `disable-model-invocation` (manual trigger) — `grep -qi 'never.*merge\|human' .claude/skills/sec-learn/SKILL.md && grep -q 'disable-model-invocation' .claude/skills/sec-learn/SKILL.md`; de-stubbed
- **Status:** todo

### T-8.6 · Implement `sec-kb-refresh` feed + tool poller (incremental diff → dated draft PR)
- **Goal:** `sec-kb-refresh/SKILL.md` + a tested poller: poll the authoritative feeds
  (`docs/research/si-07-threat-feeds.md`: OSV.dev query/querybatch, GitHub Advisory, arXiv cs.CR
  LLM-filtered, ATLAS dist, OWASP/blog atom) using stored last-seen markers in `evals/feed-state.json`
  (process deltas only); LLM-extract NEW techniques **and newly-useful tools**; map each to a
  `technique_class` + ATLAS/OWASP/CVE source; draft schema-conforming dated entries (source+url+retrieved
  mandatory); run `validate_kb` + `dedupe_kb`; open a **draft PR, never auto-merge**; write the digest for
  `inject_cve_digest.sh`. Touches the **fast tier only**.
- **Artifact:** `.claude/skills/sec-kb-refresh/SKILL.md` (+ `scripts/poll_feeds.py`, `pyproject.toml`,
  `tests/` with recorded feed fixtures), `evals/feed-state.json` (seed)
- **Depends on:** T-8.1, T-8.2
- **Verification criteria:**
  - [ ] Poller diffs incrementally against `feed-state.json` (no re-processing seen items) and parses a recorded OSV/ATLAS/atom fixture into candidate entries — `uv run pytest .claude/skills/sec-kb-refresh/scripts/tests/test_poll_feeds.py` (>1 feed type; an unchanged-feed run yields zero new entries)
  - [ ] Drafted entries pass `validate_kb` (mandatory source+url+retrieved) and `dedupe_kb` — test runs both on poller output
  - [ ] SKILL states "fast tier only / never auto-merge / draft PR" and proposes tool-registry additions (ADR-015) — `grep -qi 'fast tier\|never.*merge\|draft pr' .claude/skills/sec-kb-refresh/SKILL.md && grep -q 'tool-registry' .claude/skills/sec-kb-refresh/SKILL.md`; de-stubbed
  - [ ] No network call in tests (fixtures only); live polling honors the egress allow-list (T-8.4) — tests mock/replay; no real HTTP asserted
- **Status:** todo

### T-8.7 · Schedule the refresh routine (cloud, off-peak, draft PR)
- **Goal:** register `sec-kb-refresh` as a scheduled cloud Routine (via `/schedule`, hourly-minimum
  cadence; daily JSON/RSS, weekly blogs, monthly frameworks per si-08 §4) that runs to completion on a
  fresh clone and opens a draft PR — documented so it is reproducible, with the cadence/feed table and the
  "shares usage quota → schedule off-peak" note.
- **Artifact:** `docs/self-improvement/refresh-routine.md` (cadence table + schedule definition + how to
  create/disable it)
- **Depends on:** T-8.6
- **Verification criteria:**
  - [ ] Doc lists the three cadence tiers with their feeds and access type — `grep -qi 'daily' docs/self-improvement/refresh-routine.md && grep -qi 'weekly' docs/self-improvement/refresh-routine.md && grep -qi 'monthly' docs/self-improvement/refresh-routine.md`
  - [ ] States hourly-minimum cadence + off-peak + fresh-clone + draft-PR + never-auto-merge — `grep -qi 'hourly' docs/self-improvement/refresh-routine.md && grep -qi 'draft pr\|never.*merge' docs/self-improvement/refresh-routine.md`
  - [ ] References `poll_feeds.py` and `feed-state.json` as what the routine runs — `grep -q 'poll_feeds' docs/self-improvement/refresh-routine.md`
- **Status:** todo
