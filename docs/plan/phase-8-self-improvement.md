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
  - [x] All caps + schema rules enforced; passing & failing fixtures behave correctly — `uv run --with jsonschema --with pyyaml --with pytest pytest .../tests/test_lint_skill.py .../tests/test_validate_kb.py` *(11 + 18 tests)*
  - [x] An unsourced AI-threat entry (no `metadata.source`) is **rejected** — `validate_kb` `test_missing_metadata_source_fails` (T-4.1)
  - [x] `lint_skill` over **all** current skills exits 0 — `uv run python .../lint_skill.py .claude/skills/` *(12 skills OK; stdlib-only, lenient frontmatter parse matching CC — caught that strict YAML rejects valid colon-bearing descriptions)*
  - [x] `validate_kb` over the seed KB exits 0
- **Status:** done *(validate_kb pre-existed from T-4.1; T-8.1 added lint_skill.py)*

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
  - [x] Duplicate `id` fails the run; a shared-xref pair is flagged for merge (advisory, no fail) — `uv run --with pyyaml --with pytest pytest .../test_dedupe_kb.py` *(5 tests; incl. title-similarity)*
  - [x] An entry past `review_by` is flagged stale; a future one is not — `uv run --with pyyaml --with pytest pytest .../test_staleness_check.py`
  - [x] Aging-out moves to `archive/` (no delete) — `test_archive_moves_file_preserving_content`
  - [x] Seed KB has no duplicate ids and no stale entries — `dedupe_kb` exit 0 (2 advisory xref flags, no dup) + `staleness_check --today 2026-06-06` exit 0
- **Status:** done *(`archive/` created; cadence note: refresh touches the fast tier only)*

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
  - [x] Each hook (5 modes of `capture_hooks.py` behind 5 `.sh` wrappers), fed an event JSON, appends a well-formed JSONL line / emits the digest/nudge — `uv run --with pytest pytest .claude/hooks/tests/test_capture_hooks.py` *(9 tests)*
  - [ ] **(pending human-auth)** hooks registered under PostToolUse/SessionEnd/Stop/SessionStart in committed `.claude/settings.json` — batched into the one operator-auth approval
  - [x] Append-only + never writes a secret value (redaction) — `test_secret_value_is_redacted` + `test_append_is_additive`
- **Status:** done (logic + 9 tests) — capture is **opt-in by design** and intentionally NOT in the shipped plugin `hooks.json`: a plugin installed into others' repos must not auto-capture their session traces (privacy). The maintainer enables it via repo-local settings for self-improvement. Confirmed deliberate in the 2026-06-07 outer-loop QA (the outer loop runs in the maintainer repo, not in an installer's review).

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
  - [x] Denies writes to `src/x`, `evals/corpus/x`, `evals/keep_or_revert.py`, `evals/baseline.json`, `.claude/settings.json`, and `../`-traversal into the corpus; allows `ai-attack-kb/reference/x.md`, `PATCHES/x`, `evals/traces/x` — `uv run --with pytest pytest .claude/hooks/tests/test_confine_self_writes.py` *(10 tests)*
  - [x] Denies `.env` read (composes `guard_bash`) and egress outside the feed allow-list (incl. `169.254.169.254`); allows feed hosts (osv.dev, githubusercontent, …) — dedicated tests
  - [ ] **(pending human-auth)** committed `.claude/settings.json` `permissions.deny` lists the corpus + gate-script paths — batched into the one operator-auth approval
- **Status:** done — `confine_self_writes` is WIRED in the plugin `hooks/hooks.json` PreToolUse chain (alongside `guard_bash` + `confine_patch_writes`, and now `gate_kb_edit`); confirmed in the 2026-06-07 outer-loop QA. (Phase 10/11 generalized it to also deny control files / `.claude-plugin/`.)

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
  - [x] Body documents reflect → pre-gate (N≥3) → self-critique → PATCH-over-CREATE → branch+PR-with-evidence — *(VC corrected: `grep -E` uses plain `|`, not `\|` — the `vc-grep-gotchas` trap)* `for k in 'why_missed|why_fp' 'seen.*3|≥ *3|>= *3' 'self-crit|overfit' 'patch over create|default.*patch' 'PR|branch'; do grep -qiE "$k" .claude/skills/sec-learn/SKILL.md || echo MISSING:"$k"; done` prints nothing
  - [x] Proposes tool-registry additions, not just KB/checklist (ADR-015) — `grep -q 'tool-registry'`
  - [x] `harvest.py`/`.sh` collates traces+corrections — `uv run --with pytest pytest .claude/skills/sec-learn/scripts/tests/test_harvest.py` *(5 tests)*
  - [x] States "never auto-merge / human-gated" + `disable-model-invocation`; de-stubbed
- **Status:** done

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
  - [x] Poller diffs incrementally vs `feed-state.json` and parses OSV/ATLAS/atom fixtures into candidates — `uv run --with jsonschema --with pyyaml --with pytest pytest .../test_poll_feeds.py` *(8 tests; 3 feed types; unchanged feed → 0 new; partial-diff)*
  - [x] Drafted entries pass `validate_kb` (mandatory source+url+retrieved) and `dedupe_kb` — `test_candidate_entry_validates_and_dedupes` runs both on poller output
  - [x] SKILL states "fast tier only / never auto-merge / draft PR" + proposes tool-registry (ADR-015); de-stubbed — greps pass
  - [x] No network in tests (fixtures only); parsers take raw content; live polling honors the T-8.4 egress allow-list
- **Status:** done

### T-8.7 · Document the refresh routine (cadence + how to schedule) — DOCUMENT-ONLY
> **Re-groom (2026-06-06):** the operator's standing "no autonomous schedulers" preference means
> T-8.7 is **document-only** — it does NOT create a live cloud Routine. The doc defines the cadence +
> how the operator creates/disables it via `/schedule`; `poll_feeds.py` stays manually runnable.
- **Goal:** document `sec-kb-refresh` as a schedulable cloud Routine (hourly-minimum cadence; daily
  JSON/RSS, weekly blogs, monthly frameworks per si-08 §4) that runs to completion on a fresh clone and
  opens a draft PR — reproducible, with the cadence/feed table and the off-peak note. **No live schedule
  is created.**
- **Artifact:** `docs/self-improvement/refresh-routine.md` (cadence table + schedule definition + how to
  create/disable it)
- **Depends on:** T-8.6
- **Verification criteria:**
  - [x] Doc lists the three cadence tiers (daily/weekly/monthly) with their feeds — greps pass
  - [x] States hourly-minimum + off-peak + fresh-clone + draft-PR + never-auto-merge — greps pass
  - [x] References `poll_feeds.py` + `feed-state.json` as what the routine runs — grep passes
- **Status:** done *(document-only — no live schedule created, per the operator's no-scheduler preference)*
