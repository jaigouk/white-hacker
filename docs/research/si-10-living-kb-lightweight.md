# si-10: keeping the living KB current *without* a heavy architecture

**Status:** PROPOSAL (design synthesis — answers "can we improve living-knowledge upkeep without too heavy a system?")
**Date:** 2026-06-08
**Author:** white-hacker agent
**Sources (imported into `docs/research/` 2026-06-08):**
[`20260602_Self-Improving-Agent-Architecture-Reference.md`](20260602_Self-Improving-Agent-Architecture-Reference.md)
(vendor-neutral outer-loop reference) and
[`20260606_colleague_skill_distillation.md`](20260606_colleague_skill_distillation.md)
(trace-to-skill distillation — MIT prior-art). The third KMS doc (the multi-tenant B2B platform
design) was **deleted on purpose**: it is a different product's heavy architecture and is not our model.

---

## The one-line answer

**We already have the light version.** white-hacker's living KB is the *Context surface* of a
self-improving loop done as **dated markdown in git + a handful of deterministic Python scripts +
human-merged PRs** — no database, no daemon, no multi-tenant plane. The two imported references and
the COLLEAGUE.SKILL paper **converge on exactly this shape**, which is corroboration, not a prompt to
build more. The right move is **not** to add architecture; it is to (1) keep using the pieces we have,
and (2) add three *tiny, deterministic, file-based* helpers that close real gaps.

## Our living-KB substrate today (what to keep using)

| Function | Mechanism we already have | File |
|---|---|---|
| **Schema / size caps** | `validate_kb.py` against `kb-entry-schema.json` (mandatory `source`+`url`+`retrieved`, closed enums, ≤120-word summary, ≤400-line file) | `ai-attack-kb/scripts/validate_kb.py` |
| **Decay** | `staleness_check.py` — flags entries past `review_by`; `--archive` *moves* (never deletes) to `ai-attack-kb/archive/` | `ai-attack-kb/scripts/staleness_check.py:21` |
| **Conflict / dedupe** | `dedupe_kb.py` — no duplicate ids, flags shared-xref merges; `supersedes:` chains the old id | `ai-attack-kb/scripts/dedupe_kb.py` |
| **Input arm (currency)** | `sec-kb-refresh` — polls feeds → drafts dated entries → **draft PR, never auto-merge** | `skills/sec-kb-refresh/SKILL.md` |
| **Quality arm (reflection)** | `sec-learn` — mines FPs/misses → proposes dated diffs → PR behind the eval gate | `skills/sec-learn/SKILL.md` |
| **Keep-or-revert ratchet** | `evals/keep_or_revert.py` over the frozen corpus — a diff that lowers Youden's J is reverted | `evals/keep_or_revert.py` |
| **Confinement** | `confine_self_writes.py` PreToolUse hook — the learning arm can write only the KB lane; the exam (corpus + gate) is denied | `plugins/white-hacker/hooks/confine_self_writes.py` |

That table *is* the closed learning loop from the reference (trace → reflect → propose text diff →
gate → keep/revert), implemented at file scale.

## KMS-G4 → white-hacker map (heavy → our light equivalent)

The deleted KMS doc's "living knowledge" goal (G4) is a useful checklist *because* it lets us name what
we deliberately **skip**:

| KMS-G4 mechanism (heavy) | white-hacker light equivalent | Verdict |
|---|---|---|
| Nightly **per-tenant decay pipeline** (Celery, staleness LLM, trust scores) | `staleness_check.py` + `review_by` date, run in CI/manually | **have it — lighter** |
| **Conflict model** (Wikidata ranks, ChangeProposal/Dispute) | `supersedes:` + `dedupe_kb.py` + human-merged PR | **have it — lighter** |
| **Self-improving ratchet** (GEPA, eval-gated config ChangeProposal) | `sec-learn` + `keep_or_revert.py` over the frozen corpus | **have it — lighter** |
| **Ownership chain** (CODEOWNERS, steward rotation, PagerDuty escalation, orphan handling) | the human who merges the PR *is* the owner | **skip — overkill for a single repo** |
| **Event bus / ripple engine / concept graph** (Kafka, bi-temporal edges, impact sets) | grep + `xref`/`kb_refs`; a changed entry's consumers are found by `validate_findings.py --check-kb-refs` | **skip — no services** |
| **Multi-tenant isolation** (RLS, per-tenant DEK, OpenFGA) | one repo, one trust domain; egress confinement via the hook | **skip — not our problem** |
| **Immediate-apply NL corrections** (COLLEAGUE writes on the spot) | every change is a PR behind the eval gate ("AI never writes to `main`") | **skip — we gate, by design** |

## Three cheap borrowings worth adding (deterministic, file-based, no new architecture)

From the two kept references — each is a small pure function or a one-line policy, never a service:

1. **Section-keyed patch-merge helper** for `sec-learn`'s diffs (COLLEAGUE map #3 / reference §5.2).
   A ~30-line deterministic function: a proposed patch whose `##` heading matches an existing section
   **replaces** that section; an unmatched section is **appended**. Keeps `sec-learn`'s text mutations
   out of the LLM path (Rule 5) and the merge reviewable. *Reimplement to our style (MIT lets us lift,
   but it's <50 lines).*

2. **`{scene, wrong, correct}` correction record** layered onto `sec-learn`'s trace harvest
   (COLLEAGUE map #4). A normalized, inspectable "what fired wrong + the fix" triple is exactly the
   ground-truth the ratchet mines — append-only, surfaces conflicts instead of overwriting (matches
   our Rule 7).

3. **Data-minimization rule** for every KB / registry entry (COLLEAGUE map #9): store **paraphrased
   notes + provenance metadata, never the full copyrighted/PII source**. Our schema already mandates
   `source`+`url`+`retrieved`; this just adds "and no verbatim third-party body." A one-line lint in
   `validate_kb.py`, not a subsystem.

## The hook that ties today's npm work into the living loop

The supply-chain-malware detector (spike-09) introduces a **curated allowlist + ecosystem map** in
`deps-scan/reference/`. Treat those as **knowledge, not code**: `/sec-kb-refresh` extends them exactly
as it extends the attack KB (ADR-015 — "tools/signals are knowledge too"). That is the whole point of
the living KB applied to a new surface — the allowlist ages and refreshes through the *same* dated,
PR-gated arm, with the offline OSSF malicious-packages snapshot as the authoritative backstop. No new
machinery; one more `reference/` lane on the existing loop.

## The guiding principle (so we don't drift heavy)

- **Our "database" is the git repo**; our records are dated markdown.
- **Our "decay pipeline" is `staleness_check.py` + `review_by`** — a grep over dates, run in CI.
- **Our "conflict resolution" is `supersedes` + `dedupe_kb.py` + a human-merged PR.**
- **Our "ratchet" is `keep_or_revert.py` over the frozen corpus.**
- **No service, no daemon, no DB, no tenant plane** — if a "living knowledge" feature needs one of
  those, it is out of scope for white-hacker by construction.

## Follow-up (deferred — file as tickets, do not build speculatively)

- (impl) Add the section-keyed patch-merge helper to `sec-learn` (borrowing #1).
- (impl) Add the `{scene, wrong, correct}` record to the `sec-learn` harvest (borrowing #2).
- (lint) Add the "no verbatim third-party body" check to `validate_kb.py` (borrowing #3).
- (loop) Wire `/sec-kb-refresh` to extend `deps-scan/reference/` allowlists (ties spike-09 in).
