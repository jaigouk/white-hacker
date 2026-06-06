# Graduated-autonomy policy (T-9.6; si-08 §7 Phase 5)

How much the outer loop may do without a human, and how it earns more. Default: **everything is
human-gated.** Autonomy is loosened **one narrow class at a time, only after a clean track record.**

## Earn it: the track-record threshold
A capability may be loosened only after **≥ 20 PRs where the human's approval decision matched the
keep-or-revert gate verdict** (i.e. the gate has been demonstrably calibrated against human judgment).
Until then, every outer-loop change is a draft PR a human approves.

## The one auto-merge-eligible class (lowest-risk, highest-precision)
Only this exact class may auto-merge once the track record is earned:
- **feed-sourced** entries (from `sec-kb-refresh`, not free-form),
- **PATCH-only** (edits an existing entry; **never CREATE**),
- in the **fast tier** (`ai-attack-kb/reference/`),
- **gate-green** (keep-or-revert verdict KEEP; all 10 pre-commit gates pass),
- **add no new sink** (no new detection sink/category),
- carry valid **`source`+`url`+`retrieved`** provenance.

Everything else stays a draft PR.

## Stays human-gated indefinitely (non-negotiable)
- **CREATE** of new KB entries.
- Any **checklist** edit (`_shared/reference/**`).
- Any **rule / agent-role / `CLAUDE.md`** edit — **identity preservation** is permanent and absolute
  (the pre-commit checklist blocks these regardless of any gate verdict).
- Any change to the frozen corpus or the gate scripts.

## The ratchet keeps running as autonomy widens
Widening autonomy does **not** pause the safety machinery: the keep-or-revert gate, the 10-gate
pre-commit checklist, passive-drift re-score, and the **second ratchet** (promoting confirmed
findings into the frozen corpus, `eval-ops.md`) all keep running — so the bar keeps rising even for
the auto-merge-eligible class. Autonomy is a privilege the gate can revoke if the track record slips.
