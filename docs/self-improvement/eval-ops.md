# Eval ops — passive-drift re-score, nightly red-team, the second ratchet (T-9.5)

How the frozen eval keeps catching regressions that aren't triggered by a self-edit, and how the bar
keeps rising. **Document-only** for the scheduled parts (no live schedule is created — operator's
no-autonomous-schedulers preference; the operator arms these via `/schedule` when wanted).

## 1. Passive-drift re-score (weekly)
Self-edits aren't the only regression source — the underlying model/provider updates silently. So
**weekly**, re-score the full frozen corpus and compare to the recorded thresholds:
- Run `evals/score.py --corpus evals/corpus/cases --findings <fresh run>` → TPR/FPR/Youden's J.
- Compare against `evals/baseline.json` using the **same keep-or-revert thresholds**
  (`evals/keep_or_revert.py`): a passive **REVERT** (recall loss > 2pp, FPR gain > 1pp, or any locked
  case regressing) raises an alert even though no KB edit happened — the model drifted.
- This is the "weekly passive-drift" layer; it shares the gate logic with the per-edit merge gate.

## 2. Nightly red-team (behind the AI-redteam capability — degradable)
A nightly red-team layer adds dynamic coverage on top of the static corpus. It runs behind the
**AI-redteam capability** (ADR-015), so it is **optional and degrades gracefully**: if no red-team
tool is installed (illustrative: promptfoo redteam, UK/US AISI Inspect), the layer is skipped and
the static corpus + gate still run — it is **not a hard tool dependency**. New confirmed red-team
findings feed the second ratchet (below).

## 3. The second ratchet (raise the bar)
Newly-confirmed true findings (from review, drift, or red-team) are **promoted into the frozen
corpus** as new locked cases via `evals/scripts/promote_finding.py` — run by the **human/CI
identity** only (the agent is write-blocked from `evals/corpus/**`, T-8.4, so it can't grade its own
exam). Each promotion adds a vulnerable+benign pair + a label and appends the id to `LOCKED`, so the
keep-or-revert gate gets strictly harder over time.

## Schedule (operator-armed, off-peak)
- Weekly drift re-score + nightly red-team are cloud Routines the **operator** creates via
  `/schedule` (see `refresh-routine.md` for the pattern). This doc defines them; it creates none.
