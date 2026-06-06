---
name: sec-learn
description: Reflective learning pass. Mine recent review sessions for false-positives, missed findings, and user corrections; propose dated diffs to the KB/checklists/skills as a reviewable PR behind the eval keep-or-revert gate. Use periodically or after a notable review.
disable-model-invocation: true
---

# sec-learn — the reflective loop (reflect → propose dated diffs → PR)

The OUTER loop's **quality arm**. It mines recent review traces for **false positives** and
**misses**, reasons about root cause, and proposes **dated, sourced text diffs** to the Context
surface — the KB, the `_shared/reference/` checklists, and the **`tool-registry.md`** (ADR-015 — new
*tools* are learned like new techniques). It **never writes the live KB and never merges itself**:
every change is a branch + PR behind the Phase-9 eval keep-or-revert gate. `disable-model-invocation`
in the front-matter makes this a **manual trigger** (it never fires itself).

> Runs in a **forked/fresh context** so reflection isn't biased by the session being analyzed.
> Reads `evals/traces/*.jsonl` (capture hooks, T-8.3); writes only a proposal branch + PR.

## Control flow (GEPA-style, si-08 §3.2)
1. **Harvest** — `scripts/harvest.sh` collates this period's traces + corrections + failed exploits
   into the reflection input (`harvest.py`, tested).
2. **Reflect per signal** — for each FP/miss emit a **structured rationale**:
   - `why_missed` (for a miss) or `why_fp_fired` (for a false positive),
   - the **root cause** (which checklist/KB item was wrong or absent),
   - the **minimal edit** that would fix it.
3. **Pre-gate (cheap filters before proposing)** — only consider a change that is:
   - **seen in ≥ 3 sessions** (not a one-off), the **same fix** each time,
   - expressible in **1–2 sentences**, and leaves the **system prompt unchanged** (identity-preserving).
4. **Self-critique** — is the edit **generalizable**, or **overfit** to one repo/finding? Drop overfit
   edits. Prefer a pattern over a specific payload.
5. **PATCH over CREATE** — **default to editing an existing** KB entry / checklist line; create a new
   entry only when no existing one covers it (keeps the surface small, ADR-005).
6. **Propose** — write the dated, sourced diffs to a **branch** and open a **PR** with evidence:
   the motivating session ids, the FP/miss, and a **before/after `score.py` table** over the corpus.

## What it may propose (all PR-gated, never auto-applied)
- `ai-attack-kb/reference/*` entries (dated; mandatory `source`+`url`+`retrieved`).
- `_shared/reference/*` checklist lines (web/CWE — the stable tier).
- **`_shared/reference/tool-registry.md`** — newly-useful tools mapped to a capability (ADR-015).

## Guardrails (structural, not advisory)
- **Never auto-merge**; **never writes the live KB** — only a proposal branch + PR for a **human**.
- Confined by `confine_self_writes` (T-8.4): writes only the self-improvement lane; the frozen
  `evals/corpus/**` + gate scripts are denied (a learning pass cannot edit its own exam).
- Behind the Phase-9 **keep-or-revert** eval gate: a proposed diff that lowers Youden's J on the
  frozen corpus is reverted.

## Verification criteria (definition of done)
- [ ] Documents reflect → pre-gate (≥3 sessions) → self-critique → PATCH-over-CREATE → branch+PR-with-evidence.
- [ ] Proposes `tool-registry` additions, not just KB/checklist (ADR-015).
- [ ] `harvest.sh`/`harvest.py` collate traces + corrections (tested).
- [ ] States "never auto-merge / human-gated" + `disable-model-invocation`; de-stubbed.
