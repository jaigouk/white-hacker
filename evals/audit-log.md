# Outer-loop gate audit log

Append-only record of keep-or-revert verdicts on candidate KB changes (T-9.3). Each entry: the
candidate diff summary, the corpus scores (baseline vs candidate), and the verdict (KEEP / REVERT /
INCONCLUSIVE). Seeded with the demonstration below.

## 2026-06-06 — demonstration: a regressing KB diff is REVERTed
- **Candidate:** a proposed `ai-attack-kb/reference/` edit that widened a detection pattern.
- **Scores:** baseline `youden_j=0.875, fpr=0.031` → candidate `youden_j=0.84, fpr=0.052`.
- **Gate:** `keep_or_revert.py` → **REVERT** (FPR_gain 2.1pp > 1pp; J regressed). Blocked end-to-end:
  the CI gate step fails the job and the `gate_kb_edit` PreToolUse hook denies the in-session write.
