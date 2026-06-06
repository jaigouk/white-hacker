# Self-Improvement Research — si:reflective-loop

> Source: workflow `self-improving-white-hacker-research` (w3b87zsau), agent `si:reflective-loop`

## Lightweight Reflective Self-Improvement Loop for a Claude Code Security Agent

### What GEPA actually does (the principle to copy, not the pipeline)

GEPA — *Genetic-Pareto*, [arXiv:2507.19457](https://arxiv.org/abs/2507.19457), accepted as an **ICLR 2026 Oral** — optimizes the *plain-text instructions* of a compound AI system by reflecting on execution traces in natural language. It beats GRPO by up to 20% with **up to 35x fewer rollouts**, and beats the prior best prompt optimizer MIPROv2 by >10% ([abstract](https://arxiv.org/abs/2507.19457); [DSPy GEPA docs](https://dspy.ai/api/optimizers/GEPA/overview/)). The exact mechanism (paper Algorithm 1 & 2, Figure 3–4) is the part worth porting:

1. **Sample a candidate** from a *Pareto frontier* of past prompt versions (not just the global best — that avoids local optima).
2. **Run it on a minibatch**, capturing traces (reasoning, tool calls, outputs) and the *evaluation trace* (error messages, rubric notes).
3. **Reflect**: a reflection LM is shown `(current prompt, trajectory, score, textual feedback μ_f)` and proposes a revised instruction.
4. **Gate on the minibatch**: re-run the edited prompt on the *same* minibatch. The paper's exact rule (Algorithm 1, line 14): **"if σ′ improved then add Φ′ to P [the pool] and evaluate on D_pareto."** No improvement → discard the edit immediately.
5. **Validate**: only edits that passed the minibatch gate are scored on the larger held-out `D_pareto` set, which feeds the Pareto frontier used for future selection.
6. **System-aware merge**: occasionally combine two complementary candidates (each strong on a different module/task) into one.

The two transferable invariants: **textual feedback beats scalar reward** for an LLM optimizer ([TextGrad / textual-gradient line of work](https://www.emergentmind.com/topics/textgrad)), and a **cheap minibatch gate before an expensive full eval** is what makes it sample-efficient. DSPy's `dspy.GEPA` exposes this via a feedback metric `metric(gold, pred, trace, pred_name, pred_trace) -> float | ScoreWithFeedback`, a required `reflection_lm`, and an `auto`/`max_metric_calls` budget ([DSPy GEPA API](https://dspy.ai/api/optimizers/GEPA/overview/)). We do **not** need that pipeline — we replicate the *control flow* with Claude Code primitives.

### Mapping GEPA → Claude Code primitives

Claude Code now treats commands and skills uniformly: a `SKILL.md` under `.claude/skills/<name>/` becomes `/<name>`, supports YAML frontmatter, **dynamic context injection** (a `` !`shell` `` line is executed and its output inlined before Claude reads the skill), and **subagent execution** via `context: fork` ([skills docs](https://code.claude.com/docs/en/slash-commands)).

| GEPA concept | Claude Code artifact |
|---|---|
| System Φ (the prompts under optimization) | The security agent's **checklist**, **knowledge base** (`kb/*.md`), and **skill bodies** (`.claude/skills/security-review/SKILL.md`) — all version-controlled text |
| Trajectories + evaluation traces | Past **review session transcripts** + the **user corrections** logged in them |
| Feedback function μ_f | A `/learn` skill that mines transcripts into structured `{false_positive, missed_finding, user_correction}` records with rationale |
| Reflective mutation | The `/learn` skill proposing a **git diff** to checklist/KB/skill |
| Minibatch gate (σ′ improved?) | Re-run the agent (frozen vs. patched) on a **fixed regression corpus** of labeled past cases; compare scores |
| Pareto frontier / pool | **Git history of the KB** — every accepted edit is a commit; reverts are commits; tags mark known-good baselines |
| Accept → add to pool; else discard | **Open a PR** if the gate passes; **auto-close/revert** if it regresses |

### The keep-or-revert ratchet

The ratchet is the whole point: knowledge only accumulates if each edit is *monotonically non-regressive* against a frozen corpus. Concretely:

1. **Frozen regression corpus** at `evals/corpus/` — a directory of past review cases, each a folder with `input/` (the diff/code reviewed) and `labels.yaml` (ground-truth findings with severity, plus explicitly labeled *non-issues* so false positives are catchable). Seed it from real sessions; never let the optimizer edit it (anti-gaming hidden split — see [AgentAssay](https://arxiv.org/html/2603.02601v1)). Aim for **≥100 paired cases**; below that, the paired-bootstrap confidence interval is wider than the regressions you're trying to detect and the gate fires false alarms ([AgentAssay](https://arxiv.org/pdf/2603.02601)).
2. **Score function** with three components, computed per case:
   - **Recall** = true findings caught / total true findings (missed findings hurt this).
   - **Precision** = true findings / (true + false findings) (false positives hurt this).
   - **Severity-weighted recall** — a missed CRITICAL counts far more than a missed style nit.
3. **Gate rule (the GEPA accept criterion, ported):** the patched agent is accepted only if, on the frozen corpus, **severity-weighted recall is ≥ baseline AND precision is ≥ baseline − ε** (small slack, e.g. ε=0.02, so a precision-fixing edit isn't blocked by a 1-case wobble). Use a **three-valued verdict** (Pass / Fail / Inconclusive) from a paired bootstrap rather than a raw mean comparison — agent runs are non-deterministic, so run each case `k` times (k=3–5) ([AgentAssay](https://arxiv.org/html/2603.02601v1)).
4. **What counts as a regression** (any one triggers revert):
   - A previously-caught **true finding is now missed** (recall drop on any case).
   - A previously-clean case now produces a **new false positive** (precision drop).
   - **Severity inversion** — a CRITICAL downgraded to LOW or dropped.
   - The edit fixes its target case but **breaks ≥1 other case** (the cross-task check from GEPA Algorithm 1, lines 16–18: re-evaluate on the *whole* corpus, not just the case that motivated the edit).
5. **Ratchet bookkeeping:** `git tag eval-baseline-<date>` marks the current known-good KB. Each accepted PR moves the tag forward; each revert resets to the last tag. Because every state is a commit, the "Pareto pool" is just `git log` — you can cherry-pick a lesson that helped case A even after reverting the commit that hurt case B (the GEPA insight that you keep complementary candidates, not just the global best).

### Making every change a reviewable diff (git PR)

The optimizer **never writes the live KB directly.** It works on a branch:

- `/learn` runs in a **forked subagent** (`context: fork`) so its long transcript-mining doesn't pollute the main session, and writes proposals to a branch `learn/<date>-<topic>`.
- Each proposal is a real diff to `checklist.md` / `kb/<topic>.md` / a skill body, with a commit message that cites the **evidence** (session id, the false positive/miss it addresses) and the **before/after corpus scores**.
- A GitHub PR is opened via `gh pr create`, body templated with: motivating cases, diff summary, gate result table (precision/recall before→after), and a "regressions: none" line. The human reviews the *reasoning*, not just the text.
- **Auto-revert path:** if the gate fails, the subagent closes the branch and instead files the failed hypothesis as a note in `evals/rejected.md` (so the loop doesn't re-propose the same losing edit — the GEPA "discard P_new" path with memory).

### The loop, step by step

```
[1] HARVEST  — /learn mines recent transcripts → records.jsonl
                 (false positives, missed findings, user corrections)
[2] CLUSTER  — group records by root cause (e.g. "misses SSRF via redirect")
[3] PROPOSE  — for each cluster, reflect → minimal diff to checklist/KB/skill
                 on branch learn/<date>-<cluster>
[4] GATE     — run baseline vs patched agent on evals/corpus (k runs each)
                 severity-weighted recall ↑ AND precision ↓ ≤ ε ?
[5a] KEEP    — open PR with evidence + score table → human merge → move eval tag
[5b] REVERT  — discard branch, log hypothesis in evals/rejected.md
[6] GROW     — promote any NEW true finding the agent and human agreed on
                 (and its labels) into evals/corpus so it's protected forever
```

Step [6] is the second ratchet: the *corpus itself* grows from confirmed findings, so the bar rises over time — this is what keeps the AI-attack knowledge base **current** rather than drifting.

**Cadence:** trigger `/learn` manually after a notable review, and/or schedule it weekly via a scheduled routine (Claude Code's `schedule`/cron primitive) so harvesting is automatic but **merging stays human-gated**. A `SessionEnd` hook can append each session's corrections to `records.jsonl` so harvesting is cheap.

### Artifact sketches

**`.claude/skills/learn/SKILL.md`** (the μ_f + reflective mutation step):
```yaml
---
description: Mine recent security-review sessions for false positives, missed
  findings, and user corrections; propose gated diffs to the checklist/KB/skills.
disable-model-invocation: true   # only run on explicit /learn
context: fork                    # don't pollute main session
allowed-tools: Read Grep Glob Bash(git*) Bash(gh*)
argument-hint: "[lookback-days]"
---

## Recent corrections (auto-injected)
!`bash evals/harvest.sh ${1:-14}`   # dumps records.jsonl from transcripts

## Instructions
1. Cluster the records above by ROOT CAUSE, not by symptom.
2. For each cluster, write the SMALLEST diff to checklist.md / kb/*.md / a
   skill body that would have prevented the miss or suppressed the FP.
   Prefer adding a concrete detection rule + an example over prose.
3. For each diff: git checkout -b learn/$(date +%F)-<slug>, apply, commit
   citing the session ids and the FP/miss it fixes.
4. Run: bash evals/gate.sh   (baseline vs patched, k=5, prints score table)
5. If GATE=PASS -> gh pr create with the evidence + score table.
   If GATE=FAIL -> discard branch; append the hypothesis + why it failed to
   evals/rejected.md so we never re-propose it.
6. Do NOT edit anything under evals/corpus/. Never merge yourself.
```

**Example reflection prompt inside step [3]** (the textual-gradient move):
> "Here is a case the agent reviewed, its output, and the user's correction. The user flagged a **missed SSRF** reachable through an open redirect. Our checklist line 'check user-controlled URLs in outbound requests' did not catch it because the URL was validated against an allowlist *before* a redirect. Propose the minimal checklist/KB edit that makes this class of bypass detectable in future reviews. Output only the diff and a one-line rationale."

**Example gate output table** (goes verbatim into the PR body):
```
metric            baseline   patched   delta   verdict
sev-wtd recall      0.81       0.87    +0.06    PASS
precision           0.92       0.91    -0.01    PASS (within ε=0.02)
new false positives  —          0               PASS
newly-missed true    —          0               PASS
=> GATE: PASS (paired bootstrap, k=5, n=124)
```

This gives you GEPA's reflect→edit→gate→keep/revert loop, its Pareto-style retention of complementary lessons (via git history), and its sample efficiency (cheap corpus gate before any human review) — all in native Claude Code skills, hooks, scheduled routines, and PRs, with **no DSPy runtime**. Note the gate here is a *guardrail* (block regressions) rather than GEPA's *search objective* (maximize a benchmark), which suits a security agent where every edit must be human-auditable.

## Key takeaways

- Port GEPA's CONTROL FLOW, not its pipeline: sample a candidate prompt/KB version -> run on a cheap minibatch -> reflect in natural language on traces -> re-run on the same minibatch -> keep ONLY if it strictly improved -> then validate on the full held-out set. The accept rule is literally GEPA Algorithm 1 line 14 ('if improved then add to pool and eval on D_pareto').
- Textual feedback beats scalar reward as the learning signal for an LLM optimizer (GEPA + TextGrad core finding). The 'learn' skill should emit structured rationale (why a finding was missed / why an FP fired), not just a pass/fail number.
- The keep-or-revert ratchet needs a FROZEN, hidden regression corpus of labeled past cases (true findings AND labeled non-issues to catch false positives) that the optimizer can never edit -- this is the anti-gaming split.
- Use a 3-valued verdict (Pass/Fail/Inconclusive) from a paired bootstrap with k=3-5 runs per case, because agent runs are non-deterministic; a raw mean comparison fires false regression alarms.
- Need >=~100 paired cases in the corpus; below that the bootstrap confidence interval is wider than the regressions you're trying to detect (AgentAssay 2026).
- Define regression precisely: any previously-caught true finding now missed (recall drop), any clean case now producing a new false positive (precision drop), any severity inversion, OR fixing the target case while breaking any other case (GEPA's whole-corpus re-eval).
- Gate rule for security: accept only if severity-weighted recall >= baseline AND precision >= baseline - epsilon. The gate is a guardrail (block regressions), not GEPA's maximize-a-benchmark objective.
- Make every change a reviewable git diff: the 'learn' skill runs in a forked subagent (context: fork), writes to a branch, and opens a PR via gh with evidence (session ids, motivating FP/miss) + a before/after score table. The optimizer never writes the live KB or merges itself.
- Git IS the Pareto pool: every accepted edit is a commit, reverts are commits, tags mark known-good baselines -- so you can cherry-pick a lesson that helped case A even after reverting an edit that hurt case B (GEPA's keep-complementary-candidates insight).
- Second ratchet to stay current: promote every newly-confirmed true finding (and its labels) INTO the frozen corpus, so the bar rises over time and the AI-attack KB doesn't drift.
- Implement with native primitives only: SKILL.md with disable-model-invocation + dynamic context injection (!`harvest.sh`) for the learn command, a SessionEnd hook to log corrections cheaply, and a scheduled routine (cron) for weekly auto-harvest with human-gated merge -- no DSPy.
- Keep a rejected-hypotheses log (evals/rejected.md): failed edits get recorded so the loop never re-proposes the same losing change (GEPA's 'discard P_new' path, with memory).

## Sources

- https://arxiv.org/abs/2507.19457
- https://arxiv.org/pdf/2507.19457
- https://dspy.ai/api/optimizers/GEPA/overview/
- https://deepwiki.com/stanfordnlp/dspy/4.5-gepa:-reflective-prompt-evolution
- https://github.com/gepa-ai/gepa
- https://www.emergentmind.com/topics/textgrad
- https://www.emergentmind.com/topics/textual-gradients
- https://code.claude.com/docs/en/slash-commands
- https://arxiv.org/html/2603.02601v1
- https://arxiv.org/pdf/2603.02601
- https://futureagi.com/blog/prompt-regression-testing-2026/
- https://venturebeat.com/technology/anthropic-introduces-dreaming-a-system-that-lets-ai-agents-learn-from-their-own-mistakes

