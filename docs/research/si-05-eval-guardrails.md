# Self-Improvement Research — si:eval-guardrails

> Source: workflow `self-improving-white-hacker-research` (w3b87zsau), agent `si:eval-guardrails`

## Eval + Regression Guardrails for a Self-Modifying Security Agent

The core problem: your Claude Code security agent can rewrite its own knowledge base (KB), skills, and detection heuristics. Every such change is a potential regression — a new "prompt-injection sink" pattern might inflate false positives across an entire language, or a "cleaner" rule might silently drop recall. The fix is a **frozen golden corpus + a deterministic keep-or-revert gate that runs in CI on every self-modification**, mirroring SAST benchmark methodology (TPR − FPR / Youden's J) and the size/identity guardrails from the self-improving-agent reference.

### 1. The golden corpus (frozen ground truth)

Build a versioned, **read-only** corpus the agent cannot edit (enforce via a Claude Code hook blocking writes to `corpus/`). Two halves per category: an intentionally **VULNERABLE** sample and a **CLEAN look-alike** (same shape, sink neutralized). The look-alikes are what catch false-positive inflation.

**Per-language SAST core** — seed from established labeled sets rather than hand-writing:
- [OWASP Benchmark](https://owasp.org/www-project-benchmark/) Java v1.2: ~2,740 cases across SQLi, XSS, command injection, path traversal, LDAP/XPath injection, weak crypto/hashing/randomness, trust-boundary, secure-cookie (CWE 22–643). Python v0.1 has ~1,230 cases (v1.0 due early 2026). Every case is labeled true/false in `expectedresults-VERSION.csv` — this is your ground-truth schema to copy.
- [SecurityEval](https://github.com/s2e-lab/SecurityEval) (130 samples, 75 CWEs), [CVEfixes](https://arxiv.org/pdf/2107.08760) (5,365 CVEs / 180 CWEs, pre- and post-fix pairs — the post-fix code is your CLEAN look-alike "for free"), and [DiverseVul](https://surrealyz.github.io/files/pubs/raid23-diversevul.pdf) (18,945 vuln functions, 330k clean, 155 CWEs) for volume/diversity across C/C++/Python/Java/JS.
- Vulnerable-by-design apps for whole-repo scanning: [OWASP Juice Shop](https://offensive360.com/blog/owasp-juice-shop-alternatives/) (Node/Angular), DVWA (PHP), WebGoat (Java), NodeGoat (Node).

**AI/LLM-specific sinks** (the part generic SAST corpora miss) — map to [OWASP LLM Top 10 (2025)](https://bsg.tech/blog/owasp-llm-top-10/) and [OWASP Agentic Top 10 (Dec 2025)](https://blog.alexewerlof.com/p/owasp-top-10-ai-llm-agents):
- Direct + indirect prompt-injection sinks: untrusted content concatenated into a system prompt; tool output fed back unsanitized. Source payloads from [AgentDojo](https://www.emergentmind.com/topics/agentdojo-benchmark) (97 user tasks / 629 security cases), [InjecAgent](https://www.semanticscholar.org/paper/InjecAgent:-Benchmarking-Indirect-Prompt-Injections-Zhan-Liang/c8eee9766f0968e8f1b1be0731bc70b85be0ac97) (1,000 IPI cases), and BIPIA. A 2026 unified payload library aggregates ~820 strings from BIPIA/InjecAgent/AgentDojo/Tensor Trust/WASP/LLMail-Inject under one schema.
- **Skill-file / KB-poisoning attacks** — directly relevant since your agent self-modifies: see [Skill-Inject](https://arxiv.org/pdf/2602.20156) and ["Your AI, My Shell"](https://arxiv.org/pdf/2509.22040) on prompt injection in agentic coding editors. Include malicious skill/CLAUDE.md samples your agent must flag, plus benign look-alikes.
- LLM insecure output handling, sensitive-info disclosure (hardcoded keys in prompts), excessive agency (tool that executes model output).

Each corpus entry is a small manifest:
```yaml
id: py-sqli-001
language: python
category: SQLI
cwe: 89
owasp: "A03"
verdict: vulnerable        # or: clean
expected_severity: high    # critical|high|medium|low
file: samples/py-sqli-001.py
```

### 2. Metrics (the scorecard)

Run the agent (current vs. candidate KB) over the corpus and compute, per category and overall:

| Metric | Formula | Catches |
|---|---|---|
| **TPR / Recall** | TP / (TP+FN) | missed vulns (the dangerous failure) |
| **FPR** | FP / (FP+TN) | false-positive inflation (alert fatigue) |
| **Precision** | TP / (TP+FP) | noisy KB rules |
| **Youden's J** | TPR − FPR | single keep-or-revert number |
| **Severity accuracy** | correct-severity / TP | severity drift |

Youden's J (Score = TPR − FPR) is exactly how [OWASP Benchmark's BenchmarkScore](https://owasp.org/www-project-benchmark/) and the [TheAuditorTool SAST benchmark](https://github.com/TheAuditorTool/sast-benchmark) grade tools — adopt it verbatim so your numbers are externally comparable. The CLEAN look-alikes drive the FPR term, which is what stops "improvements" that just flag everything.

### 3. The keep-or-revert gate (concrete thresholds)

The gate is a script the agent runs *before* committing any KB/skill change. It scores `baseline` (current HEAD) and `candidate` (proposed change) and applies a **non-inferiority + improvement** rule. These thresholds combine the SAST scoring convention with the regression thresholds from the [self-improving-agent reference](https://borghei.github.io/Claude-Skills/skills/engineering/self-improving-agent.html):

```
REVERT (hard fail) if ANY:
  recall_candidate  < recall_baseline − 0.02      # never lose >2pp recall
  fpr_candidate     > fpr_baseline   + 0.01       # never add >1pp FPR
  any category recall drops > 0.05                # no category collapse
  severity_accuracy < severity_accuracy_baseline − 0.05
  a previously-passing case now fails             # zero new regressions on locked cases

KEEP requires ALL of:
  J_candidate >= J_baseline                        # net non-inferior
  AND (J_candidate > J_baseline + 0.01             # measurable global win
       OR new_category_coverage_added)             # OR it covers a genuinely new sink
```
Asymmetry is deliberate: recall loss is penalized harder (security cost) and FPR is tightly capped (the drift you most fear). Borrow the self-improving-agent's promotion criteria as *eligibility* before a rule even reaches the gate: **seen in 3+ sessions, same fix every time, expressible in 1–2 sentences, underlying system unchanged** — this stops one-off noise from becoming permanent KB rules. Confidence scoring (`base × recency × consistency`) resolves contradictory rules: the new rule only wins if it scores higher AND clears the gate.

### 4. Size & identity guardrails (from the reference)

These prevent KB bloat and unauthorized self-modification — both vectors for drift and for skill-file poisoning:
- **Size**: `MEMORY.md` capped at **200 lines**; overflow routes to `memory/<topic>.md`. Reject any commit that exceeds the cap. Weekly `scripts/memory_health_checker.py` classifies each entry PROMOTE / CONSOLIDATE / STALE / KEEP / EXTRACT and must end **under 200 lines with zero stale rules**.
- **Identity**: treat the agent as a first-class scoped identity, not a blanket account. The corpus and the gate script are **owned by a different identity than the agent** — the agent proposes, CI (or a human) ratifies. Sign KB commits; a hook verifies the signature before load to defeat skill-file injection.
- **Steady-state acceptance**: first-attempt success > **80%** within 20 sessions, promotion rate **15–25%**, regression-detection latency **< 3 sessions**.

### 5. Running it in CI (runnable, Claude Code native)

Wire the gate as a **PreToolUse/Stop hook** on KB/skill edits and a CI job on PRs that touch `.claude/`, `skills/`, or `memory/`:

```bash
# 1. Generic SAST corpus: agent-vs-ground-truth, Youden's J
uv run python scripts/score_corpus.py \
  --agent-config baseline --corpus corpus/ --out reports/baseline.json
uv run python scripts/score_corpus.py \
  --agent-config candidate --corpus corpus/ --out reports/candidate.json
uv run python scripts/keep_or_revert.py reports/baseline.json reports/candidate.json
# exit 1 -> CI fails the PR, hook blocks the commit, agent auto-reverts

# 2. LLM/agent red-team layer (promptfoo) — now MIT, OpenAI-acquired Mar 2026
promptfoo redteam run --tag git.sha="$GIT_SHA" --no-progress-bar
```
`promptfooconfig.yaml` (covers the AI-sink half) — from [promptfoo's red-team config](https://www.promptfoo.dev/docs/red-team/configuration/):
```yaml
redteam:
  purpose: "white-hat code-vuln triage agent"
  plugins:
    - 'owasp:llm'                  # full OWASP LLM Top 10
    - 'indirect-prompt-injection'
    - 'prompt-extraction'
    - 'cyberseceval'
  strategies: ['jailbreak:composite', 'prompt-injection']
  frameworks: ['owasp:llm', 'nist:ai:measure', 'mitre:atlas']
```
Set a fixed pass threshold (e.g. attack-success-rate must not rise vs. baseline). Run `PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true` to keep generation local for a security tool.

**Deeper agentic security** ([Inspect AI](https://inspect.aisi.org.uk/) by UK AISI): pin specific evals as nightly regression, scored by Inspect's Scorer (`accuracy`):
```bash
pip install inspect-evals
uv run inspect eval inspect_evals/agentdojo  --model anthropic/claude-opus-4-8
uv run inspect eval inspect_evals/cyberseceval --model anthropic/claude-opus-4-8
```
[DeepEval](https://deepeval.com/) (pytest-style) is the cleanest way to express the gate as unit tests — write `assert_test` cases per category and let it diff runs side-by-side to flag regressions in CI.

**Routine**: schedule a weekly Claude Code routine that (a) runs `memory_health_checker.py`, (b) re-scores the full corpus to detect *passive* drift (model/provider updates), and (c) refreshes the AI-attack knowledge base by pulling new payloads from AgentDojo/InjecAgent/the unified payload library, gated through the same keep-or-revert script before any new pattern is accepted.


## Key takeaways

- Freeze the golden corpus as read-only ground truth (block agent writes via a Claude Code hook); the agent proposes KB changes but cannot edit the corpus or the gate script — separate identities, signed KB commits.
- Always pair each VULNERABLE sample with a CLEAN look-alike; the look-alikes drive the false-positive-rate term that catches FP inflation, the #1 drift failure mode. CVEfixes gives pre/post-fix pairs for free.
- Score with Youden's J (TPR − FPR), the exact OWASP Benchmark / SAST convention, so your numbers are externally comparable and the keep-or-revert decision is a single deterministic number.
- Gate asymmetrically: hard-revert on >2pp recall loss or >1pp FPR gain or any single locked case regressing; KEEP only if J is non-inferior AND (J improves >0.01 OR new sink coverage added).
- Borrow the self-improving-agent promotion eligibility (seen 3+ sessions, same fix each time, 1-2 sentence rule, system unchanged) as a pre-gate filter so one-off noise never reaches the KB.
- Enforce size guardrails: MEMORY.md <=200 lines with overflow to memory/<topic>.md; weekly memory_health_checker.py must end under cap with zero stale rules — bloat is a drift vector.
- Cover AI/LLM-specific sinks separately from generic SAST: prompt-injection (direct+indirect), skill-file/KB poisoning (Skill-Inject), excessive agency, insecure output — map to OWASP LLM Top 10 (2025) and OWASP Agentic Top 10 (Dec 2025).
- Seed AI-attack payloads from AgentDojo (629 cases), InjecAgent (1,000 IPI), BIPIA, and the 2026 unified ~820-string payload library; refresh them on a schedule and re-gate before acceptance.
- Run two CI layers: a deterministic corpus scorer + keep_or_revert.py as a PreToolUse/Stop hook on KB edits, plus promptfoo redteam run (MIT, OpenAI-acquired Mar 2026) and Inspect evals (agentdojo, cyberseceval) nightly.
- Detect PASSIVE drift (from model/provider updates, not just agent edits) with a scheduled weekly full-corpus re-score against the same thresholds — a green gate today can silently regress when the underlying model changes.
- Express the gate as DeepEval pytest-style assertions for clean CI integration and side-by-side run diffing; use Inspect for deeper agentic-security regression coverage.
- Keep everything implementable with Claude Code native primitives: corpus + scorer scripts in-repo, gate as a hook, weekly refresh as a scheduled routine/cron, no from-scratch runtime required.

## Sources

- https://owasp.org/www-project-benchmark/
- https://github.com/TheAuditorTool/sast-benchmark
- https://www.promptfoo.dev/docs/red-team/
- https://www.promptfoo.dev/docs/red-team/configuration/
- https://github.com/promptfoo/promptfoo
- https://deepeval.com/
- https://github.com/confident-ai/deepeval
- https://inspect.aisi.org.uk/
- https://github.com/UKGovernmentBEIS/inspect_evals
- https://inspect.cyber.aisi.org.uk/
- https://www.aisi.gov.uk/blog/inspect-cyber
- https://arxiv.org/pdf/2509.26354
- https://arxiv.org/pdf/2507.21046
- https://borghei.github.io/Claude-Skills/skills/engineering/self-improving-agent.html
- https://github.com/s2e-lab/SecurityEval
- https://arxiv.org/pdf/2107.08760
- https://surrealyz.github.io/files/pubs/raid23-diversevul.pdf
- https://www.semanticscholar.org/paper/InjecAgent:-Benchmarking-Indirect-Prompt-Injections-Zhan-Liang/c8eee9766f0968e8f1b1be0731bc70b85be0ac97
- https://www.emergentmind.com/topics/agentdojo-benchmark
- https://arxiv.org/pdf/2602.20156
- https://arxiv.org/pdf/2509.22040
- https://bsg.tech/blog/owasp-llm-top-10/
- https://blog.alexewerlof.com/p/owasp-top-10-ai-llm-agents
- https://offensive360.com/blog/owasp-juice-shop-alternatives/
- https://code.claude.com/docs/en/sub-agents

