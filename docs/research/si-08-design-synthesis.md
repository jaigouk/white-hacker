# Self-Improvement Layer — Design Synthesis

> Source: workflow w3b87zsau, agent `si-synth:design`.

All facts verified. I have enough grounded detail to write the design. OWASP LLM Top 10 = 2025 (current), Agentic = 2026, OSV.dev `/v1/query` + `/v1/querybatch` no-auth confirmed. Now I'll write the complete design document.

# DESIGN — Self-Improvement Layer for the White-Hacker Claude Code Agent

> Status: proposal for approval. Today is 2026-06-06. All versions/URLs verified against live 2026 sources (see Appendix B). This design assumes a Claude Code agent assembled from native primitives only (subagents, skills, slash commands, hooks, auto-memory, scheduled Routines). No from-scratch runtime, no DSPy.

---

## 0. Design thesis in one paragraph

The white-hacker agent improves by **editing text on three learning surfaces, never by retraining**. The *Context* surface (a versioned AI-attack knowledge base packaged as a progressive-disclosure Skill, plus per-repo auto-memory) holds *what the agent knows*. The *Harness* surface (hooks + settings.json + slash commands + scheduled Routines) holds *how the agent captures signal and enforces guardrails deterministically*. The *Model* surface is frozen — we cannot fine-tune Opus, and we shouldn't want to: all durable learning is a reviewable git diff. The closed loop is GEPA's **control flow** (sample → minibatch → reflect in natural language → re-run → keep only if strictly improved → validate on frozen held-out corpus → PR), wrapped in security-specific guardrails (asymmetric keep-or-revert gate, frozen anti-gaming corpus, human-in-the-loop PR). We start human-gated everywhere and graduate specific steps to autonomy only after they earn it.

---

## 1. Which learning surface each improvement lives on

Three surfaces, mapped to the attached Model/Harness/Context architecture. **Retraining (the Model surface) is out of scope** because (a) we use the hosted `claude-opus-4-8` model — there is no fine-tuning path for it in Claude Code; (b) gradient updates are not reviewable, not revertible, and not auditable, which violates the white-hat agent's core requirement that every change be a signed, inspectable git diff; (c) GEPA/TextGrad's own finding is that **textual** prompt/KB optimization beats scalar-reward weight updates for an LLM optimizer at a fraction of the cost. So every "learning" below is a text edit.

| Improvement type | Surface | Concrete artifact | Why here |
|---|---|---|---|
| New AI-attack technique knowledge | **Context** | New entry in `skills/ai-attack-kb/references/ai-threats/<class>.md` | Progressive disclosure: 0 tokens until a task triggers it |
| Stable web/CWE checklist refinement | **Context** | Edit in `skills/ai-attack-kb/checklists/*.md` | Slow-decaying; yearly cadence |
| Per-repo durable finding ("this codebase's auth uses X") | **Context** | Auto-memory `~/.claude/projects/<repo>/memory/<topic>.md` | Machine-local, repo-scoped, Claude writes it itself |
| Detection rule (Semgrep/Sigma/grep) | **Context** | `skills/ai-attack-kb/scripts/detections/` + fixture pairs | Detection-as-code; testable in CI |
| Deterministic signal capture | **Harness** | `PostToolUse`/`PostToolUseFailure`/`SessionEnd` hooks → JSONL | Runs regardless of model choices |
| Self-write confinement & secret-block | **Harness** | `PreToolUse` hooks (exit 2 / `permissionDecision: deny`) + `settings.json` `permissions.deny` | Guardrails must be enforced by harness, not advised in memory |
| Path-scoped always-on security rules | **Harness** | `.claude/rules/*.md` with `paths:` frontmatter | Loads only when touching matching files; keeps context lean |
| Manual learning triggers | **Harness** | Slash commands w/ `disable-model-invocation: true` | `/reflect`, `/refresh-attack-kb` |
| Reflection / curation pass | **Harness + Context** | `kb-curator` subagent (`memory: project`, `skills: [ai-attack-kb]`, `context: fork`) | Claude-A-authors / Claude-B-uses loop |
| Autonomous feed ingestion | **Harness** | Scheduled Routine (`/schedule`) → draft PR | Cloud infra, fresh clone, nightly |

**Key principle (from takeaways):** *Guardrails belong in the harness, never in memory.* CLAUDE.md and auto-memory are advisory — the model may ignore them. Confinement of self-writes, secret-read blocking, and network-egress control are all enforced via `PreToolUse` hooks and `settings.json` `permissions` (deny wins, merges across scopes).

---

## 2. The living KNOWLEDGE BASE

### 2.1 Two physical tiers (decay rates differ — this is the #1 anti-drift lever)

```
skills/ai-attack-kb/
├── SKILL.md                      # <500 lines, ~5000 tokens. Pure TOC. Always-indexed by 1-line description (~100 tok).
├── manifest.json                 # content_version (YYYY.MM.N) + format_version (semver). ATLAS convention.
├── CHANGELOG.md                  # append-only, dated. Audit trail.
├── checklists/                   # STABLE TIER — yearly cadence. Refresh routines NEVER touch this.
│   ├── owasp-web-top10.md
│   ├── cwe-top25.md
│   └── auth-crypto-baseline.md
├── references/                   # FAST TIER — monthly cadence. Exactly ONE level deep from SKILL.md.
│   └── ai-threats/
│       ├── prompt-injection.md          # one file per technique_class
│       ├── indirect-injection.md
│       ├── tool-poisoning.md
│       ├── memory-context-poisoning.md
│       ├── skill-kb-injection.md        # Skill-Inject
│       ├── excessive-agency.md
│       ├── insecure-output.md
│       └── mcp-confused-deputy.md
├── archive/                      # deprecated/superseded entries. NEVER delete — move here. 0 tokens until read.
├── detections/                   # detection-as-code spine
│   ├── join.csv                  # technique → checklist-item → detection-rule join table
│   ├── rules/*.{semgrep.yml,sigma.yml,grep.txt}
│   └── fixtures/<rule-id>/{vulnerable.*, benign.*}   # mandatory PAIR per rule
└── scripts/
    ├── validate_kb.py            # CI + PreToolUse gate: schema, IDs, size caps, source-linking
    ├── dedupe_kb.py              # title-similarity + shared xref flagging
    └── staleness_check.py        # flags entries past review_by
```

**Separation of AI-attack knowledge from stable checklists is physical, not by convention.** The fast tier (`references/ai-threats/`) gets ATLAS `AML.T*` techniques, OWASP Agentic ASI01–ASI10, prompt/tool/memory/skill injection — refreshed monthly. The stable tier (`checklists/`) gets OWASP Web Top 10, CWE Top 25 — refreshed yearly. **Refresh Routines are scoped to the fast tier only**; this single rule prevents most drift.

### 2.2 Entry schema (fused Sigma + Semgrep front-matter)

Each entry in a `references/ai-threats/<class>.md` file is a section with YAML front-matter. Summary body ≤120 words. Group entries **by technique_class, one file each** so Claude reads whole files instead of `head -100` previews.

```yaml
---
id: WHK-AITHREAT-0042            # typed, never-reused (ATLAS convention)
title: Indirect prompt injection via retrieved web content
technique_class: indirect-injection   # from CONTROLLED vocabulary (dedup layer 1)
affected_stack: [rag, browser-tool, mcp-fetch]
severity: high                  # Sigma: critical|high|medium|low|informational
confidence: medium              # Semgrep: high|medium|low
status: active                  # active|archived|deprecated
date: 2026-04-30                # first created
modified: 2026-05-22            # bump ONLY on title/logic/severity/class change (Sigma discipline)
review_by: 2026-08-22           # CI flags as stale past this date (primary fast-tier anti-drift guard)
metadata:
  source: AML.T0051             # MANDATORY: real ATLAS AML.Txxxx | OWASP ASIxx | CVE-xxxx
  url: https://atlas.mitre.org/techniques/AML.T0051
  retrieved: 2026-04-30         # MANDATORY dated provenance
supersedes: [WHK-AITHREAT-0011] # explicit lineage for merges
detections: [DET-IPI-RAG-01, DET-IPI-RAG-02]   # join to detection rules
xref: [OWASP-ASI01, OWASP-LLM01]
---
```

**Blocking validator rule (in `validate_kb.py`, wired as a `PreToolUse` hook):** an AI-threat entry **cannot be persisted** without `metadata.source` (matching `AML\.T\d+|ASI\d+|CVE-\d{4}-\d+`) + `url` + `retrieved`. This is what keeps the KB auditable instead of hallucinated. Refuse to write an unsourced threat claim.

### 2.3 Size caps & distillation (enforced mechanically, not by trust)

| Artifact | Cap | Enforced by |
|---|---|---|
| `SKILL.md` | <500 lines / ~5000 tokens | `validate_kb.py` (CI + PreToolUse) |
| reference file | ~400 lines (TOC if >100) | `validate_kb.py` |
| entry summary | ≤120 words | `validate_kb.py` |
| `MEMORY.md` index | ≤200 lines / 25KB | native + weekly `memory_health_checker` |
| skill `name` | ≤64 chars, == parent dir name, no `anthropic`/`claude` | `validate_skill.py` (PreToolUse) |
| skill `description` | ≤1024 chars, third-person what+when | `validate_skill.py` |

**Distillation cadence:** the native `consolidate-memory` skill is wired into a weekly schedule to merge duplicates / fix stale facts / prune the index — *we do not reinvent memory curation*. For the KB proper, `dedupe_kb.py` runs in CI: two-layer dedup = (1) controlled `technique_class` vocabulary stops synonym sprawl; (2) script flags entries sharing an ATLAS/OWASP xref or high title similarity, merged via `supersedes` lineage. **CI fails on duplicate IDs.** Aging-out uses an `archive/` move (never delete) plus a `## Old patterns` `<details>` block for deprecated in-file techniques — no time-sensitive prose ("before August 2025") that becomes a time-bomb.

---

## 3. The CLOSED LEARNING LOOP (`/reflect` + `/learn` + hooks)

This is the GEPA control flow, not the GEPA pipeline. **Two tiers: cheap CAPTURE (hooks, no LLM cost) separated from gated COMMIT (semantic + human-reviewed).** This is the claude-reflect pattern.

### 3.1 CAPTURE tier (deterministic, every session, ~0 cost)

`.claude/settings.json` (exact verified hook schema — `hooks.<EventName>[].matcher` + `hooks[]` array of `{type, command}`; block via exit 2 / `permissionDecision: deny`):

```json
{
  "hooks": {
    "PostToolUse": [
      { "matcher": "Bash|Read|Grep|WebFetch",
        "hooks": [{ "type": "command",
          "command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/append_trace.sh",
          "async": true }] }
    ],
    "PostToolUseFailure": [
      { "matcher": "Bash",
        "hooks": [{ "type": "command",
          "command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/log_failed_exploit.sh",
          "async": true }] }
    ],
    "SessionStart": [
      { "hooks": [{ "type": "command",
          "command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/inject_cve_digest.sh" }] }
    ],
    "SessionEnd": [
      { "hooks": [{ "type": "command",
          "command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/log_corrections.sh",
          "async": true }] }
    ],
    "Stop": [
      { "hooks": [{ "type": "command",
          "command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/save_learnings_nudge.sh" }] }
    ]
  }
}
```

- `PostToolUse`/`PostToolUseFailure` → append every tool call and every failed exploit attempt to `evals/traces/findings-YYYY-MM.jsonl` (confidence-scored, queues candidates — **no LLM cost**).
- `SessionStart` → inject the freshness/CVE digest (output of the nightly refresh routine); may set `reloadSkills: true` so a same-session KB rewrite takes effect immediately.
- `SessionEnd`/`Stop`/`SubagentStop` → log user corrections cheaply and inject a "save what you learned" nudge.

### 3.2 COMMIT tier (`/reflect` slash command — human-gated)

`skills/reflect/SKILL.md` front-matter:

```yaml
---
name: reflect
description: Reflects on captured review traces and user corrections, proposes KB/checklist diffs, gates them against the frozen eval corpus, and opens a PR. Use after a review session or on the weekly schedule.
disable-model-invocation: true     # manual trigger only
context: fork                       # isolated context
agent: kb-curator                  # runs in the curator subagent
---
```

Dynamic context injection harvests the raw signal at invocation via `!`./scripts/harvest.sh`` (collates this week's traces + corrections). The skill body runs the GEPA control flow:

1. **Reflect (textual, not scalar).** For each FP and each miss, emit *structured rationale*: `why_missed` / `why_fp_fired`, candidate root cause, proposed minimal edit. Textual feedback is the learning signal (GEPA + TextGrad core finding) — never just pass/fail.
2. **Pre-gate filter (promotion eligibility).** Only consider a lesson if: seen in ≥3 sessions, same fix each time, expressible in 1–2 sentences, system unchanged. One-off noise never reaches the KB.
3. **Self-critique step.** Before proposing: *Is this generalizable or overfit to one incident? Is it "technically true but misleading"?* Discard overgeneralizations.
4. **Sample candidate → minibatch → re-run → keep only if strictly improved** (GEPA Algorithm 1 line 14). Run candidate KB version on a cheap minibatch of eval cases; reflect on traces; re-run on the **same** minibatch; keep only on strict improvement; then validate on the **full frozen held-out set**.
5. **Default to PATCH over CREATE** (fight skill-index sprawl). Dedup-before-create: embed/grep the proposed description against all existing; on overlap, convert create→patch.
6. **Write to a branch, open a PR via `gh`** with evidence: session ids, motivating FP/miss, before/after score table. The optimizer **never writes the live KB and never merges itself.**

### 3.3 Four triggers → four actions

| Trigger | Action | Default |
|---|---|---|
| Novel vuln class (no matching technique_class) | Create new reference entry / skill | CREATE |
| Recurring false positive (N≥2 dismissals) | Patch the entry's exclusions/benign section | PATCH |
| User correction | Patch/edit the relevant entry | PATCH |
| New technique from a feed | Scheduled routine drafts a PR (§4) | PATCH |

### 3.4 Guardrails on the loop

- **Confinement (harness):** `PreToolUse` hook denies any `Write`/`Edit` outside `skills/ai-attack-kb/**`, `.claude/rules/**`, and the auto-memory dir; denies reads of `**/.env`, `**/secrets/**`, private keys; denies network egress except the allow-listed feed hosts. Exit 2 wins.
- **Frozen corpus & gate script are read-only to the agent** — separate identity; a hook blocks agent writes to `evals/corpus/**` and `scripts/keep_or_revert.py`.
- **No autocommit, never the default branch.** Every self-write is a PR reviewed as a diff with Apply/Edit/Skip; decision + diff + source journaled to `evals/audit-log.md`.
- **Rejected-hypotheses log** (`evals/rejected.md`): failed edits recorded so the loop never re-proposes the same loser (GEPA's discard-with-memory path).
- **Second ratchet:** every newly-confirmed true finding (+ labels) is promoted INTO the frozen corpus, so the bar rises and the KB can't drift.

---

## 4. The KB-REFRESH routine (scheduled feed polling → dated draft PRs)

A **cloud Scheduled Routine** (Anthropic infra, no machine needed, fresh clone, runs to completion, commits to a `claude/`-prefixed branch and opens a PR). Created via `/schedule`. **Hourly is the minimum cadence; sub-hourly cron is rejected.** Touches the **fast tier only**.

### 4.1 Polling tiers (by feed machine-readability)

| Cadence | Feeds | Access |
|---|---|---|
| **Daily** | OSV.dev `POST /v1/query` + `/v1/querybatch` (allow-list of AI pkg names, e.g. `vllm`, `langchain`, `transformers`, `@modelcontextprotocol/*`); GitHub Global Advisory DB `GET api.github.com/advisories?ecosystem=pip`; arXiv `rss.arxiv.org/rss/cs.CR`; ATLAS `dist/ATLAS-latest.yaml` + `dist/stix-atlas.json` (poll repo/releases, not the website); `.atom` blogs | JSON/RSS, no-auth for public data |
| **Weekly** | embracethered.com `/blog/index.xml`; simonwillison.net `prompt-injection.atom` + `llms.atom`; Microsoft Security Blog `/security/blog/feed/` + MSRC; Google Online Security Blog feed (GTIG) | RSS/Atom |
| **Monthly** | OWASP framework PDFs/HTML (genai.owasp.org — WebFetch + LLM-extraction); NIST CSRC News RSS (Cyber AI Profile NISTIR 8596 draft; COSAIS SP 800-53 overlays) | HTML/PDF |

arXiv cs.CR firehose is pulled daily and **LLM-filtered** for: prompt injection, indirect injection, jailbreak, agent hijack, tool/RAG poisoning, lethal trifecta, MCP. Anthropic Newsroom has no official feed → WebFetch + extraction.

### 4.2 Routine logic

1. **Diff incrementally.** Store last-seen markers (etag / stable ID / `content_version`) in `evals/feed-state.json`; only process deltas.
2. **Extract NEW techniques.** LLM-extract from deltas; map each to a `technique_class`, ATLAS `AML.T*` / OWASP `ASIxx` / CVE.
3. **Draft dated entries with provenance** using the §2.2 schema (`source` + `url` + `retrieved` mandatory).
4. **Run `validate_kb.py` + `dedupe_kb.py`** in the routine; dedup-before-create.
5. **Re-gate** against the frozen corpus before proposing (no auto-acceptance of a draft that regresses).
6. **Open a PR, never auto-merge.** Human reviews. Write the digest (new CVEs/techniques) so `SessionStart`'s `inject_cve_digest.sh` can surface it next session.

### 4.3 Scheduling in Claude Code (three tiers — pick by need)

- **Cloud Routines (`/schedule`)** — the primary mechanism here. Nightly disclosure scan + draft PRs. No local machine, fresh clone, no local-file access. Min cadence hourly. Shares your usage quota — schedule off-peak.
- **Session cron / `/loop`** — 1-min granularity, **7-day expiry**, for in-session upkeep only (e.g. re-poll during a long engagement).
- **Desktop Scheduled Tasks** — when durable **local-file** access is required (auto-memory is machine-local and not synced; a routine's fresh clone can't see it).

**Knowledge-freshness anchors** the routine cheaply diffs version strings against: OWASP LLM Top 10 = **2025** (watch for 2026 revision), OWASP Agentic Top 10 = **2026**, ATLAS content = **2026.05** / format **6.0.0**, NIST AI 600-1, COSAIS/Cyber-AI-Profile draft status.

---

## 5. Autonomous skill/KB generation — triggers + pre-commit safety checklist

### 5.1 Triggers (same four as §3.3)

Novel vuln class → CREATE skill/entry; recurring FP (N≥2) → PATCH exclusions; user correction → PATCH; new feed technique → routine drafts PR. **Default PATCH over CREATE.**

### 5.2 Mandatory safety checklist — every gate must pass before any self-write commit

A self-write is **blocked at `PreToolUse` (exit 2)** unless `validate_skill.py` / `validate_kb.py` confirm all of:

1. **Schema/spec caps:** skill `name` ≤64, == parent dir name, no `anthropic`/`claude` reserved word; `description` ≤1024 third-person what+when; `SKILL.md` <500 lines; reference ≤400 lines; entry ≤120 words.
2. **References one level deep** from SKILL.md; any file >100 lines has a TOC.
3. **Source-linking present** for AI-threat claims (`source`+`url`+`retrieved`, regex-matched).
4. **Dedup passed:** no duplicate ID; no high-similarity collision (else convert to PATCH + `supersedes`).
5. **Identity preservation:** the edit does not alter the agent's role/guardrail prose (CLAUDE.md, core rules untouched); curator subagent has no permission to edit `.claude/rules/` security rules.
6. **Confinement:** write target is inside `skills/ai-attack-kb/**` or auto-memory only.
7. **Self-critique passed:** generalizable, not overfit, not "technically-true-but-misleading."
8. **Promotion eligibility:** seen ≥3 sessions / same fix / 1–2 sentences / system unchanged.
9. **Regression gate green** (§6).
10. **It is a PR on a feature branch, not the default branch, not autocommit.**

If any check fails: do not write; log to `evals/rejected.md`.

---

## 6. Eval / regression corpus design + keep-or-revert thresholds

### 6.1 Corpus (frozen, read-only, anti-gaming)

```
evals/
├── corpus/                       # FROZEN. Agent-write blocked by hook. Signed commits.
│   ├── cases/<id>/{target.*, vulnerable_variant.*, benign_lookalike.*, label.json}
│   └── README.md                 # ground truth provenance
├── keep_or_revert.py             # the gate. Agent cannot edit.
├── score.py                      # deterministic scorer (Youden's J)
├── feed-state.json
├── audit-log.md
└── rejected.md
```

- **≥~100 paired cases** (AgentAssay 2026: below that the bootstrap CI is wider than the regressions you're hunting). Each VULNERABLE case is paired with a **CLEAN look-alike** — the look-alikes drive the false-positive term that catches FP inflation (the #1 drift mode). CVEfixes gives pre/post-fix pairs for free.
- **AI/LLM sinks covered separately** from generic SAST: prompt-injection (direct+indirect), skill-file/KB poisoning (Skill-Inject), excessive agency, insecure output → mapped to OWASP LLM Top 10 (2025) + OWASP Agentic Top 10 (2026).
- **Payload seeds:** AgentDojo (629), InjecAgent (1,000 IPI), BIPIA, the 2026 unified ~820-string library — refreshed on schedule and re-gated before acceptance.
- **Regression anchors** (validate the pipeline against real CVEs): vLLM auto_map RCE **CVE-2026-22807**, vLLM get_config RCE **GHSA-8fr4-5q9j-m8gm**, vLLM video-URL RCE **CVE-2026-22778**, LangChain serialization injection **CVE-2025-68664**.

### 6.2 Scoring & verdict

- **Score = Youden's J (TPR − FPR)** — the OWASP Benchmark / SAST convention, so numbers are externally comparable and the decision is a single deterministic number.
- **3-valued verdict (Pass/Fail/Inconclusive)** from a **paired bootstrap, k=3–5 runs/case** — agent runs are non-deterministic; a raw-mean comparison fires false regression alarms.
- **Whole-corpus re-eval:** fixing the target case while breaking any other case = regression (GEPA's keep-complementary insight; git is the Pareto pool — cherry-pick the lesson that helped case A even after reverting the edit that hurt case B).

### 6.3 Regression definition (precise)

Any of: a previously-caught true finding now missed (recall drop) · a clean case now producing a new FP (precision drop) · a severity inversion · fixing the target while breaking any other case.

### 6.4 Keep-or-revert thresholds (asymmetric — a guardrail, not a maximizer)

```
HARD REVERT if:  recall_loss > 2pp  OR  FPR_gain > 1pp  OR  any single locked case regresses
KEEP only if:    J non-inferior  AND ( J improves > 0.01  OR  new sink coverage added )
SECURITY GATE:   severity-weighted recall >= baseline  AND  precision >= baseline - epsilon
```

The gate blocks regressions; it does not chase a benchmark high score.

### 6.5 Two CI layers + passive-drift detection

- **Deterministic layer:** `score.py` + `keep_or_revert.py`, wired as a `PreToolUse`/`Stop` hook on KB edits; expressed as **DeepEval pytest-style assertions** for clean CI diffing.
- **Red-team layer (nightly):** `promptfoo redteam run` (MIT, OpenAI-acquired 2026-03-09 — still open source) + **Inspect** evals (agentdojo, cyberseceval) for deeper agentic-security coverage.
- **Passive-drift guard:** a **weekly scheduled full-corpus re-score** against the same thresholds — a green gate today can silently regress when the underlying model/provider updates, not just when the agent edits itself.

---

## 7. Phased rollout (human-in-the-loop first, graduate to autonomy)

**Phase 0 — Capture & confine (week 1). Build first.**
Ship the harness skeleton: `PostToolUse`/`PostToolUseFailure`/`SessionEnd`/`Stop` capture hooks → JSONL traces; `PreToolUse` confinement + secret-block hooks; `settings.json` `permissions.deny`; `.claude/rules/` path-scoped security rules. *Value: signal + guardrails before any learning. Lowest risk.*

**Phase 1 — KB as a Skill (week 1–2).**
Stand up `skills/ai-attack-kb/` with the two-tier layout, `manifest.json` (content/format versions), schema, `validate_kb.py` + `dedupe_kb.py` + `staleness_check.py` in CI and as PreToolUse gates. Seed the fast tier from ATLAS 2026.05 + OWASP Agentic 2026; seed checklists from OWASP Web Top 10 + CWE Top 25.

**Phase 2 — Frozen eval corpus + gate (week 2–3).**
Build ≥100 paired cases (vulnerable + benign look-alike), seed from AgentDojo/InjecAgent/BIPIA + the CVE anchors. Ship `score.py` (Youden's J), `keep_or_revert.py` (asymmetric thresholds), DeepEval assertions. Freeze it; block agent writes via hook. *Nothing graduates to autonomy until this exists.*

**Phase 3 — Manual closed loop (week 3–4). Fully human-gated.**
`/reflect` slash command (`disable-model-invocation`, `context: fork`, `agent: kb-curator`) running the GEPA control flow → branch → PR with before/after table. Wire `consolidate-memory` into a weekly schedule. Human approves every PR (Apply/Edit/Skip), decisions journaled.

**Phase 4 — Scheduled refresh, still human-merged (week 4–6).**
Cloud Routine via `/schedule`: daily JSON/RSS poll (OSV, GitHub Advisory, arXiv, ATLAS), weekly blog poll, monthly framework poll → incremental diff → draft dated entries → `validate`+`dedupe`+`gate` → **draft PR, never auto-merge**. Add nightly `promptfoo redteam` + Inspect + weekly passive-drift re-score.

**Phase 5 — Graduated autonomy (week 6+). Earn it per-step.**
Only after a step demonstrates a clean track record (e.g. ≥20 PRs where human approval matched the gate's verdict) do we loosen it — and only for the **lowest-risk, highest-precision** classes:
- Auto-merge **feed-sourced PATCH-only** entries that (a) pass the gate green, (b) add no new sink, (c) carry valid `source`+`url`+`retrieved`, (d) touch only the fast tier. CREATE, checklist edits, and any rule/CLAUDE.md change **remain human-gated indefinitely** — identity preservation is non-negotiable.
- Keep the second ratchet running (promote confirmed findings into the frozen corpus) so the bar keeps rising.

---

## Appendix A — Native-primitive gaps engineered around

| Native gap | Mitigation in this design |
|---|---|
| No built-in eval runner | We ship `score.py`/`keep_or_revert.py` + DeepEval assertions (eval-driven, §6) |
| No automatic KB dedup/ranking | `dedupe_kb.py` (controlled vocab + similarity + `supersedes`), CI fails on dup IDs |
| Session cron 7-day expiry | Use cloud Routines for durable schedules; session cron only for in-engagement upkeep |
| Auto-memory is machine-local, not synced | Durable cross-machine learnings go to the git-tracked KB, not auto-memory |
| Subagents cannot spawn subagents | `kb-curator` does the full curation itself; refresh is a Routine, not a nested subagent |
| Routine fresh clone can't see local files | Anything a routine needs is committed to the repo (skills, corpus, scripts) |

## Appendix B — Facts verified live (2026-06-06)

- **MITRE ATLAS:** content_version **2026.05** (2026-05-27), format_version **6.0.0**; `dist/ATLAS-latest.yaml` + `dist/stix-atlas.json` confirmed in `github.com/mitre-atlas/atlas-data`.
- **OWASP Top 10 for Agentic Applications 2026:** released **2025-12-09**; ASI01 Agent Goal Hijack … ASI10 Rogue Agents confirmed (genai.owasp.org).
- **OWASP LLM Top 10:** current version **2025** (System Prompt Leakage + RAG/embedding entries new in 2025); no 2026 revision published yet.
- **Claude Code auto-memory:** `~/.claude/projects/<project>/memory/`, `MEMORY.md` index loads first **200 lines** at SessionStart; topic files load on demand.
- **Claude Code Routines:** research preview **2026-04-14**, Anthropic cloud, fresh clone from default branch, commits to `claude/`-prefixed branch + PR; `/schedule` supports hourly/daily/weekday/weekly — **sub-hourly cron rejected**; shares interactive usage quota.
- **Hooks schema (verified):** `hooks.<EventName>[].matcher` + `hooks[]` array of `{type, command}`; block via **exit 2** or `permissionDecision: "deny"` (values allow/deny/ask/defer); **`PostToolUseFailure`**, `SessionStart`, `SessionEnd`, `Stop`/`StopFailure`, `SubagentStop` all confirmed real events.
- **promptfoo:** MIT, open source; **OpenAI acquisition announced 2026-03-09** (~$86M); stays open source.
- **OSV.dev:** `POST /v1/query` + `/v1/querybatch`, JSON, **no auth** for public data; aggregates GitHub Security Advisories.
- **CVE anchors:** CVE-2026-22807 (vLLM auto_map RCE, fixed 0.14.0) confirmed; CVE-2026-22778 (vLLM video-URL RCE) confirmed.

Sources: [MITRE ATLAS data repo](https://github.com/mitre-atlas/atlas-data) · [OWASP Agentic Top 10 2026](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) · [OWASP GenAI LLM Top 10](https://genai.owasp.org/llm-top-10/) · [Claude Code memory docs](https://code.claude.com/docs/en/memory) · [Claude Code scheduled tasks docs](https://code.claude.com/docs/en/scheduled-tasks) · [Claude Code hooks docs](https://code.claude.com/docs/en/hooks) · [OpenAI acquires Promptfoo](https://openai.com/index/openai-to-acquire-promptfoo/) · [OSV API docs](https://google.github.io/osv.dev/api/) · [CVE-2026-22807 (Wiz)](https://www.wiz.io/vulnerability-database/cve/cve-2026-22807)
