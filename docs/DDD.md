# DDD — Domain Model for white-hacker

> A **model, not an implementation.** This document fixes the *ubiquitous language*
> and the *bounded contexts* of the white-hacker agent so that every artifact under
> `.claude/` (agent, skills, references, hooks) speaks one consistent vocabulary.
> Where this model and a file on disk disagree, the file's behaviour is the source of
> truth — open a diff to reconcile. Companion to `docs/ARD.md` (the *why*),
> `docs/ARCHITECTURE.md` (the *what/how*), and `docs/plan/PLAN.md` (the *build order*).

The whole product is **two nested loops over plain-text artifacts behind open
interfaces** (Agent Skills, MCP):

- **INNER loop — the Review** (Anthropic `defending-code` methodology):
  threat-model → discovery (recall) → verification (precision) → triage → patch (+re-attack).
- **OUTER loop — Self-Improvement** (Model / Harness / Context surfaces; *no retraining* —
  only text edits behind interfaces): trace → reflect → propose text diffs → gate
  (eval keep-or-revert) → PR.

**The inner loop CONSUMES the knowledge base; the outer loop EDITS it.** Everything
between the two loops flows as files. Tools are a *swappable capability layer* (ADR-015),
not part of the domain's identity.

---

## 1. Ubiquitous Language (glossary)

These terms are used *exactly* as defined here in code, prompts, JSON keys, and docs.
A term in **bold** is a domain object; the context that owns it is named in brackets.

| Term | Definition | Owner context |
|---|---|---|
| **Finding** | A claim that a specific code location exhibits a vulnerability class. Has identity (`id`), a `file:line` anchor, and a lifecycle (Candidate → Confirmed/Rejected → Canonical). Never invented; always cites evidence. | Review |
| **Candidate** | A Finding in the *discovery* state: recorded by the recall pass, possibly unproven, explicitly flag-able. Self-censorship is forbidden here. | Review |
| **Confirmed** | A Candidate that survived verification: a fresh-context adversarial pass tried to refute it and failed. Carries a `Verdict` and a precondition-counted `Severity`. | Review |
| **ThreatModel** | The scoping & calibration aggregate for one repo/engagement: assets, entry points, **TrustBoundary** set, in-scope vuln classes, and the chosen `scoring standard`. The top precision lever (~90% exploitable findings when well-defined). | Review |
| **TrustBoundary** | A line across which data changes trust level (e.g. network→handler, tenant A→tenant B, model-output→sink). Reachability and severity are derived *relative to* boundaries, not in the abstract. | Review |
| **ScanPlan** | The per-run detection plan: detected languages/frameworks, the attack-surface **partition**, which scanners (by capability) apply, which reference appendices and the AI/LLM pass to load. Output of detection. | Review / Tooling |
| **Capability** | The durable *interface* the agent depends on: `SAST · SCA · secrets · IaC · AI-redteam`. Stable while tools churn. The agent depends on a Capability, never on a brand. | Tooling |
| **Tool** | A concrete, swappable implementation of one or more Capabilities (e.g. an SAST engine, an SCA scanner). Discovered at runtime, pinned, and mapped to its Capability. Illustrative, never required. | Tooling |
| **Floor** | The zero-install fallback Capability implementation: built-in Read/Grep/Glob scoped to cwd. Always available; produces value with zero external Tools. | Tooling |
| **ReviewSession** | One end-to-end run of the inner loop over a target diff/path. The unit the outer loop later *reflects on*. Produces the artifact chain and a JSONL trace. | Review (traced into Knowledge) |
| **Severity** | A *derived*, precondition-counted rank (HIGH/MEDIUM/LOW), computed in triage as `min(precondition_count_score, required_access_level_score)`; a ThreatModel match may bump at most one step. Never the finder's self-assessment. The `severity_label` (presentation, per scoring standard) is distinct from this sort key. | Review |
| **Verdict** | The triage outcome for a Finding. Two orthogonal axes kept separate: **verification class** ∈ `{ladder_passed, ladder_failed, static_review_only}` and **review outcome** ∈ `{ACCEPT, REJECT}`. Downstream branches on *class*, not outcome. | Review |
| **Exclusion** | A rule in the DO-NOT-REPORT list that suppresses a known-noisy class (DoS, test/dead code, path-only SSRF, prompt-injection-as-code-bug, …). Config-extendable per project; cited by id when a Finding is rejected. | Review (rules curated by Knowledge) |
| **KnowledgeBaseEntry** | A dated, sourced, status-tagged unit of AI-attack knowledge (`active/archived/deprecated`), mapping a **Technique** → detection pattern → checklist item. Mandatory provenance (`source`+`url`+`retrieved`). Lives behind progressive disclosure. | Knowledge |
| **Technique** | A named class of attack against an AI/LLM/agent/MCP product (e.g. indirect injection, tool poisoning, memory poisoning). Drawn from a controlled `technique_class` vocabulary; the dedup anchor for entries. | Knowledge |
| **Feed** | An authoritative external source of new Techniques/CVEs/tools (OWASP GenAI, MITRE ATLAS, OSV/GHSA, arXiv cs.CR, practitioner blogs). Polled on a cadence; the *input arm* that ingests "new ways to hack AI products." | Knowledge |
| **EvalCase** | A frozen, labelled corpus item — a vulnerable sample *paired with a clean look-alike* — used by the keep-or-revert gate. Read-only to the agent (separate identity). The anti-gaming ground truth. | Knowledge |
| **Skill** | A progressive-disclosure procedure (one stage of a loop) packaged as `SKILL.md` + `reference/` + `scripts/`. Procedural memory: ~100 tokens indexed, body on invoke, references on demand. The unit the outer loop creates/patches. | (cross-context) |
| **Artifact** | A plain-text, on-disk file that chains stages and survives context exhaustion: `THREAT_MODEL.md → SCAN-PLAN.json → VULN-FINDINGS.json → TRIAGE.json → PATCHES/ → SECURITY-REPORT.md`. The integration mechanism between every context. | (cross-context) |

---

## 2. The bounded contexts (overview)

Four contexts, each with a single responsibility and a clear loop allegiance:

| Context | Loop | One-line responsibility | Talks to others via |
|---|---|---|---|
| **Review** | inner | Run one ReviewSession; turn a diff into Confirmed Findings + a report. | the Artifact chain; *reads* Knowledge & Tooling |
| **Knowledge** | outer | Hold & curate what the agent knows (KB + Exclusions + EvalCases); ingest Feeds; reflect on traces. | proposes diffs (PRs); *serves* entries to Review |
| **Tooling** | (serves both) | Map Capabilities → discovered Tools; degrade to the Floor; keep the registry current. | ScanPlan; registry entries curated by Knowledge |
| **Team** | (orchestrates inner) | Place the Review context into a TL/QA/Dev/white-hacker workflow; route results. | Artifact handoff + (opt-in) SendMessage |

A deliberate dependency rule keeps the model clean: **Review depends on Knowledge and
Tooling at read-time; Knowledge depends on Review only through recorded traces
(never live).** No context reaches into another's internals — they integrate through
Artifacts (and, in Team mode, a mailbox).

---

## 3. Context: REVIEW (the inner loop)

> Responsibility: take an authorized diff/path and produce **real, high-confidence,
> exploitable** Confirmed Findings, a report, and (opt-in) proposed patches — under a
> read-only, treat-all-input-as-untrusted posture.

### Aggregates

- **ReviewSession** *(root aggregate)* — owns one run end to end. Its consistency
  boundary is "one target, one threat model, one artifact chain." It coordinates the
  six stages but holds no cross-session state; resumability lives in the Artifacts and
  checkpoint files, not in memory.
- **ThreatModel** *(aggregate root)* — assets + entry points + TrustBoundary set +
  in-scope classes + scoring standard. Bootstrapped interactively or synthesized from
  docs/git-history/past-fixes. Calibrates severity for the whole session.
- **FindingSet** *(aggregate root)* — the collection of Findings with the invariant that
  *each appears exactly once*; duplicates collapse to a `canonical_of` reference. Passes
  through states (Candidate → {Confirmed, Rejected}) without ever losing identity.

### Entities

- **Finding** — identity `id` (`F-001`…), `file:line`, `category`, `owasp[]`, lifecycle
  state, `preconditions[]`, `access_required`, `Verdict`, `Severity`, `confidence`,
  `tool_assisted`, `kb_refs[]`. The same Finding object is *enriched* across stages,
  not recreated.
- **TrustBoundary** — entity within ThreatModel; reachability is computed across it.
- **PatchProposal** — a candidate fix entity (opt-in), living only under `./PATCHES/`,
  with a `PATCH-STATE.json` recording the ladder result. Never mutates the working tree.

### Value objects (immutable, identity-free)

- **Severity** — `(rank, severity_label)`; derived, precondition-counted; comparable.
- **Verdict** — `(verification_class, review_outcome)`; the two axes are independent.
- **Preconditions** — an ordered set enumerated *before* scoring (anti-inflation).
- **PartitionKey** — endpoint/component/subsystem label used to fan out discovery.
- **Confidence** — `[0,1]`; report ≥ 0.7; final gate HIGH/MEDIUM ≥ 8/10 and >80% exploitability.
- **Evidence** — `{first_link: "path:line", exploit_scenario, recommendation}`.

### Stage operations (the inner loop, in order)

1. **Threat-model** → `THREAT_MODEL.md`. Scope & calibrate; pick the scoring standard.
2. **Detect** → `SCAN-PLAN.json`. Partition the surface; choose Capabilities/appendices
   (delegates Tool selection to the Tooling context).
3. **Discovery — RECALL** → `VULN-FINDINGS.json`. Partition-then-fan-out; simple
   non-prescriptive prompts; record Candidates, *do not self-censor*. (`secrets-scan`,
   `deps-scan`, `ai-llm-review` contribute here; `ai-llm-review` *reads the KB*.)
4. **Verification + triage — PRECISION** → `TRIAGE.json`. **Fresh context, no shared
   history.** Assume each Finding is a false positive and try to refute it; adversarial
   **N-of-N voting** (default 3); dedup by root cause; apply Exclusions; derive Severity.
5. **Report** → `SECURITY-REPORT.md` + machine JSON. Map to OWASP IDs; CI gates on
   `counts.high == 0`.
6. **Patch (opt-in)** → `PATCHES/`. Ladder: build → original PoC stops → tests pass →
   **re-attack with a fresh agent**. Root-cause fix + variant hunt; minimal diff.

### Invariants

- **Recall/precision separation.** Discovery and verification run in **distinct
  contexts**; verification has *no shared history/filesystem state* from discovery. (ADR-008)
- **Severity is derived, not declared.** Computed in triage from preconditions; a finder
  never sets it. `verification_class` ≠ `review_outcome` ≠ `severity_label`.
- **Context starvation at the gate.** The decision-making voter/patcher sees only
  `{file, line, category, diff}` — never Finding prose or author rationale — so injected
  instructions can't pass both author and gate.
- **Single-occurrence.** Every input Finding appears once in `TRIAGE.json`; duplicates
  reference a canonical id.
- **Read-only + capability-removed writes.** No working-tree mutation; `sec-patch` can
  write *only* to `./PATCHES/` (capability removed, not merely instructed — ADR-010).
- **Untrusted-input posture.** All reviewed content (code, comments, tickets, model/tool/
  RAG output, KB text) is untrusted; Agents Rule of Two holds (never simultaneously hold
  untrusted input + secrets + egress).
- **Static-analysis-only by default.** No build/run/install/network during scanning;
  "no PoC" is weak evidence, not proof of safety (ADR-007).

---

## 4. Context: KNOWLEDGE (KB + feeds + learn)

> Responsibility: hold *what the agent knows*, keep it *current and auditable*, and
> *improve* it via the outer loop — entirely as reviewable text diffs, never retraining.

### Aggregates

- **KnowledgeBase** *(aggregate root)* — the living AI-attack KB, physically split into
  two tiers with different decay rates (the #1 anti-drift lever): a **fast tier**
  (`reference/` AI-threat entries, ~monthly) and a **stable tier** (web/CWE checklists,
  ~yearly). Refresh routines touch the **fast tier only**. Owns a `manifest`
  (content_version + format_version) and an append-only changelog.
- **EvalCorpus** *(aggregate root)* — the frozen, ≥~100 paired EvalCases. **Read-only to
  the agent** (a separate identity owns it). The keep-or-revert gate and scorer are part
  of this aggregate's consistency boundary.
- **ExclusionRuleSet** *(aggregate root)* — the DO-NOT-REPORT list (Review consumes it;
  Knowledge curates it). Config-extendable per project.

### Entities

- **KnowledgeBaseEntry** — typed never-reused `id`, `title`, `technique_class`,
  `severity`, `confidence`, `status`, `date`/`modified`/`review_by`, mandatory
  `metadata.{source,url,retrieved}`, `supersedes[]`, `detections[]`, `xref[]`. Aged out
  by *moving to archive*, never deletion.
- **Feed** — a polled source with a last-seen marker; emits deltas → draft entries.
- **EvalCase** — `{vulnerable, benign_lookalike, label}`; the look-alike drives the
  false-positive term that catches FP inflation.
- **LearningProposal** — a candidate diff (new/patched entry, checklist tweak, exclusion,
  or tool-registry addition) carrying its motivating trace evidence; becomes a PR.

### Value objects

- **Technique** (`technique_class`) — from a controlled vocabulary (dedup layer 1).
- **Provenance** — `(source, url, retrieved)`; **blocking**: an AI-threat claim cannot be
  persisted without it (refuse to write an unsourced technique).
- **ContentVersion** / **FormatVersion** — `YYYY.MM.N` / semver (ATLAS convention).
- **Verdict (eval)** — `Pass / Fail / Inconclusive` from a paired bootstrap (k=3–5).
- **Score** — Youden's J (`TPR − FPR`); a single deterministic keep-or-revert number.

### The closed learning loop (outer loop control flow)

Two tiers, deliberately separated: **cheap CAPTURE** (deterministic, ~0 LLM cost) vs.
**gated COMMIT** (semantic + human-reviewed).

```
trace (hooks → JSONL) ─► reflect (textual rationale: why missed / why FP)
   ─► pre-gate filter (seen ≥3 sessions, same fix, 1–2 sentences, system unchanged)
   ─► self-critique (generalizable? overfit? "technically-true-but-misleading"?)
   ─► propose text diff  (default PATCH over CREATE; dedup-before-create)
   ─► GATE: run on frozen EvalCorpus; keep only if strictly improved & non-regressing
   ─► PR  (branch, never default; never autocommit; human Apply/Edit/Skip)
```

`sec-learn` runs this reflectively on recent traces; `sec-kb-refresh` runs the *input
arm* (poll Feeds → extract NEW Techniques → draft dated entries → same gate → PR).

### Invariants

- **No retraining — text edits only.** Every learning is a signed, inspectable git diff
  on the Context surface; the Model surface is frozen. (ADR-001, ADR-004)
- **Mandatory provenance.** Each active AI-threat entry has `source`+`url`+`retrieved`;
  unsourced claims are refused at write time.
- **Two-tier decay separation.** Refresh routines never edit the stable checklists.
- **Frozen, agent-unwritable corpus.** The agent proposes KB changes but **cannot edit
  the EvalCorpus or the gate script** — separate identity; this is the anti-gaming split.
- **Asymmetric keep-or-revert.** Hard-revert on >2pp recall loss, >1pp FPR gain, or any
  single locked case regressing; keep only if J non-inferior *and* improves or adds new
  sink coverage. The gate is a guardrail, not a benchmark maximizer.
- **Human-in-the-loop, never auto-merge** (v1). Graduated autonomy is earned per-step and
  only for the lowest-risk class (feed-sourced PATCH-only, fast-tier, green-gated);
  identity/role prose and CLAUDE.md/rules stay human-gated indefinitely.
- **No time-bombs.** Avoid "before August 2025" prose; age out via `archive/` + a
  collapsible *Old patterns* block.
- **Size caps mechanical, not by trust.** `description`+`when_to_use` ≤ 1,536 chars;
  `SKILL.md` < 500 lines; `reference/` one level deep (ADR-005).
- **Second ratchet.** Every newly-confirmed true Finding (with labels) is promoted *into*
  the frozen corpus so the bar keeps rising and the KB can't drift.

---

## 5. Context: TOOLING (the capability layer)

> Responsibility: let Review depend on **Capabilities, never brands** — discover installed
> Tools at runtime, map them to Capabilities, and **degrade to the Floor** when none
> exist. The registry is itself part of the self-improving loop (ADR-015).

### Aggregates

- **ToolRegistry** *(aggregate root)* — the capability→Tool map. Its entries are
  *illustrative defaults, not requirements*. Curated like the KB: `sec-learn` /
  `sec-kb-refresh` add newly-discovered Tools as dated, reviewable diffs. Owns a
  change-log; the concept owns this file, not any vendor.
- **DegradationLadder** *(policy aggregate)* — per Capability, the ordered fallback:
  native low-FP gate → general scanner → **Floor (Read/Grep/Glob, confidence capped)**.
  Encodes "never block on a missing Tool."

### Entities

- **Capability** — durable interface: `SAST · SCA · secrets · IaC · AI-redteam` (open set;
  new Capabilities may be added). The thing Review actually requests.
- **Tool** — a discovered implementation: `tool · cost · langs/ecosystems · invoke ·
  notes · added(date,source)`. Pinned to a known-good version (ADR-006); never
  auto-installed from unpinned sources.

### Value objects

- **Floor** — the constant zero-install implementation of every Capability.
- **DetectionResult** — `{installed Tools, Capability coverage, tools_unavailable[]}`.
- **ToolAssisted** — boolean stamped on each Finding; `false` caps confidence and feeds
  the report's honesty fields.

### Invariants

- **Depend on the interface, not the vendor.** Any named Tool (an SAST engine, an SCA
  scanner, a secrets scanner, …) is swappable behind its Capability.
- **The Floor always works.** Built-in Read/Grep/Glob scoped to cwd produces value with
  zero external Tools; it is the guaranteed bottom of every ladder.
- **Never block; degrade honestly.** A missing Tool → fall back, mark
  `tool_assisted:false`, cap confidence, record `tools_unavailable` (ADR-003).
- **Pin & verify whatever IS used.** Known-good version, signature/digest where relevant;
  no single Tool is complete (combine Capabilities for coverage).
- **The registry self-updates (design intent — proposer not yet built).** Tooling knowledge
  is designed to evolve through the same outer-loop lane as attack-technique knowledge —
  *what to look with* learns like *what to look for*. Today the gated write-lane exists but
  the registry-row proposer does not; and registry/watchlist DATA edits need a deterministic
  source+schema gate (Gate-2), not the eval gate
  (`docs/research/20260609_supply_chain_loop_leverage.md` §3 ADMIT + §4.1; wh-hxt.4 / wh-562).

---

## 6. Context: TEAM

> Responsibility: place the Review context into a side-project workflow
> (TL / QA / Dev / white-hacker on a ticket). The agent's *identity* is defined once and
> carried into three roles without forking it.

### Aggregates

- **Engagement** *(aggregate root)* — one authorized ticket/target with its posture
  preamble (authorized targets only, read-only-by-default, responsible disclosure,
  review the developer's *own* working tree/diff). The consistency boundary for "who may
  be reviewed and how results are routed."
- **AgentIdentity** *(aggregate root)* — the single `white-hacker` definition (persona,
  posture, stage dispatch, tool allowlist). One definition, three carriers; identity
  comes from the `name` field, not the path (ADR-014).

### Entities

- **Role / Teammate** — TL, QA, Dev, white-hacker. white-hacker is the security carrier
  of AgentIdentity.
- **Handoff** — the review-phase invocation that hands a diff to white-hacker and receives
  back *only* the `TRIAGE.json` summary + the `SECURITY-REPORT.md` path (never raw
  discovery).

### Value objects

- **ExecutionMode** — `sequential/subagent` (default; lower token cost, summary-only
  return) | `agent-team` (opt-in; adversarial cross-check, non-overlapping file ownership).
- **Mailbox** — the SendMessage channel (team mode only); findings route to the **tech
  lead**, not the dev. On WAIT states, exit cleanly.

### Invariants

- **One identity, three carriers** — `/security-review` command, delegated subagent, and
  team teammate share the same definition (ADR-009/014). Operational detail belongs in the
  *spawn prompt* (subagent `skills`/`mcpServers` frontmatter does not carry to teammate mode).
- **Summary-only return.** Downstream sees triaged results, not raw discovery; a beads P1
  ticket is created **only after triage**.
- **white-hacker proposes; it does not push.** Capability removed, not merely instructed.
- **Team mode degrades safely.** If `SendMessage` won't load, reply that it's unavailable
  and exit rather than mis-routing.

---

## 7. Context map (integration = the Artifact chain)

The contexts integrate almost entirely through **plain-text Artifacts on disk** — the
chain is both the data-flow and the resumability/CI-gating mechanism. Knowledge and
Tooling feed *into* Review at read-time; Review feeds *back into* Knowledge only as
recorded traces (the dotted, deferred edge — the outer loop).

```
                                ┌──────────────────────────────────────────────┐
                                │                 TEAM context                  │
                                │  Engagement · AgentIdentity (1 def, 3 carriers)│
                                │  sequential/subagent (default) | agent-team    │
                                └───────────────┬───────────────────────────────┘
                                                │ Handoff (diff in →
                                                │ TRIAGE summary + report path out)
                                                ▼
   ┌───────────────────────────  REVIEW context (INNER LOOP)  ───────────────────────────┐
   │                                                                                      │
   │  threat-model ─► THREAT_MODEL.md                                                      │
   │       │                                                                               │
   │  detect ──────► SCAN-PLAN.json ◄──────── ScanPlan needs Capabilities ───────┐         │
   │       │                                                                      │         │
   │       ├─ secrets-scan ─┐                                                     │         │
   │       ├─ deps-scan ────┤                                                     │         │
   │  discovery (RECALL) ───┼─► VULN-FINDINGS.json                               (reads)    │
   │       └─ ai-llm-review ─┘        ▲                                            │         │
   │             (reads KB) ──────────┼──────── KnowledgeBaseEntry / Technique ───┼──┐      │
   │       │                          │                                           │  │      │
   │  triage (PRECISION, fresh ctx) ─► TRIAGE.json ◄── Exclusions ────────────────┼──┤      │
   │       │   adversarial N-of-N · dedup · precondition severity                 │  │      │
   │  report ─────► SECURITY-REPORT.md (+ CI JSON gate: counts.high==0)           │  │      │
   │       │                                                                      │  │      │
   │  patch (opt-in) ─► PATCHES/  (re-attack; writes ONLY here)                   │  │      │
   │                                                                              │  │      │
   └──────────────────────────────────┬───────────────────────────────────────────┼──┼────┘
                                       │ trace (hooks → JSONL)                     │  │
                                       ▼  (deferred — the OUTER LOOP)              │  │
   ┌──────────────  KNOWLEDGE context (OUTER LOOP)  ─────────────┐    ┌────────────┴──┴──────┐
   │  KnowledgeBase (fast tier: AI-threats / stable: checklists) │    │  TOOLING context     │
   │  EvalCorpus (frozen, agent-unwritable)  ExclusionRuleSet    │    │  Capability ↔ Tool   │
   │                                                             │    │  Floor · Degradation │
   │  Feeds ─► sec-kb-refresh ─┐                                 │    │  ToolRegistry        │
   │  traces ─► sec-learn ─────┼─► reflect ─► self-critique ─►   │    │                      │
   │                            │   GATE (Youden's J,            │    │  registry entries    │
   │                            │   keep-or-revert) ─► PR        │◄───┤  curated by the same │
   │  serves entries/exclusions │   (human Apply/Edit/Skip)      │    │  outer-loop PR gate  │
   │  to REVIEW  ───────────────┘                                │    │                      │
   └─────────────────────────────────────────────────────────────┘    └──────────────────────┘
```

Relationship types (DDD strategic patterns):

- **Review ⟶ Knowledge / Review ⟶ Tooling: Customer–Supplier.** Review is the customer;
  Knowledge supplies entries/exclusions, Tooling supplies capability mappings. The supply
  is *published-language* JSON/markdown (the Artifacts), so Review never couples to
  internal KB or registry structure.
- **Knowledge ⟵ Review: traces only (deferred).** Knowledge consumes Review's *recorded*
  traces, never its live context — this independence is what makes the gate trustworthy.
- **Team ⟶ Review: Conformist + open-host.** Team carries the one AgentIdentity and
  receives the published summary contract (`TRIAGE.json` + report path).
- **EvalCorpus: a separately-owned upstream.** Frozen ground truth that the agent may read
  but not write — an intentional anti-corruption boundary against self-gaming.

---

## 8. Domain → concrete `.claude/` files

The model maps directly onto the on-disk scaffolding. (Empty/planned files are noted; the
file's behaviour, not this table, is the source of truth where they differ.)

| Domain object / context | Concrete file(s) |
|---|---|
| **AgentIdentity** (Team) | `plugins/white-hacker/agents/white-hacker.md` |
| **Engagement / Handoff** (Team) | `plugins/white-hacker/commands/security-review.md`; team-mode spawn prompts + `SendMessage` |
| **ReviewSession orchestration** (Review) | `plugins/white-hacker/agents/white-hacker.md` (stage dispatch) |
| **ThreatModel** → `THREAT_MODEL.md` | `plugins/white-hacker/skills/sec-threat-model/` |
| **ScanPlan** → `SCAN-PLAN.json` | `plugins/white-hacker/skills/sec-detect/` |
| **Discovery (RECALL)** → `VULN-FINDINGS.json` | `plugins/white-hacker/skills/sec-vuln-scan/`, `secrets-scan/`, `deps-scan/`, `ai-llm-review/` |
| **Verification + triage (PRECISION)** → `TRIAGE.json` | `plugins/white-hacker/skills/sec-triage/` |
| **Report** → `SECURITY-REPORT.md` + JSON | `plugins/white-hacker/skills/sec-report/` |
| **PatchProposal** → `PATCHES/` | `plugins/white-hacker/skills/sec-patch/` |
| **KnowledgeBase / KnowledgeBaseEntry / Technique** | `plugins/white-hacker/skills/ai-attack-kb/` (+ `reference/` entries) |
| **sec-learn** (reflect on traces → PR) | `plugins/white-hacker/skills/sec-learn/` |
| **sec-kb-refresh** (Feeds → PR) | `plugins/white-hacker/skills/sec-kb-refresh/` |
| **Feed list** (Knowledge input arm) | `docs/research/si-07-threat-feeds.md` (16 feeds) |
| **ToolRegistry / Capability / Tool / Floor** (Tooling) | `plugins/white-hacker/skills/_shared/reference/tool-registry.md` |
| **ExclusionRuleSet** (Review consumes, Knowledge curates) | `plugins/white-hacker/skills/_shared/reference/exclusion-rules.md` |
| **Severity** value object & rubric | `plugins/white-hacker/skills/_shared/reference/severity-rubric.md` |
| **Finding** schema (the published contract) | `plugins/white-hacker/skills/_shared/reference/finding-schema.json` |
| **Vuln-class taxonomy / appendices** (Review reads) | `plugins/white-hacker/skills/_shared/reference/{core-checklist,api,ai-llm,infra,lang-go,lang-python,lang-typescript,lang-java}.md` |
| **EvalCorpus / keep-or-revert gate** (Knowledge) | BUILT — `evals/` (corpus, `score.py`, `keep_or_revert.py`; the gate is fail-closed — no `gate-verdict.json` ⇒ KB writes blocked) |
| **CAPTURE hooks + PreToolUse guardrails** (Harness) | guardrails BUILT+WIRED — `plugins/white-hacker/hooks/` (`hooks.json`); capture scripts built, registration pending human-auth (T-8.3) ⇒ `evals/traces/` is empty today |
| **Settings / permissions / size-cap lint** (Harness) | `.claude/settings.local.json`; `lint_skill.py` + `validate_kb.py` BUILT — `plugins/white-hacker/skills/ai-attack-kb/scripts/` (ADR-005) |
| **Conventions & the key concept** | `.claude/CLAUDE.md` (dev-only); decisions in `docs/ARD.md`; build order in `docs/plan/PLAN.md` |

---

## 9. Cross-cutting invariants (true in every context)

- **Plain-text artifacts behind open interfaces.** Every stage chains via on-disk files;
  every learning is a git diff. Nothing essential lives in opaque state or weights.
- **The inner loop consumes the KB; the outer loop edits it.** Never the reverse: a
  ReviewSession does not mutate the KB; only the gated outer-loop PR does.
- **Treat all input as untrusted; the agent is an injection target.** Code, comments,
  tickets, model/tool/RAG output, *and KB/registry text* can carry prompt injection.
- **Capability-removal over instruction.** Structural safety (no push, scoped writes,
  context starvation, frozen corpus) beats prose a prompt-injection could override.
- **Honest degradation everywhere.** Missing Tools, undefined threat models, and absent
  PoCs are *recorded and confidence-capped*, never silently ignored — and never a reason
  to block: the Floor alone produces value.
- **Tools are swappable; the concept is not.** Any brand named anywhere in the system is
  an illustrative example behind a Capability, and the registry is designed to self-update
  through the same loop that updates attack knowledge (proposer arm: design intent —
  loop-leverage audit G5, wh-hxt.4).
