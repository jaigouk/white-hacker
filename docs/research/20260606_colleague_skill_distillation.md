# Research: COLLEAGUE.SKILL — trace-to-skill distillation (paper + code), distilled for KMS

> **Imported into white-hacker `docs/research/` on 2026-06-08** as external prior-art from the
> sibling **KMS** project. White-hacker borrows only the LIGHT, file-based ideas (append-only +
> surface-conflicts merge, versioned correction/rollback, section-keyed patch) — see the
> distillation in [`si-10-living-kb-lightweight.md`](si-10-living-kb-lightweight.md). Internal
> `../ADR/…` and `../DDD.md` links point at KMS files and do **not** resolve in this repo.

**Date:** 2026-06-06
**Author:** Jaigouk Kim
**Spike Ticket:** KMS-fil
**Status:** Final

## Summary

**COLLEAGUE.SKILL** (arXiv:2605.31264v1, Shanghai AI Lab, May 2026) and its reference implementation
[`titanwings/colleague-skill@dot-skill`](https://github.com/titanwings/colleague-skill/tree/dot-skill)
reframe "simulating a person" as **person-grounded trace-to-skill distillation**: convert selected,
heterogeneous human traces (docs, chats, reviews, emails, transcripts) into **bounded, inspectable,
versioned, correctable skill packages** that load into existing agent hosts via the
[Agent Skills](https://agentskills.io) `SKILL.md` standard. The authors are explicit that the
contribution is the **artifact format and lifecycle**, not behavioral fidelity — they make *no* claim
that a generated skill faithfully reproduces a person or improves downstream work, and there is **no
evaluation**.

**The essence in one sentence:** *treat a learned agent capability as an editable software artifact
with an explicit evidence trail and a versioned correction/rollback lifecycle — inspect → correct →
patch → version → rollback → govern — rather than as a hidden prompt or opaque memory.*

That essence is **direct prior art for KMS**: it is the same shape as the §1.11 keep-or-revert ratchet
([ADR-014](../ADR/ADR-014-agent-self-improvement.md)) and the append-only / surface-conflicts conflict
model ([ADR-010](../ADR/ADR-010-conflict-resolution.md)). But the system is **single-user,
permission-blind, filesystem-local, and persona-centric** — the opposite of KMS's multi-tenant,
fail-closed, GDPR-safe, *org-knowledge* (not *person*) platform. So the value to KMS is at the
**design-pattern / prompt-template level**, never as a runtime dependency. License is **MIT** (clean,
KMS-compatible), so specific helpers *could* be lifted — but they are small enough to reimplement to
KMS conventions.

## Research Question

Understand the essence of the paper + code and map the transferable ideas onto KMS's
composable-agent / self-improving-agent design (spike KMS-fil, Q1–Q5).

---

## Part 1 — The paper's essence

### 1.1 The reframing (Q1)

Actionable expertise "is usually embedded in heterogeneous traces rather than written as clean
instructions"; when people leave, their "review standards, incident heuristics, and communication
norms often disappear with them." Rather than unrestricted person simulation, the system distils
**selected evidence** into **bounded, editable packages**. The contribution is explicitly framed as
**artifact engineering**, and all claims are **artifact-level only** (portability/inspectability/etc.),
*not* fidelity.

### 1.2 The five requirements (Q1)

| Requirement | Definition (paraphrased from the paper) | Why it matters |
|---|---|---|
| **Portable** | Skills-compatible agents load the package through ordinary skill mechanisms. | No bespoke runtime; rides the Agent Skills standard so the artifact works across hosts. |
| **Inspectable** | Users read extracted rules, examples, limitations, metadata *before* use. | Human-readable Markdown/JSON, not an opaque prompt — a precondition for review and trust. |
| **Composable** | Full, work-only, and persona-only entrypoints invoked separately. | Take the *capability* without the *style* — separates the risk/utility tradeoff. |
| **Correctable** | New evidence/feedback updates the package while **preserving prior state**. | An evolution loop with version history, not destructive overwrite. |
| **Governable** | Metadata, source boundaries, disclaimers support deletion, sharing, safety review. | Consent, deletion, provenance, source-boundary labels become first-order artifact properties. |

### 1.3 The dual-track artifact (Q2)

Every package splits into two tracks (consistent across all presets):

- **Capability track → `work.md`** — responsibilities, workflows, technical standards, review
  criteria, decision heuristics, lessons learned. *Reusable expert judgment and procedure.*
- **Behavior track → `persona.md`** — bounded behavior constraints, expression preferences,
  interaction rules, and a correction log. *Communication style/boundaries, not facts.*

The **writer emits seven files** (schema **v3**): `SKILL.md` (combined invokable skill — frontmatter
`name`/`description`/`user-invocable: true`, then **Part A = capability**, **Part B = behavior**, plus
"operating rules": *start with Part B to set attitude → execute with Part A → keep Part B tone;
Layer-0 rules always win*), the editable `work.md` / `persona.md`, the single-track entrypoints
`work_skill.md` / `persona_skill.md`, and `manifest.json` (entrypoints, compatible runtimes,
slash-commands) + `meta.json` (schema, provenance, lifecycle version, correction count, compatibility).

### 1.4 Multi-entrypoint / progressive disclosure (Q2)

Built on Agent Skills **progressive disclosure** (agents see metadata first, load detail on invoke):

- **Full** (`SKILL.md`) — both tracks; default.
- **Capability-only** (`work_skill.md`) — expertise without persona style; "when style transfer is
  inappropriate."
- **Behavior-only** (`persona_skill.md`) — interaction rules "as style reference only."

### 1.5 Generation & evolution workflow (Q3)

`collect → normalize → dual extract → render → install → correct → patch+rollback → (optional) gallery`

1. **Collect/normalize** heterogeneous sources into local knowledge dirs: work traces (design docs,
   code-review comments, chat decisions, incident notes), comms (chat/email), media (PDF/screenshot/
   audio→transcribe), and platform exports (**Feishu, DingTalk, Slack, WeChat SQLite**).
2. **Dual extraction** via two preset-specialized prompts (capability vs behavior).
3. **Render** to `work.md`/`persona.md` → combined `SKILL.md` + two entrypoints + manifest/meta.
4. **Install** into four named hosts (Claude Code, OpenClaw, Codex, Hermes) as a `SKILL.md` folder.
5. **Correction loop** (the most KMS-relevant mechanic) — NL feedback ("he would not say that"):
   - **Capability correction** → a **Markdown patch** against `work.md`. Merge rule (verbatim):
     *"Patches with matching level-2 headings replace the corresponding section; unmatched sections
     are appended."*
   - **Behavior correction** → a normalized **`{scene, wrong, correct}`** record appended to
     `persona.md`.
   - The writer **archives the current version, applies the patch, increments the lifecycle version,
     and regenerates all derived artifacts.** Version-manager verbs: `list`, `back up`, `roll back`,
     `clean`. `meta.json` tracks `lifecycle version` + `correction count`.
6. **Gallery** distribution is **opt-in**: submitter attestation, review, takedown, source-boundary
   labels, visible disclaimers.

### 1.6 Three presets (Q4) — same artifact, different consent/boundaries

- **Colleague** (enterprise) — distil a departing teammate's *work judgment*; enterprise consent
  assumption; standard workplace collectors.
- **Celebrity / public figure** — distil *public mental models from first-person evidence with
  explicit source boundaries*; must "not present itself as the actual person"; adds a **research
  pipeline** with a source hierarchy, evidence weighting, and a "**downgrade confidence when evidence
  is thin**" protocol.
- **Relationship** (private) — represent private interaction patterns as **local, editable, deletable
  state**; strongest consent bar; makes **deletion, correction, local ownership, non-public defaults
  first-order**.

### 1.7 Limitations & governance (Q1)

No fidelity claim; correction can **encode editor bias** or make contested traces "appear more settled
than they are"; quality depends on source/extraction/model/human-review. Governance = **tiered
consent** by preset, **identity boundaries** (never assert faithful modeling), **deletion/redaction
under user control**, **provenance via metadata**, **opt-in gallery**. **No formal evaluation** — only
deployment counters (repo stars, gallery counts), explicitly disclaimed as distribution surface, not
quality.

---

## Part 2 — The code's essence

### 2.1 License (load-bearing for KMS)

**MIT** — `Copyright (c) 2026 titanwings`, confirmed in `LICENSE`, README, and `CITATION.cff`. Plain
MIT, no AGPL/BSL/SSPL nuance → **permissive and compatible with KMS's Apache-2.0 / MIT / BSD policy**
(attribution preserved on any reuse).

### 2.2 Architecturally, it is a *prompt library*, not a service

100% Python + Markdown + one Bash script; **no `pyproject.toml`/`package.json`**, no framework, no DB,
no network service, **no ports/adapters, no auth**. The **prompts ARE the engine** — `SKILL.md`
(1465 lines) orchestrates the host LLM through Markdown prompts; the Python `tools/` are stateless
CLIs the agent shells out to. State is the filesystem (skill folders + `knowledge/` + `versions/`).
Only hard dependency: `requests`; everything else (`playwright`, `slack-sdk`, `pypinyin`,
`python-docx`, Whisper, `yt-dlp`) is optional per-collector.

### 2.3 On-disk schema — the concrete IP

The committed `colleague` examples (`skills/colleague/example_*`) show the legacy 3-file shape; the
writer (`tools/skill_writer.py` + `tools/skill_schema.py`) upgrades to the **v3** 7-file set.

- **`persona.md` — a 6-layer persona** (the core IP): `Layer 0 Core personality` (highest priority,
  concrete *executable* rules, not adjectives) · `Layer 1 Identity` · `Layer 2 Expression style`
  (catchphrases + worked dialogue) · `Layer 3 Decisions` (priority ordering, how they say "no") ·
  `Layer 4 Interpersonal` (toward superiors/juniors/peers/under-pressure) · `Layer 5 Boundaries &
  landmines` · `Correction log` · `Overall behavioral principles`.
- **`work.md`**: `Scope/responsibilities` · `Tech standards` (stack/style/naming/interface/CR focus) ·
  `Workflows` · `Output style` · `Experience knowledge base`.
- **`meta.json` v3** (`schema_version:"3"`, `enrich_skill_meta()`): nested `lifecycle{status,…,version}`,
  `generation{engine,…,corrections_count}`, `classification{gallery_category,tags,language}`,
  `source_context{domain,relationship_to_user,is_real_person,is_public_figure,is_fictional}`,
  `engine{…,merge_strategy,quality_profile,knowledge_dirs}`, `artifacts{…}`, `compat{…}`.
- **`manifest.json`** (`build_manifest()`): `entrypoints{default,work,persona}`, `capabilities`,
  `install{compatible_runtimes:[claude-code,openclaw,hermes,codex], min_schema_version, slash_commands}`.

### 2.4 Writer / evolution mechanics (deterministic, no LLM)

- `merge_markdown_patch()` — replaces `##`-keyed sections by heading, else appends (**append-only**).
- `apply_correction()` — appends `- [{scene}] should not {wrong}; should {correct}` under
  `## Correction Log`.
- `version_manager.py` — copies the primary artifacts into `versions/<name>/`, keeps `MAX_VERSIONS=10`,
  supports rollback.

### 2.5 Prompts as the engine — and the celebrity research pipeline

`prompts/` holds the per-family instruction sets; the shared `merger.md` classifies new info as
work-vs-persona and is **append-only, instructed to *surface conflicts instead of overwriting***. The
**celebrity** family adds the richest ideas: a **source hierarchy with per-evidence source weight
(1 user-local → 7 secondhand)**, a **source blacklist** (content farms, AI-generated bios,
Wikipedia-as-primary), a **Cold-Figure Protocol** (<10 sources → limit to 2–3 mental models, mark
"limited information"), explicit numeric **quality gates** (`audit.md`/`synthesis.md`/`validation.md`
PASS/FAIL on primary-source ratio, contradiction counts, blind voice test), and a **copyright-safety
rule: never store full transcripts/subtitles — paraphrased notes + metadata only.**

### 2.6 Collectors — permission-blind by design

`feishu/dingtalk/slack` auto-collectors and `email_parser` dump a person's messages/docs into
`knowledge/{slug}/` as flat text. **No ACLs, no tenant, no principal mapping** — single-user, local.

---

## KMS-relevance mapping (the core deliverable) — adopt / adapt / reject

| # | COLLEAGUE.SKILL concept | KMS touchpoint (`file:section`) | Verdict | Rationale |
|---|---|---|---|---|
| 1 | **Two-layer artifact** (`work.md` capability + `persona.md` behavior → `SKILL.md`) | AgentConfig assets `system_prompt_uri` / `tool_descriptions` / `skill_refs` ([DDD.md §6 AgentConfig](../DDD.md)); `SKILL.md ≤ 15 KB` ([ADR-014](../ADR/ADR-014-agent-self-improvement.md)) | **Adapt** | Keep the **capability track** (≈ KMS agent's prompt + tool descriptions + skill). KMS agents are org-curation agents (RegWatch, PracticeCurator), **not personas** → **drop the behavior/persona track**: identity replication is out of scope and a governance risk. |
| 2 | **NL-correction → versioned patch → rollback** loop | Ratchet keep-or-revert; "Rollback = reactivate prior config version" ([ADR-014](../ADR/ADR-014-agent-self-improvement.md)); `AgentConfig.revert()` ([DDD.md §6](../DDD.md)) | **Adapt** | Same *shape*, different *trigger*. COLLEAGUE.SKILL applies a single human NL edit **immediately**; KMS must **not** — that violates "AI never writes to `main`". KMS gates it: ≥30 outcomes, eval gates, ships only as a **ChangeProposal** + human merge. Reusable: rollback-as-prior-version + correction-as-append-only-record. |
| 3 | **Level-2-heading patch merge** (replace matching `##`, append unmatched) — `merge_markdown_patch()` | Reflective optimizer emitting `SKILL.md`/prompt mutations ([ADR-014 ratchet step 2](../ADR/ADR-014-agent-self-improvement.md)); ChangeProposal merge resolution ([DDD.md ChangeProposal](../DDD.md)) | **Adopt** (as a deterministic helper) | A clean, **deterministic** section-keyed merge primitive — exactly what the optimizer needs to apply text mutations, and deterministic so it stays out of the LLM path (Rule 5). ~30 lines; reimplement to KMS style rather than vendoring. |
| 4 | **Append-only correction record** `{scene, wrong, correct}` | `agent_outcomes(verdict, edit_distance)` ([DDD.md AgentConfig/AgentOutcome](../DDD.md)) | **Adopt** | A normalized, inspectable "what was wrong + the fix" record — the ground-truth the ratchet mines. The `{scene,wrong,correct}` triple is a good structured shape to layer onto `agent_outcomes`. |
| 5 | `merger.md`: **append-only, surface conflicts, never overwrite** | Tier-2 ranked claims, "deprecated claims are **kept, not deleted**" ([ADR-010](../ADR/ADR-010-conflict-resolution.md)); CLAUDE.md Rule 7 | **Adopt** (corroboration) | **Independent convergence** on KMS's central principle. No change needed — cite as external prior-art confirming ADR-010 and the "surface conflicts, don't average" working rule. |
| 6 | **Schema-versioned `meta.json` (v3) + `manifest.json`** (entrypoints, compatible_runtimes, slash_commands, provenance, correction_count) | Frozen/drift-gated **contract files** (manifest = install contract; §6.6 MCP/n8n surface); `SKILL.md` standard ([ADR-013](../ADR/ADR-013-implementation-language-python.md)/[-014](../ADR/ADR-014-agent-self-improvement.md)) | **Adapt** | Good model for **AgentConfig metadata + a drift-gated manifest** with provenance/lifecycle/correction_count. But **define KMS's own keys** — the paper exposes no formal schema and the repo's keys are persona-centric (`is_real_person`, `gallery_category`). |
| 7 | **Multi-entrypoint** (full / capability-only / persona-only) via progressive disclosure | `InvokeSkill`; `SKILL.md` progressive disclosure ([ADR-014](../ADR/ADR-014-agent-self-improvement.md), agentskills.io) | **Adapt** | The **capability-only** entrypoint is genuinely useful (expose expertise without tenant-specific tone). The **persona-only** mode has no KMS analog → drop. |
| 8 | **Source collectors** (Feishu/DingTalk/Slack/email) dumping to `knowledge/` | Connector-sync **capability contract** + PrincipalMapping/ACL-mirror, **fail-closed** ([ADR-005](../ADR/ADR-005-connector-sync-capability-contract.md)); Ingestion invariants ([DDD.md §7 Ingestion](../DDD.md)) | **Reject** (anti-pattern) | Sharpest divergence. The collectors are **permission-blind bulk dumps** (no ACL, no tenant). KMS ingestion **must** mirror source ACLs fail-closed, partition by `tenant_id`, and never mirror unmapped principals. Do **not** reuse — they are an anti-pattern for a multi-tenant GDPR platform. |
| 9 | **Celebrity research pipeline**: source-weight ladder (1–7), blacklist, **cold-figure → downgrade confidence**, **never store full transcripts (notes + metadata only)**, numeric quality gates | Layer-authority weights L1–L4 = 1.00/0.85/0.70/0.50 (§6.7); §1.4 staleness/contradiction classifiers; freshness decay ([ADR-006](../ADR/ADR-006-knowledge-decay-pipeline.md)); eval gates ([ADR-019](../ADR/ADR-019-evaluation-framework.md)); GDPR data-minimization | **Adapt** (strong ideas) | Source-weight ladder ≈ KMS layer authority; "downgrade confidence when evidence thin" ≈ staleness/freshness scoring; **"paraphrased notes + metadata, never the full copyrighted/PII source"** is a clean **data-minimization** pattern worth an ingestion note; numeric PASS/FAIL gates ≈ ADR-019. |
| 10 | **Governance surface**: opt-in publish, provenance, source-boundary labels, deletion-first-order, disclaimers | Tenant isolation ([ADR-004](../ADR/ADR-004-tenant-isolation-strategy.md)); GDPR erasure cascade (`EraseUser`/`MemoryErased`, [DDD.md §7](../DDD.md)); disputed-badge visible to retrieval ([ADR-010](../ADR/ADR-010-conflict-resolution.md)) | **Adapt** (principle only) | Aligned in spirit (deletion/provenance/consent as first-order) but **far weaker** — single-user, no RLS/DEK/OpenFGA. Adopt the *principle* (metadata-carried provenance + deletion); KMS already enforces it far more strongly. |

### What NOT to copy (the divergences that matter)

1. **Persona / identity replication** is the *whole point* of COLLEAGUE.SKILL and is **out of scope**
   for KMS — KMS distils **org knowledge**, not **people**. The behavior track, the 6-layer persona,
   and the relationship/celebrity families have no KMS home and carry consent/impersonation risk.
2. **Permission-blind, single-user, filesystem-local** is the exact inverse of KMS's multi-tenant,
   RLS + per-tenant-DEK + OpenFGA-fail-closed model. The collectors are an anti-pattern here.
3. **Immediate-apply corrections** violate the KMS invariant **"AI never writes content to `main`"**
   ([ADR-010](../ADR/ADR-010-conflict-resolution.md), [DDD.md](../DDD.md)). KMS corrections must flow
   through a gated ChangeProposal with human merge authority.
4. **LLM-prompt-driven orchestration with no deterministic code path** — KMS uses LLMs only at the
   designed judgment points (Rule 5); merge, routing, retries, and validation stay deterministic.

## Recommendation

Use COLLEAGUE.SKILL as **prior art and a pattern/prompt source, never a runtime dependency.** It
**validates** two existing KMS decisions by independent convergence (append-only + surface-conflicts →
[ADR-010](../ADR/ADR-010-conflict-resolution.md); editable-text + versioned correction/rollback →
[ADR-014](../ADR/ADR-014-agent-self-improvement.md)), so **no ADR needs to change**. Concretely worth
carrying into the implementation phase:

- **(a)** a deterministic **section-keyed patch-merge** helper for the §1.11 optimizer's `SKILL.md`/
  prompt mutations (map #3) — reimplement to KMS conventions;
- **(b)** an append-only **`{scene, wrong, correct}`** correction record layered onto `agent_outcomes`
  (map #4);
- **(c)** an ingestion **data-minimization** pattern — store paraphrased notes + provenance metadata,
  not full copyrighted/PII source — worth a note in [ADR-006](../ADR/ADR-006-knowledge-decay-pipeline.md) /
  the ingestion design (map #9);
- **(d)** corroboration to cite in [ADR-010](../ADR/ADR-010-conflict-resolution.md)/[ADR-014](../ADR/ADR-014-agent-self-improvement.md)
  References as external prior art.

MIT licensing means (a)/(b) *could* be lifted verbatim, but both are <50 lines and reimplementing
keeps ruff/typing/conventions clean (Rule 11).

## References

- [COLLEAGUE.SKILL: Automated AI Skill Generation via Expert Knowledge Distillation](https://arxiv.org/html/2605.31264v1) — arXiv:2605.31264v1, Shanghai AI Lab, May 2026 (the paper).
- [`titanwings/colleague-skill@dot-skill`](https://github.com/titanwings/colleague-skill/tree/dot-skill) — reference implementation, **MIT**.
- [Agent Skills open standard](https://agentskills.io) — `SKILL.md`, progressive disclosure.
- KMS internal: [ADR-014](../ADR/ADR-014-agent-self-improvement.md) (ratchet), [ADR-010](../ADR/ADR-010-conflict-resolution.md) (conflict resolution), [ADR-005](../ADR/ADR-005-connector-sync-capability-contract.md) (connector sync), [ADR-006](../ADR/ADR-006-knowledge-decay-pipeline.md) (decay), [ADR-019](../ADR/ADR-019-evaluation-framework.md) (eval), [DDD.md](../DDD.md) (AgentConfig, ChangeProposal, ingestion invariants).
- Related internal reference: [20260602_Self-Improving-Agent-Architecture-Reference.md](20260602_Self-Improving-Agent-Architecture-Reference.md) (basis for §1.11 / ADR-014).

## Follow-up Tasks

> Implementation tickets are deferred — KMS is in the docs-refinement phase (no epics/tickets yet).
> These are **noted for the implementation phase**, not created now.

- [ ] (impl phase) Add a deterministic section-keyed patch-merge helper to the §1.11 optimizer (map #3).
- [ ] (impl phase) Layer a `{scene, wrong, correct}` correction record onto `agent_outcomes` (map #4).
- [ ] (doc, optional) Add a "source data-minimization" note to [ADR-006](../ADR/ADR-006-knowledge-decay-pipeline.md) / ingestion (map #9).
- [ ] (doc, optional) Cite COLLEAGUE.SKILL as external prior art in ADR-010 / ADR-014 References.

## Notes / Open Questions

- COLLEAGUE.SKILL's correction-and-rollback is **the same idea** as the §1.11 keep-or-revert ratchet,
  under a different name and without gating — confirming the KMS model rather than competing with it.
- The repo distils **people**; KMS distils **org knowledge**. The mechanics that survive that
  reframing are the *capability* track, the *patch/version/rollback* lifecycle, the *append-only +
  surface-conflicts* merge, and the *evidence-weight + data-minimization* ideas. Everything
  persona-specific (the 6-layer persona, relationship/celebrity families, the collectors) is dropped.
