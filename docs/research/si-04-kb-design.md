# Self-Improvement Research — si:kb-design

> Source: workflow `self-improving-white-hacker-research` (w3b87zsau), agent `si:kb-design`

## Designing a Living Security Knowledge Base for a Claude Code Agent (2026)

The goal is a knowledge base (KB) that a white-hat Claude Code agent reads through a skill's `references/` directory, that refreshes on a cadence, carries provenance, and resists both **bloat** (too many tokens / stale entries) and **drift** (entries that no longer match reality or contradict each other). The dominant 2026 patterns to borrow are **detection-as-code (DaC)** — treat detections like source code with Git, PRs, CI tests, and lifecycle/retirement ([Splunk](https://www.splunk.com/en_us/blog/learn/detection-as-code.html), [Kraven](https://kravensecurity.com/detection-engineering-lifecycle/)) — and the **MITRE ATLAS living-KB model**, which moved to a *monthly release cadence*, uses typed IDs, separates **content version (`YYYY.MM.N`) from format/schema version (semver)**, and groups entity types under stable top-level keys ([atlas-data](https://github.com/mitre-atlas/atlas-data), [CTID](https://ctid.mitre.org/blog/2026/05/06/secure-ai-v2-release)).

### Core architectural decision: split fast-moving from stable

Separate the two knowledge classes physically, because they have different decay rates and different review cadences:

- **`kb/ai-threats/`** — prompt injection, indirect/tool injection, memory & context poisoning, skill-file attacks, agent-specific MITRE ATLAS techniques (`AML.T*`). This tier churns monthly and needs dated provenance and confidence on every entry. ATLAS itself releases monthly and just added 14 agent-focused techniques via the Zenity collaboration ([Vectra](https://www.vectra.ai/topics/mitre-atlas), [ARMO](https://www.armosec.io/blog/mitre-atlas-for-ai-agent-attack-detection/)).
- **`checklists/`** — stable language/web review checklists (OWASP Web Top 10, CWE Top 25, SQLi/XSS/SSRF/path-traversal, secrets, deserialization). These map to Semgrep-style rules and change yearly, not monthly. Keep them lean and mostly static; the Claude skill guidance explicitly warns against time-sensitive phrasing and recommends an `<details>` "old patterns" block for deprecations ([Claude best practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)).

This split lets the agent's *scheduled refresh routine* touch only `ai-threats/` and `detections/` weekly/monthly, leaving the stable corpus untouched (no drift introduced by needless edits).

### Proposed file/folder layout (Claude Code skill)

```text
security-kb/                         # a Claude Code skill
├── SKILL.md                         # <500 lines: navigation + how to query KB
├── KB_SCHEMA.md                     # entry schema + lifecycle rules (the contract)
├── CHANGELOG.md                     # human-readable, dated, append-only
├── manifest.json                    # content_version, format_version, counts, last_refresh
├── references/
│   ├── ai-threats/                  # FAST tier (monthly cadence)
│   │   ├── INDEX.md                 # ToC table: id | title | class | severity | status
│   │   ├── prompt-injection.md      # one file per technique class (not per entry)
│   │   ├── tool-and-mcp-injection.md
│   │   ├── memory-context-poisoning.md
│   │   ├── skill-supplychain.md
│   │   └── data-exfiltration.md
│   ├── checklists/                  # STABLE tier (yearly cadence)
│   │   ├── INDEX.md
│   │   ├── web-owasp.md
│   │   ├── injection-sqli-xss-ssrf.md
│   │   ├── secrets-and-crypto.md
│   │   └── language-python.md
│   └── mappings/
│       └── technique-checklist-detection.csv   # the join table (DaC link)
├── detections/                      # detection-as-code: machine rules
│   ├── semgrep/  (*.yaml)
│   ├── sigma/    (*.yml)
│   └── grep/     (patterns.yaml)
├── archive/                         # deprecated/superseded entries (moved, not deleted)
└── scripts/
    ├── validate_kb.py               # schema lint, dup check, dead-link, size caps
    ├── dedup.py                     # near-duplicate detection
    └── refresh.py                   # pull ATLAS/OWASP/CVE deltas → draft entries
```

Two deliberate choices from the Claude skill docs: **(1)** entries live grouped *by technique class in one file*, not one-file-per-entry — this keeps references one level deep from `SKILL.md` (the docs warn nested references get partially read with `head -100`) and lets the agent `grep -i "indirect injection" references/ai-threats/prompt-injection.md`. **(2)** Each file >100 lines opens with a Markdown ToC so partial reads still see full scope ([Claude best practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)).

### Per-entry template (Markdown body + YAML front-matter)

The front-matter is machine-parseable (validation, dedup, mapping); the body is what Claude reads. Field choices fuse Sigma's lifecycle fields (`status`, `level`, `date`, `modified`, `references`, `id`, `tags`) ([SigmaHQ](https://sigmahq.io/docs/basics/rules.html)) with Semgrep's metadata (`cwe`, `owasp`, `confidence`, `references`, `category`) ([Semgrep rule syntax](https://semgrep.dev/docs/writing-rules/rule-syntax)) and ATLAS's typed IDs + technique class.

````markdown
---
id: AIT-0007                          # stable typed id; never reused
title: Indirect prompt injection via retrieved web content
technique_class: prompt-injection    # controlled vocab (see KB_SCHEMA.md)
atlas: AML.T0051.001                  # external xref where one exists
owasp_llm: LLM01:2025
affected_stack: [agent, rag, tool-use, browser]   # tags for grep filtering
severity: high                        # critical|high|medium|low|informational (Sigma levels)
confidence: medium                    # high|medium|low (Semgrep semantics)
status: active                        # active|archived|deprecated
date: 2026-02-14                      # first added (ISO-8601)
modified: 2026-05-30                  # bump ONLY on logic/severity/detection change
provenance:                           # dated source URLs — traceability
  - {url: "https://atlas.mitre.org/techniques/AML.T0051", date: 2026-05}
  - {url: "https://genai.owasp.org/llmrisk/llm01-2025-prompt-injection/", date: 2025}
supersedes: [AIT-0003]                # explicit dedup/merge lineage
detections: [semgrep/agent-untrusted-tool-output.yaml, grep/exfil-markdown-image]
review_by: 2026-08-30                 # forces re-validation; expiry guard vs drift
---

## Summary
One paragraph. Assume Claude is smart — no LLM-101 explanation.

## Detection pattern
- grep: `!\[.*\]\(https?://[^)]*\?[^)]*=`   # data-exfil via markdown image
- AST/Semgrep: untrusted tool/RAG output reaching a tool-call arg unsanitised
- Behavioral: agent acts on instructions embedded in fetched/returned content

## Checklist items it maps to
- CHK-AGENT-04: treat all tool/RAG/web output as untrusted data, never instructions

## False positives / notes
Legitimate templated image URLs with query params.
````

### Versioning, changelog, size caps, dedup

- **Versioning.** Mirror ATLAS: a global `manifest.json` carries `content_version` (`YYYY.MM.N`) and `format_version` (semver for the schema itself). Per-entry, `date`/`modified` follow Sigma's rule: bump `modified` *only* when title, detection, severity, or class changes — not for typo fixes — so "last meaningfully changed" stays honest ([SigmaHQ](https://sigmahq.io/docs/basics/rules.html)). IDs are never reused; merges use `supersedes`.
- **Changelog.** `CHANGELOG.md` is append-only and dated, plus Git history as the authoritative audit trail (DaC: every change via PR + peer review) ([dac-reference](https://dac-reference.readthedocs.io/en/latest/core_component_managing_detection_rules_in_a_vcs.html)).
- **Size caps & distillation.** Hard limits enforced by `validate_kb.py`: `SKILL.md` < 500 lines (Anthropic's stated cap); each `references/*.md` file ≤ ~400 lines / ~250 entries-equiv; entry Summary ≤ 120 words. When a file approaches the cap, *distill*: collapse near-identical variants into one entry with a variants list, and move `status: deprecated` entries to `archive/` (off the agent's hot path, zero context cost until read). This directly counters bloat — the whole point of progressive disclosure is that unread files cost zero tokens ([Claude best practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)).
- **Dedup.** Two layers: (1) controlled `technique_class` vocab prevents synonym sprawl ("Use consistent terminology" — Anthropic); (2) `dedup.py` flags entries sharing `atlas`/`owasp_llm` xref or high title/Summary similarity, surfacing them for merge via `supersedes`. CI fails on duplicate `id`s.

### Detection-as-code: technique → checklist → rule

The KB's spine is the **mapping join** in `references/mappings/technique-checklist-detection.csv`, e.g. `AIT-0007 → CHK-AGENT-04 → semgrep/agent-untrusted-tool-output.yaml`. This is the DaC principle that detection logic is testable code, not prose ([Splunk DaC](https://www.splunk.com/en_us/blog/learn/detection-as-code.html)). Every rule under `detections/` ships with a **fixture pair** (a vulnerable sample that must match + a benign sample that must NOT), and `scripts/validate_kb.py` runs in CI to: lint schema, check every `id` referenced in the CSV exists, run Semgrep/Sigma syntax validation, and assert each fixture's match/no-match. Borrow Semgrep registry hygiene: `confidence` levels gate which rules run in CI vs advisory mode, `references`/`cwe`/`owasp` are mandatory for `category: security` rules, and rules can be deprecated without deletion ([Semgrep policies](https://semgrep.dev/docs/semgrep-code/policies)). Sigma supplies the portability lesson: write detection intent once, convert per backend.

### Keeping it fresh without drift (the self-improving loop)

Drive refresh with a **Claude Code scheduled routine** (cron via the `schedule` skill / `CronCreate`): monthly, `refresh.py` pulls deltas from ATLAS's machine-readable `dist/ATLAS-latest.yaml` (STIX 2.1) and OWASP/CVE feeds, drafts candidate entries into a branch, and opens a PR for human review — never auto-merge. The `review_by` field acts as an **expiry guard**: any `active` entry past its date is flagged stale in CI, forcing re-validation against its provenance URLs. This gives the three properties asked for — **fresh** (cadenced PR-gated ingestion), **traceable** (dated provenance + Git history + changelog), and **bloat/drift-resistant** (size caps, dedup-by-xref, archive-don't-delete, expiry guards, and the fast/stable split so stable checklists are never needlessly churned).

## Key takeaways

- Physically split the KB into a FAST tier (references/ai-threats/, monthly cadence: prompt/tool/memory/skill-injection, ATLAS AML.T* techniques) and a STABLE tier (checklists/, yearly: OWASP Web, CWE Top 25). They decay at different rates, so refresh routines should only touch the fast tier — this alone prevents most drift.
- Adopt MITRE ATLAS's living-KB conventions: typed never-reused IDs, and TWO version numbers in a manifest.json — content_version (YYYY.MM.N) for the data and format_version (semver) for the schema. ATLAS now ships monthly; mirror that cadence for AI-threat entries.
- Per-entry front-matter should fuse Sigma + Semgrep fields: id, title, technique_class, affected_stack, severity (Sigma levels critical/high/medium/low/informational), confidence (Semgrep high/medium/low), status (active/archived/deprecated), date, modified, dated provenance URLs, supersedes, and a detections[] link.
- Apply Sigma's modified-date discipline: bump `modified` ONLY when title, detection logic, severity, or class changes — not for typos — so 'last meaningfully changed' stays trustworthy for staleness checks.
- Enforce size caps mechanically (SKILL.md <500 lines per Anthropic; reference files ~400 lines; entry summaries ~120 words) and group entries BY technique class in one file each — keep references one level deep from SKILL.md so Claude reads whole files instead of head-100 previews.
- Make detection-as-code the spine: a technique -> checklist-item -> detection-rule join table (CSV), with every Semgrep/Sigma/grep rule carrying a fixture PAIR (must-match vulnerable + must-not-match benign) validated in CI. Detections are testable code, not prose.
- Dedup with two layers: a controlled technique_class vocabulary to stop synonym sprawl, plus a script that flags entries sharing an ATLAS/OWASP xref or high title similarity, merging via an explicit `supersedes` lineage field. CI fails on duplicate IDs.
- Never delete — move deprecated/superseded entries to an archive/ directory. Progressive disclosure means unread files cost zero context tokens, so archiving fights bloat without losing history.
- Add a `review_by` expiry field per active entry; CI flags any entry past its date as stale, forcing re-validation against its provenance URLs. This is the primary anti-drift guard for the fast tier.
- Drive freshness with a Claude Code scheduled routine (cron) that pulls deltas from ATLAS dist/ATLAS-latest.yaml (STIX 2.1) and OWASP/CVE feeds, drafts candidate entries into a branch, and opens a PR — human-reviewed, never auto-merged (detection-as-code PR + peer-review discipline).
- Avoid time-sensitive prose in stable checklists; use an <details> 'old patterns / deprecated' block per Anthropic guidance so legacy context is preserved without polluting the active checklist.
- Provenance + traceability = dated source URLs in front-matter PLUS Git history PLUS an append-only dated CHANGELOG.md; together they give a full audit trail of who/when/why each entry changed.

## Sources

- https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices
- https://sigmahq.io/docs/basics/rules.html
- https://github.com/mitre-atlas/atlas-data
- https://atlas.mitre.org/
- https://www.vectra.ai/topics/mitre-atlas
- https://www.armosec.io/blog/mitre-atlas-for-ai-agent-attack-detection/
- https://ctid.mitre.org/blog/2026/05/06/secure-ai-v2-release
- https://www.splunk.com/en_us/blog/learn/detection-as-code.html
- https://kravensecurity.com/detection-engineering-lifecycle/
- https://dac-reference.readthedocs.io/en/latest/core_component_managing_detection_rules_in_a_vcs.html
- https://semgrep.dev/docs/writing-rules/rule-syntax
- https://semgrep.dev/docs/semgrep-code/policies
- https://semgrep.dev/docs/contributing/contributing-to-semgrep-rules-repository
- https://genai.owasp.org/llm-top-10/
- https://www.deepwatch.com/glossary/detection-as-code-dac/

