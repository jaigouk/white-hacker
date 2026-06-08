---
name: ai-attack-kb
description: Living knowledge base of AI/LLM/agent/MCP attack techniques with detection patterns, dated provenance, and active/archived status. Loaded on demand during ai-llm-review; refreshed by sec-kb-refresh. Use to look up current AI-attack techniques.
---

# ai-attack-kb — living AI-attack knowledge base

Progressive-disclosure KB of AI/LLM/agent/MCP attack techniques (ADR-012). It is the
**Context surface** the outer loop edits: `ai-llm-review` (inner loop) **consumes** these
entries and attaches their `id`s to findings as `kb_refs`; `sec-kb-refresh` and `sec-learn`
(outer loop) **add/age** entries with dated provenance. This file is a pure **table of
contents** — the technique detail lives one level deep in `reference/<technique-class>.md`
and is loaded only when a class is in play, so a review never pays for knowledge it doesn't use.

## How to use this KB (during a review)

1. `sec-detect` sets `SCAN-PLAN.json` `ai_pass:true` when AI/LLM/MCP deps are present.
2. `ai-llm-review` partitions the agent surface, then for each relevant **technique class**
   below, opens just that one `reference/*.md` entry (progressive disclosure).
3. Each entry maps **technique → detection pattern → the `ai-llm.md` checklist item** and
   carries `xref` ids (OWASP `LLMxx:2025` / `ASIxx` / `MCPxx`, MITRE `AML.Txxxx`, `CVE-…`).
4. A finding cites the entry by its `id` in `kb_refs`. `validate_findings.py --check-kb-refs`
   asserts every cited id resolves to an entry here.

## Technique classes (the controlled vocabulary)

`technique_class` is a **closed enum = these six file stems** (one entry per file today;
a class that grows splits to `reference/<class>-<n>.md`, still one level deep — ADR-012, ADR-019):

| Class | File | Covers | Primary xrefs |
|-------|------|--------|---------------|
| **prompt-injection** | [`reference/prompt-injection.md`](reference/prompt-injection.md) | Direct + indirect/retrieved instruction override; the lethal trifecta heuristic. Architectural (no general fix) — a **design note**, not a HIGH code finding. | `LLM01:2025`, `ASI01`, MITRE ATLAS |
| **tool-poisoning** | [`reference/tool-poisoning.md`](reference/tool-poisoning.md) | MCP tool description/schema poisoning, token passthrough (RFC 8707 audience binding), confused-deputy / rug pulls. | OWASP MCP Top 10, `ASI02` |
| **rag-poisoning** | [`reference/rag-poisoning.md`](reference/rag-poisoning.md) | Knowledge-base/vector poisoning, embedding inversion, cross-tenant retrieval leakage, memory poisoning. | `LLM08:2025`, `ASI06` |
| **excessive-agency** | [`reference/excessive-agency.md`](reference/excessive-agency.md) | Over-broad tool scope/autonomy; missing human-in-the-loop on high-impact actions; least-agency violations. | `LLM06:2025`, `ASI03` |
| **data-exfil** | [`reference/data-exfil.md`](reference/data-exfil.md) | The exfiltration leg of the trifecta; sensitive-info disclosure via outputs/tool results; MCP context over-sharing. | `LLM02:2025`, MITRE ATLAS exfiltration |
| **supply-chain** | [`reference/supply-chain.md`](reference/supply-chain.md) | Slopsquatting (LLM-hallucinated package names) + AI-SDK typosquatting; cross-ecosystem (npm/PyPI/RubyGems/Go/crates/Maven). Detection lives in the deps-scan supply-chain floor. | `LLM03:2025` |

`reference/ai-llm.md` does **not** live here — the inner-loop **checklist** is a stable
`_shared/reference/ai-llm.md` (yearly cadence); this `ai-attack-kb/reference/` tier is the
**fast** AI-threat tier (monthly cadence, refreshed by `sec-kb-refresh`). See the README
layout reconcile and `docs/plan/phase-4-ai-llm-api.md`.

## Entry format (the contract)

One entry per file: YAML front-matter (the schema) then a body
(`≤120-word summary` → detection → checklist mapping). Validated by
[`scripts/validate_kb.py`](scripts/validate_kb.py) against
[`kb-entry-schema.json`](kb-entry-schema.json):

```yaml
---
id: AISEC-PROMPT-INJECTION-001     # typed, NEVER reused (ADR-012)
title: <short technique title>
technique_class: prompt-injection  # enum = the six stems above
severity: high                     # high | medium | low
confidence: 0.8                    # 0..1
status: active                     # active | archived | deprecated
date: 2026-06-06                   # first added
modified: 2026-06-06               # last edited
review_by: 2026-09-06              # staleness gate (T-8.1 enforces)
metadata:                          # provenance — ALL THREE MANDATORY
  source: <human-readable source>
  url: https://…
  retrieved: 2026-06-06
supersedes: null                   # or the id this entry replaces
detections:                        # ≥1 grep/semgrep hint or behavioral check
  - "…"
xref: ["LLM01:2025", "AML.T0051"]  # external taxonomy ids
---
<≤120-word summary>

Detection: <pattern / behavioral check>
Checklist: <the ai-llm.md item this maps to>
```

**Schema invariants** (enforced by `validate_kb.py`): `metadata.{source,url,retrieved}` are
mandatory; `technique_class` and `status` are closed enums; `id` is the typed `AISEC-…`
pattern and unique across the directory; summary ≤ 120 words; file ≤ 400 lines.

## Validate

```bash
uv run --with jsonschema --with pyyaml python \
  .claude/skills/ai-attack-kb/scripts/validate_kb.py \
  .claude/skills/ai-attack-kb/reference/
# exit 0 = every entry conforms; tests: .claude/skills/ai-attack-kb/scripts/tests/
```

## Lifecycle (outer loop)

- **Add:** `sec-kb-refresh` polls authoritative feeds (`docs/research/si-07-threat-feeds.md`),
  proposes a dated entry with a fresh, never-reused `id`, for human approval (PR-gated).
- **Age:** `review_by` flags staleness; an obsoleted technique flips `status: archived`
  (kept for audit) and a replacement sets `supersedes:` to the old `id`.
- **Gate:** no autonomous change merges until the Phase-9 frozen eval corpus + keep-or-revert
  gate exist (README ordering note; si-08 §7). T-4.1 builds the structure; T-8.1 adds gating.
