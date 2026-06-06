# Spike 05 — AI-threat taxonomy currency for the five KB technique classes

> **Why this spike:** the `ai-attack-kb` ships FIVE technique classes (prompt-injection,
> tool-poisoning, rag-poisoning, excessive-agency, data-exfil). Each KB entry carries an
> `xref` id set (OWASP LLMxx:2025, Agentic ASIxx, OWASP MCPxx, MITRE ATLAS AML.Txxxx, CVE).
> Per the project "verify before concluding" rule, those ids are re-checked against 2026
> **primary** sources before they go into the KB. MITRE ATLAS AML.T ids are the easiest to
> hallucinate, so every one cited here was seen on a real ATLAS source (atlas-data CHANGELOG
> /repo or a mirror that prints the id verbatim); any id I could not pin is tagged `unverified`.

- **Question:** for each of the 5 KB technique classes, what is the confirmed xref id set
  (LLMxx:2025 · ASIxx · MCPxx · AML.Txxxx · CVE), as of **2026-06-06**, and which ids cannot
  be confirmed against a primary source?
- **Method:** WebSearch (June-2026 results) + WebFetch of primary sources — `genai.owasp.org`
  (LLM Top 10, Agentic Top 10), `owasp.org` (MCP Top 10, API Security Top 10/2023),
  `modelcontextprotocol.io` (auth spec 2025-11-25), and the `mitre-atlas/atlas-data` GitHub
  CHANGELOG/repo (authoritative ATLAS content). Secondary mirrors (Promptfoo, misp-galaxy,
  StartupDefense) used only to cross-check ATLAS id↔name pairs.
- **Confidence:** **HIGH** for OWASP LLM/Agentic/MCP ids and the MCP auth spec (fetched
  primary); **HIGH** for the headline ATLAS ids (T0051/T0070/T0053/T0024/T0025/T0020/T0086,
  each seen on an ATLAS source); **MEDIUM** only for the exact "AI Agent Tool Poisoning"
  AML.T number (T0108 vs T0110 — a live renumber across ATLAS releases; see note).

## ATLAS version (confirmed)
- **Content version `2026.05`** (released **2026-05-27**), **format_version `6.0.0`** — matches
  `si-07-threat-feeds.md`. Source: `mitre-atlas/atlas-data` CHANGELOG.md + Releases (fetched).
- Use the repo (`dist/v6/ATLAS-latest.yaml` + STIX), **not** `atlas.mitre.org` — the website is a
  client-rendered SPA and `atlas.mitre.org/techniques/AML.T*` returns 404 to WebFetch (confirmed
  this spike). Repo CHANGELOG is the citable id↔name source.

## Findings — per-class xref id set

| Class | xref id | Name (verbatim) | Status | Source seen on |
|-------|---------|-----------------|--------|----------------|
| **prompt-injection** | `LLM01:2025` | Prompt Injection | confirmed | genai.owasp.org/llmrisk/llm01-prompt-injection (heading "LLM01:2025 Prompt Injection"; 2025 edition, no 2026 LLM revision) |
| | `ASI01` | Agent Goal Hijack | confirmed | Agentic Top 10 2026 list (genai.owasp.org / corroborating mirrors) |
| | `MCP03:2025` | Tool Poisoning | confirmed | owasp.org/www-project-mcp-top-10 |
| | `AML.T0051` | LLM Prompt Injection | confirmed | atlas-data CHANGELOG; sub-techs `AML.T0051.000` Direct, `AML.T0051.001` Indirect, `AML.T0051.002` Triggered |
| **tool-poisoning** | `MCP03:2025` | Tool Poisoning | confirmed | owasp.org/www-project-mcp-top-10 |
| | `ASI02` | Tool Misuse & Exploitation | confirmed | Agentic Top 10 2026 list |
| | `ASI04` | Agentic Supply Chain Vulnerabilities | confirmed | Agentic Top 10 2026 list (covers poisoned/tampered tool descriptors) |
| | `MCP01:2025` | Token Mismanagement & Secret Exposure | confirmed | owasp.org/www-project-mcp-top-10 (the "token" leg) |
| | `AML.T0110` | AI Agent Tool Poisoning | **MEDIUM / see note** | atlas-data CHANGELOG (also appears as `AML.T0108`); Promptfoo + Feb-2026 sources cite T0110 |
| | `AML.T0011.002` | User Execution: Poisoned AI Agent Tool | confirmed | atlas-data CHANGELOG + StartupDefense mirror |
| | `AML.T0104` | Publish Poisoned AI Agent Tool | confirmed | atlas-data CHANGELOG |
| | `AML.T0053` | Compromise LLM Plugins (was "LLM Plugin Compromise") | confirmed | atlas-data CHANGELOG (renamed) |
| **rag-poisoning** | `LLM08:2025` | Vector and Embedding Weaknesses | confirmed | OWASP LLM Top 10 2025 (fnd-04, genai.owasp.org/llm-top-10) |
| | `ASI06` | Memory & Context Poisoning | confirmed | Agentic Top 10 2026 list |
| | `AML.T0070` | RAG Poisoning | confirmed | atlas-data CHANGELOG (Spring-2025 addition) |
| | `AML.T0020` | Poison Training Data | confirmed | atlas-data CHANGELOG + misp-galaxy mirror |
| | `AML.T0071` | False RAG Entry Injection | confirmed | atlas-data CHANGELOG (supporting) |
| | `AML.T0099` | AI Agent Tool Data Poisoning | confirmed | atlas-data CHANGELOG (supporting) |
| **excessive-agency** | `LLM06:2025` | Excessive Agency | confirmed | OWASP LLM Top 10 2025 (fnd-04) |
| | `ASI03` | Identity & Privilege Abuse | confirmed | Agentic Top 10 2026 list |
| | `ASI02` | Tool Misuse & Exploitation | confirmed | Agentic Top 10 2026 list |
| | `AML.T0053` | Compromise LLM Plugins | confirmed | atlas-data CHANGELOG (agent-autonomy/over-permissioned tools) |
| **data-exfil** | `LLM02:2025` | Sensitive Information Disclosure | confirmed | OWASP LLM Top 10 2025 (fnd-04; moved up from #6) |
| | `MCP10:2025` | Context Injection & Over-Sharing | confirmed | owasp.org/www-project-mcp-top-10 |
| | `AML.T0024` | Exfiltration via AI Inference API | confirmed | atlas-data CHANGELOG (sub-tech `AML.T0024.000` Infer Training Data Membership) |
| | `AML.T0025` | Exfiltration via Cyber Means | confirmed | misp-galaxy mirror (prints id+name verbatim) |
| | `AML.T0086` | Exfiltration via AI Agent Tool Invocation | confirmed | atlas-data CHANGELOG + Promptfoo (the "lethal-trifecta exfil leg" for agents) |

### Note on `AML.T0108` vs `AML.T0110` (the one MEDIUM-confidence id)
Both numbers appear in the atlas-data CHANGELOG carrying the **same name "AI Agent Tool
Poisoning"** across different release rows — a live renumber/dedupe in the v5.x→v6 (2026.05)
restructure. Promptfoo and Feb-2026 write-ups cite **`AML.T0110`**, so the KB `tool-poisoning`
entry uses **T0110** as the primary ATLAS xref but should keep **`AML.T0011.002`** (Poisoned AI
Agent Tool) + **`MCP03:2025`** + **`ASI02`** as the *durable* anchors, since those are stable and
the exact AML.T number for "AI Agent Tool Poisoning" may shift again. Re-confirm the number on the
next `sec-kb-refresh` ATLAS poll.

## Cross-checks confirmed in passing
- **OWASP API Security Top 10 is still the 2023 edition** — no 2025/2026 edition exists. Confirmed
  on owasp.org/API-Security/editions/2023: **API1:2023** Broken Object Level Authorization (BOLA),
  **API5:2023** Broken Function Level Authorization (BFLA), **API3:2023** Broken Object Property
  Level Authorization (BOPLA). Any "API Top 10 2026" claim should be **distrusted**.
- **MCP authorization spec `2025-11-25`** (fetched primary, modelcontextprotocol.io) hardens auth:
  - MCP clients **MUST** implement RFC 8707 Resource Indicators and send the `resource` parameter
    with the **canonical MCP server URI** in authorization + token requests.
  - MCP servers **MUST** validate token audience (token issued specifically for them; reject
    otherwise) and **MUST NOT** pass through the client-supplied token to upstream APIs.
  → "no token passthrough" + RFC 8707 audience binding are hard review checks for `tool-poisoning`.
- **OWASP LLM Top 10** current edition = **2025**; **no 2026 LLM revision** as of 2026-06 (watch the
  GitHub repo for the next version-year bump). Agentic Top 10 = **2026** edition (published 2025-12-09).

## Decision
Use the per-class id sets in the Findings table for the KB `xref` fields. All ids are **confirmed**
except the single **MEDIUM** "AI Agent Tool Poisoning" number — write it as **`AML.T0110`** and add a
KB comment noting the T0108/T0110 renumber so a future refresh can settle it; do **not** treat the
exact number as load-bearing (the OWASP MCP03/ASI02 anchors carry the meaning). Keep KB entries
*pattern-first* (the detection signature is the lesson; ids are evidence that survives id churn).
No id needed the `unverified` tag — the only soft spot is the T0108/T0110 number, tagged MEDIUM.

## Sources (fetched / searched this spike)
- https://genai.owasp.org/llmrisk/llm01-prompt-injection/ (LLM01:2025, 2025 edition confirmed)
- https://genai.owasp.org/llm-top-10/ (LLM02/06/08:2025 — via fnd-04 + index)
- https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ (Agentic 2026 edition) ·
  https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/ (ASI01–ASI10 full list)
- https://owasp.org/www-project-mcp-top-10/ (MCP01:2025, MCP03:2025, MCP10:2025)
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization (RFC 8707 MUST, no token passthrough MUST NOT, audience validation MUST)
- https://github.com/mitre-atlas/atlas-data/blob/main/CHANGELOG.md + https://github.com/mitre-atlas/atlas-data/releases (content v2026.05 / format 6.0.0; AML.T0051/.000/.001/.002, T0053, T0070, T0071, T0086, T0099, T0104, T0108/T0110, T0011.002)
- https://misp-galaxy.org/mitre-atlas-attack-pattern/ (older ATLAS mirror — prints AML.T0020, T0024, T0025 id+name verbatim; lacks the newer GenAI/agentic ids)
- https://www.promptfoo.dev/docs/red-team/mitre-atlas/ (cross-check: T0051, T0024, T0020, T0086, T0110)
- https://www.startupdefense.io/mitre-atlas-techniques/aml-t0051-llm-prompt-injection (AML.T0051 = LLM Prompt Injection, cross-check)
- https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/ + https://owasp.org/API-Security/editions/2023/en/0x11-t10/ (API Top 10 = 2023; BOLA/BFLA/BOPLA)
