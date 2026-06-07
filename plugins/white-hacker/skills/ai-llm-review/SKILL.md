---
name: ai-llm-review
description: >
  AI/LLM/MCP/Agentic security review: improper output handling (LLM05), lethal
  trifecta, prompt-injection architecture, MCP token-passthrough/tool poisoning,
  RAG/vector poisoning, excessive agency, unbounded consumption. Use when the repo
  contains LLM/agent/MCP code.
---

# ai-llm-review — the AI/LLM/MCP/Agentic discovery pass

The inner-loop pass that **consumes** the living `ai-attack-kb` (ADR-012). It runs as a focused
discovery sweep over the AI surface and merges its candidates into `VULN-FINDINGS.json`, exactly
like `sec-vuln-scan` does for general code. Discovery and verification stay **separate** (ADR-008) —
this stage optimizes recall; `sec-triage` decides what is real.

> **Trigger:** runs **only when `SCAN-PLAN.json` has `ai_pass:true`** (set by `sec-detect` when an
> LLM/agent/MCP dep is present). When `ai_pass:false` the pass is **skipped entirely** — no AI noise
> on non-AI repos. Reads `SCAN-PLAN.json`, the repo, `_shared/reference/ai-llm.md`, and
> `ai-attack-kb/reference/*` on demand; writes/merges `VULN-FINDINGS.json`.

## Stance (load-bearing)
Treat **all model output and all tool/RAG/MCP results as untrusted user input** (Agents Rule of
Two: never simultaneously hold untrusted input + secrets + egress). Two precision rules from the
grooming, baked in here:
- **LLM05 Improper Output Handling is the highest-yield, reportable code check** — model/tool/RAG
  output reaching a sink (`eval`/`exec`/`subprocess`, string-built SQL, unsanitized HTML, file path,
  URL/SSRF, template/SSTI, deserializer). This is what you report as HIGH.
- **LLM01 prompt injection is architectural**, exclusion-listed (`exclusion-rules.md` rule 11), and
  emitted as a **design note, not a HIGH** finding. Flag *missing architectural defenses* (dual-LLM/
  CaMeL, spotlighting, least agency), not "prompt injection" as a line-level bug.

## Method — partition the AI surface, then sweep
1. **Partition** the AI surface into independent areas:
   - **system prompt / instructions** (LLM07 leakage, secrets in prompts),
   - **tool / function definitions** (MCP tool-description poisoning, over-broad scope),
   - **RAG / ingestion / memory** (vector poisoning, cross-tenant retrieval, indirect injection),
   - **output sinks** (the LLM05 sinks — *highest priority*),
   - **MCP surface** (token passthrough, confused deputy, audience binding),
   - **agent loop / agency** (high-impact tools without a human gate, unbounded consumption).
2. **Sweep each partition** against `_shared/reference/ai-llm.md` (§1–§8). For the matched
   technique class, **load the `ai-attack-kb/reference/<class>.md` entry on demand** (progressive
   disclosure) and use its `detections` patterns. For each candidate trace **source → sink**.
3. **Trifecta pass.** For each agent/tool path, apply the lethal-trifecta / Rule-of-Two test
   (private data + untrusted input + exfiltration ⇒ architectural HIGH-risk design note).

Record `{file, line, category, source, sink, why-reachable}` per candidate; report unproven ones
with lower `confidence` (recall stage — triage prunes). The clean structured-output look-alike
(schema-validated before the sink) is **not** a finding.

## KB citation — `kb_refs`
Every AI finding must carry **`kb_refs`**: the `id`(s) of the `ai-attack-kb` entry whose technique
it instantiates (e.g. `AISEC-DATA-EXFIL-001` for an LLM05 exfil sink, `AISEC-TOOL-POISONING-001` for
MCP token passthrough). `validate_findings.py --check-kb-refs .claude/skills/ai-attack-kb/reference/`
asserts every cited id resolves to a real KB entry — a finding with a dangling `kb_ref` fails CI.

## AI-redteam capability selection (+ degradation)
The AI pass runs behind the **`ai-redteam` capability** (ADR-015), present in `SCAN-PLAN.json`'s
`category_tool["ai-redteam"]` only when `ai_pass` is set:
- **Tool bound** (illustrative, not required: promptfoo / garak / Inspect): use it as a
  behavioral red-team signal, fold hits into the candidate set, stamp `tool_assisted:true` (via
  `_shared/scripts/degradation.py`). Pin/verify the tool per ADR-006.
- **Degraded** (`null` — no AI-redteam tool installed, the common case today): run the **static
  floor** — the `ai-llm.md` + KB `detections` patterns over the code with Read/Grep/Glob — stamp
  `tool_assisted:false`, cap confidence, and list `ai-redteam` in `summary.tools_unavailable`.
  The pass is **optional**-tool, **never blocks**, and **does not fake a behavioral red-team** when
  no tool is present.

## Output — merged into `VULN-FINDINGS.json`
Conforms to `_shared/reference/finding-schema.json` (the `kb_refs` field is required; validate with
`_shared/scripts/validate_findings.py [--check-kb-refs <kb-dir>]`). Every finding is
`verified: static_review_only` at this stage; severity is provisional (triage re-derives it).
Never write secret values to output (decision-makers see only `{file,line,category,diff}`).

## Verification criteria (definition of done)
- [ ] Triggered by `SCAN-PLAN.json` `ai_pass`; loads `ai-attack-kb` entries (progressive disclosure).
- [ ] Findings carry `kb_refs` to KB entry ids; LLM05-first / LLM01-architectural stance documented.
- [ ] `ai-redteam` capability optional with floor degradation (ADR-003/015); never blocks.
- [ ] Stub banner removed; output validates against the T-1.1 schema (incl. `--check-kb-refs`).
- [ ] No secret values written to output.
