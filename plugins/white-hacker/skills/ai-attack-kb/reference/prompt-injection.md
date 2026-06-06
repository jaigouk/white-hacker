---
id: AISEC-PROMPT-INJECTION-001
title: Prompt injection (direct + indirect) overriding model instructions
technique_class: prompt-injection
severity: high
confidence: 0.9
status: active
date: 2026-06-06
modified: 2026-06-06
review_by: 2026-09-06
metadata:
  source: OWASP Top 10 for LLM Applications 2025 (LLM01) + Simon Willison "lethal trifecta" / Agents Rule of Two
  url: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
  retrieved: 2026-06-06
supersedes: null
detections:
  - "grep: retrieved/tool/web/email content concatenated into a prompt or system-prompt string (untrusted spans not delimited/labeled)"
  - "behavioral: does any single agent path hold >=2 of {private data, untrusted input, exfiltration/state-change} without human approval? (lethal trifecta / Rule of Two)"
  - "absence of a dual-LLM / quarantine separation where untrusted content is processed by a tool-less, stateless model"
xref: ["LLM01:2025", "ASI01", "MCP03:2025", "AML.T0051", "AML.T0051.000", "AML.T0051.001"]
---
Crafted input — direct in the user turn, or indirect via retrieved documents, tool output,
emails, or web pages — overrides the model's intended instructions. As of 2026 there is no
reliable general fix: models cannot separate instructions from data. Treat this as an
**architectural** risk, not a code bug. It is exclusion-listed (`exclusion-rules.md`) and
reported as a **design note, not a HIGH finding**. The load-bearing heuristic is the **lethal
trifecta / Agents Rule of Two**: danger arises when one path combines private-data access,
exposure to untrusted content, and an exfiltration/state-change channel without human approval.
Mitigations are architectural (dual-LLM / CaMeL, spotlighting, least agency) — never a classifier
used as a control boundary ("99% is a failing grade").

Detection: see `detections` — flag raw concatenation of untrusted content into instruction
context and any trifecta-complete path.
Checklist: maps to `ai-llm.md` LLM01 (architectural design note) + the lethal-trifecta test.
The exploitable *code* sink it leads to is LLM05 — see `data-exfil` and `ai-llm.md` LLM05.
