---
id: AISEC-DATA-EXFIL-001
title: Data exfiltration — the trifecta's exit channel & sensitive-info disclosure
technique_class: data-exfil
severity: high
confidence: 0.8
status: active
date: 2026-06-06
modified: 2026-06-06
review_by: 2026-09-06
metadata:
  source: OWASP Top 10 for LLM Applications 2025 (LLM02 Sensitive Information Disclosure) + MITRE ATLAS exfiltration (AML.T0024/T0025/T0086) + OWASP MCP Top 10 (context over-sharing)
  url: https://genai.owasp.org/llm-top-10/
  retrieved: 2026-06-06
supersedes: null
detections:
  - "grep: an outbound channel reachable from model/tool output — fetch/requests to a model-supplied URL, markdown image/link auto-render, webhook/email/issue-comment sinks (the 'exfil leg')"
  - "grep: secrets/PII/internal ids placed into prompts, system prompts, tool outputs, or logs (assume system prompts leak — LLM07)"
  - "behavioral: MCP context over-sharing — more context/data handed to a tool/server than the action needs"
xref: ["LLM02:2025", "MCP10:2025", "AML.T0024", "AML.T0025", "AML.T0086"]
---
Exfiltration is the **exit channel** that completes the lethal trifecta: once an injected agent
holds private data, it needs a way out. Classic vectors are a model-controlled `fetch`/`requests`
call, an auto-rendered markdown image/link that beacons to an attacker URL, or a write-capable tool
(webhook, email, issue comment) carrying data off. Related disclosure: secrets/PII/internal ids in
prompts, **system prompts** (assume they leak, LLM07), tool outputs, or logs; and **MCP context
over-sharing** (handing a tool/server more data than the action needs). Membership-inference and
inversion against an inference API are the model-extraction variants (AML.T0024).

Detection: see `detections` — model-reachable outbound channels, sensitive data in context/logs,
over-broad context handed to tools.
Checklist: maps to `ai-llm.md` data-exfil / sensitive-disclosure section; pairs with
`excessive-agency` (write-capable tools) and `prompt-injection` (the trifecta).
