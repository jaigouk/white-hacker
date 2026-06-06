---
id: AISEC-TOOL-POISONING-001
title: MCP tool-description poisoning, token passthrough & confused deputy
technique_class: tool-poisoning
severity: high
confidence: 0.8
status: active
date: 2026-06-06
modified: 2026-06-06
review_by: 2026-09-06
metadata:
  source: MCP Authorization spec 2025-11-25 (RFC 8707 audience binding, no token passthrough) + OWASP MCP Top 10 (beta)
  url: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
  retrieved: 2026-06-06
supersedes: null
detections:
  - "grep: MCP tool/function `description`/schema fields containing imperative instructions to the model (model-visible, human-invisible 'tool poisoning')"
  - "grep: an incoming access/bearer token forwarded to a downstream API (token passthrough) instead of the server minting/validating its own audience-bound token"
  - "behavioral: a tool action not bound to the validated calling user's identity (confused deputy / OAuth-proxy reuse); unpinned tool/manifest sources (rug pull, typosquat)"
xref: ["MCP03:2025", "MCP01:2025", "ASI02", "ASI04", "AML.T0011.002", "AML.T0053", "AML.T0110"]
---
MCP servers expose tools whose **descriptions/schemas are part of the model's context**, so a
malicious or compromised server can hide instructions there (model-visible, human-invisible) —
"tool poisoning." Related failures: **token passthrough** (forwarding the caller's token to a
downstream API instead of validating audience), the **confused deputy** (a tool acting with
another principal's credentials), and supply-chain "rug pulls"/typosquatting of tool sources.
The MCP authorization spec (2025-11-25) makes audience binding via **RFC 8707 Resource
Indicators** mandatory and explicitly forbids token passthrough.

Detection: see `detections` — instructions inside tool metadata, forwarded tokens, actions not
bound to the validated user, unpinned tool provenance.
Checklist: maps to `ai-llm.md` MCP section (token-passthrough / tool-poisoning / confused-deputy).
Note: `AML.T0110` is medium-confidence (ATLAS v6/2026.05 renumber vs `AML.T0108`) — durable
anchors are `MCP03:2025`, `ASI02`, `AML.T0011.002`; re-confirm the number on the next ATLAS poll.
