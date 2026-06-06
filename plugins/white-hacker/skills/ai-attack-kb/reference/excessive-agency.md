---
id: AISEC-EXCESSIVE-AGENCY-001
title: Excessive agency — over-broad tool scope/autonomy without human gate
technique_class: excessive-agency
severity: high
confidence: 0.8
status: active
date: 2026-06-06
modified: 2026-06-06
review_by: 2026-09-06
metadata:
  source: OWASP Top 10 for LLM Applications 2025 (LLM06 Excessive Agency) + OWASP Top 10 for Agentic Applications 2026 (ASI03 Identity & Privilege Abuse)
  url: https://genai.owasp.org/llm-top-10/
  retrieved: 2026-06-06
supersedes: null
detections:
  - "grep: high-impact tools (payments, deletes, sends, admin, shell/code-exec) invoked from an agent loop with no human-in-the-loop / out-of-band confirmation"
  - "grep: tools granted broad filesystem/network/DB scope (wildcard creds, no per-tool least-privilege); a shared long-lived identity across agents"
  - "behavioral: no validation/circuit-breaker between autonomous stages; no per-action blast-radius or iteration cap"
xref: ["LLM06:2025", "ASI03", "ASI02", "AML.T0053"]
---
Excessive agency is too much autonomy, permission, or tooling: the agent can take consequential
actions (move money, delete data, send messages, run code) without proportionate controls. The
guiding principle is **least agency** — "the threat is not malfunction, it is the misuse of normal
behavior." Controls: a distinct short-lived per-agent identity (no shared god-credential),
**human-in-the-loop** for high-impact actions (money/admin/data-writes/code-exec), per-tool
least-privilege scope, validation and **circuit breakers** between autonomous stages, and
blast-radius/iteration limits. This is the agency leg that turns a prompt injection into real-world
impact, so it pairs directly with `prompt-injection` (the trifecta's state-change channel).

Detection: see `detections` — high-impact tools without a human gate, over-scoped credentials,
missing inter-stage validation.
Checklist: maps to `ai-llm.md` excessive-agency / Agents-Rule-of-Two section.
