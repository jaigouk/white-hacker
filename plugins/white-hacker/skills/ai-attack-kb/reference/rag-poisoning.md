---
id: AISEC-RAG-POISONING-001
title: RAG / vector poisoning, embedding inversion & cross-tenant leakage
technique_class: rag-poisoning
severity: high
confidence: 0.8
status: active
date: 2026-06-06
modified: 2026-06-06
review_by: 2026-09-06
metadata:
  source: OWASP Top 10 for LLM Applications 2025 (LLM08 Vector & Embedding Weaknesses) + MITRE ATLAS AML.T0070 RAG Poisoning
  url: https://genai.owasp.org/llm-top-10/
  retrieved: 2026-06-06
supersedes: null
detections:
  - "grep: unauthenticated/unvalidated write path into a knowledge base or vector store (ingestion accepts external content without provenance checks)"
  - "grep: vector query missing a per-tenant namespace/filter at the DB layer (cross-tenant retrieval); bulk vector read without rate limiting (embedding inversion)"
  - "behavioral: retrieved documents flow into instruction context unlabeled (indirect prompt injection via RAG); no cross-tenant retrieval test exists"
xref: ["LLM08:2025", "ASI06", "AML.T0070", "AML.T0020", "AML.T0071"]
---
RAG is "the forgotten attack surface." **Knowledge-base poisoning**: a handful of malicious
documents among millions can flip ~90% of answers (PoisonedRAG); poisoned content also becomes an
**indirect prompt-injection** vector. **Embedding inversion**: stored vectors can reconstruct
source text, so encrypt/access-control the store and rate-limit bulk reads. **Cross-tenant
leakage**: semantic overlap plus weak isolation leaks one tenant's documents to another; ANN
indexes can leak distribution via timing. Strongest control is per-tenant physical isolation;
minimum is an enforced namespace + per-query tenant filter at the DB layer, plus a cross-tenant
retrieval test. Also covers agent **memory/context poisoning** (ASI06).

Detection: see `detections` — open ingestion, missing tenant scoping, unlabeled retrieved content.
Checklist: maps to `ai-llm.md` RAG/vector section; pairs with `prompt-injection` (indirect IPI).
