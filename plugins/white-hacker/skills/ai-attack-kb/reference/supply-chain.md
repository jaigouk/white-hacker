---
id: AISEC-SUPPLY-CHAIN-001
title: Slopsquatting & AI-SDK typosquatting — LLM-hallucinated/lookalike dependency names
technique_class: supply-chain
severity: high
confidence: 0.7
status: active
date: 2026-06-08
modified: 2026-06-08
review_by: 2026-09-08
metadata:
  source: Cloud Security Alliance — Slopsquatting research note (AI supply-chain; ~1-in-5 hallucination rate, 205,474 fabricated names) + Aikido slopsquatting writeup
  url: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_slopsquatting-ai-supply-chain_20260419-csa-styled-1.pdf
  retrieved: 2026-06-08
supersedes: null
detections:
  - "dependency name with no upstream registry record (slopsquat — a plausible-but-nonexistent package an attacker pre-registered)"
  - "typosquat/homoglyph/keyboard-adjacency distance (Damerau-Levenshtein 1-2) to a curated AI-SDK allowlist, applied across ecosystems (npm/PyPI/RubyGems/Go/crates/Maven)"
  - "package added via an unverified LLM-suggested install command (the AI's pasted `install <pkg>` line, name never checked against official docs)"
  - "scope/name separator or non-ASCII homoglyph collision with an allowlist entry while the raw string differs"
xref: ["LLM03:2025"]
---
Slopsquatting is the AI-native supply-chain technique: an LLM invents a plausible-but-nonexistent
package name, an attacker pre-registers it, and a developer installs it by pasting the AI's
suggested command. ~1-in-5 AI code suggestions reference a nonexistent package and 43% of
hallucinations repeat (predictable, so pre-registerable). Its sibling is AI-SDK typosquatting:
lookalike names of popular AI/LLM SDKs (Anthropic/OpenAI/LangChain/HuggingFace/MCP and friends).
Both are **ecosystem-agnostic** — the same name-trust failure exists for npm, PyPI, RubyGems, Go,
crates, and Maven. This entry documents the *technique*; the offline, per-ecosystem detection
greps (registry-record check, distance-to-allowlist, install-script inspection) live in the
deps-scan supply-chain floor, not here.

Detection: see `detections` — no-registry-record (slopsquat), distance-to-AI-SDK-allowlist
(typosquat/homoglyph) across ecosystems, and unverified LLM-suggested installs.
Checklist: maps to the deps-scan supply-chain floor (S4/S5 name-trust signals; wh-07w) — confirm
each dep name char-by-char against the curated allowlist / official SDK docs before installing.
