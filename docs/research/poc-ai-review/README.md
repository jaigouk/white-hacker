# PoC / fixture — AI-pass end-to-end (ai-llm-review)

- **Status:** ✅ PASS — `ai_pass` flips on the AI/MCP fixture (incl. an MCP-only repo),
  the AI pass flags the LLM05 sink + lethal-trifecta path + MCP token passthrough with
  KB-cited findings, the clean look-alike is spared, and findings validate with every
  `kb_ref` resolving.
- **Date:** 2026-06-06 · **Task:** Phase 4 T-4.6.

## Layout
| Dir | Manifest signal | Purpose |
|-----|-----------------|---------|
| `ai-vuln/` | `openai` + `mcp` | three planted vulns — the AI pass must flag all three |
| `ai-vuln-mcp-only/` | `mcp` only (no LLM SDK) | proves an MCP-only repo still flips `ai_pass` |
| `clean-lookalike/` | `openai` | same shapes done safely — the pass must **not** fire |
| `EXPECTED-FINDINGS.json` | — | the expected AI-pass output (schema-valid; every `kb_ref` resolves) |

## Expected findings (before → after)
| id | file:line | technique | OWASP | `kb_refs` |
|----|-----------|-----------|-------|-----------|
| F-001 | `ai-vuln/agent.py:28` | LLM05: model output → `subprocess(shell=True)` → RCE | LLM05:2025 | AISEC-PROMPT-INJECTION-001 |
| F-002 | `ai-vuln/agent.py:40` | lethal trifecta: private data + untrusted web + model-chosen exfil POST | LLM01/LLM02:2025 | AISEC-PROMPT-INJECTION-001, AISEC-DATA-EXFIL-001 |
| F-003 | `ai-vuln/agent.py:50` | MCP token passthrough (no audience binding) | MCP01:2025 | AISEC-TOOL-POISONING-001 |
| F-004 | `ai-vuln-mcp-only/server.py:16` | MCP token passthrough on an MCP-only repo | MCP01:2025 | AISEC-TOOL-POISONING-001 |

**Spared (must NOT appear in findings):** `clean-lookalike/agent_safe.py` —
`run_allowed_action` schema-validates the model's structured output against an allowlist and
uses a fixed argv (no shell), and `mint_downstream_token` mints an audience-bound credential
instead of forwarding the caller's token. Both are the safe forms of F-001/F-003, so neither
fires. (LLM01 prompt injection itself is treated as an architectural design note per
`exclusion-rules.md` rule 11 — F-002 is MEDIUM, not a line-level HIGH.)

## Run (verified)
```bash
# 1. detection flips ai_pass:true (AI/MCP dep) — incl. the MCP-only manifest
uv run --with jsonschema python .claude/skills/sec-detect/scripts/detect_tools.py \
  docs/research/poc-ai-review/ai-vuln | \
  python3 -c 'import json,sys; assert json.load(sys.stdin)["ai_pass"]'        # -> ai_pass True
uv run --with jsonschema python .claude/skills/sec-detect/scripts/detect_tools.py \
  docs/research/poc-ai-review/ai-vuln-mcp-only | \
  python3 -c 'import json,sys; assert json.load(sys.stdin)["ai_pass"]'        # -> ai_pass True (MCP-only)

# 2. findings validate + every kb_ref resolves to a real KB entry id
uv run --with jsonschema python .claude/skills/_shared/scripts/validate_findings.py \
  docs/research/poc-ai-review/EXPECTED-FINDINGS.json --no-dup-ids \
  --check-kb-refs .claude/skills/ai-attack-kb/reference/                       # -> OK (exit 0)
```

## Notes
- The "AI pass" itself is performed by `ai-llm-review` (an agent-driven discovery skill), not a
  script; `EXPECTED-FINDINGS.json` here is the **expected** output it produces on this fixture, used
  to lock the contract (schema + `--check-kb-refs`). The two automated edges proven by code are
  detection (`ai_pass`) and validation (`--check-kb-refs`), each with pytest coverage:
  `sec-detect` MCP tests + `_shared` `--check-kb-refs` tests.
- No AI-redteam tool is installed on the host, so the pass runs the **static floor**
  (`tool_assisted:false`, `ai-redteam` in `tools_unavailable`) — no faked behavioral red-team.
- Fixture files are detection bait only: no real secrets, no working exploit payloads.
