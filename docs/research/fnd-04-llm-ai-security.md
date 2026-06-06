# research:llm-ai-security

> Source: workflow `white-hacker-research` (wycjclbk6), agent `research:llm-ai-security`

## AI/LLM Application & Agent Security (2026 State of the Art)

This section maps the 2026 threat landscape for LLM apps and agents and ends with an actionable, language-agnostic checklist a code-reviewing agent can apply across TS/Go/Python/Java backends, frontends, and AI/agent projects.

### OWASP Top 10 for LLM Applications (2025 edition — current baseline in 2026)

The [2025 OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) is the governing list. Compared to the 2023 version it reordered risks and added new entries reflecting RAG and agentic systems:

| ID | Name | Core risk | Notable change |
|----|------|-----------|----------------|
| LLM01 | Prompt Injection | Crafted input (direct or indirect/retrieved) overrides intended behavior | Still #1; no robust general fix exists |
| LLM02 | Sensitive Information Disclosure | PII/secrets/IP leak via outputs or training data | Moved up from #6 |
| LLM03 | Supply Chain | Compromised models, datasets, adapters (LoRA), deps | Broadened beyond plugins |
| LLM04 | Data and Model Poisoning | Tainted pre-train/fine-tune/embedding data | Merged training-data poisoning |
| LLM05 | Improper Output Handling | Unsanitized model output flows into exec/SQL/HTML/shell | Renamed from "Insecure Output Handling" |
| LLM06 | Excessive Agency | Too much autonomy/permission/tooling | Elevated for agents |
| LLM07 | System Prompt Leakage | **New** — leaked system prompts expose logic/secrets | New 2025 entry |
| LLM08 | Vector and Embedding Weaknesses | **New** — RAG/vector DB poisoning, embedding inversion, cross-tenant leakage | New 2025 entry |
| LLM09 | Misinformation | Hallucinations/overreliance causing harmful decisions | Replaced "Overreliance" framing |
| LLM10 | Unbounded Consumption | Resource/cost DoS, model extraction, wallet-drain loops | Expanded from "Model DoS" |

Items dropped/folded from 2023: standalone "Insecure Plugin Design," "Model Theft" (now under Supply Chain/Unbounded Consumption), and "Overreliance" (now Misinformation).

### Prompt injection — the unsolved core (LLM01)

As of 2026 there is **still no reliable, general defense**. Simon Willison's framing remains the consensus: models cannot distinguish instructions from data, and "99% in application security is a failing grade" ([airia](https://airia.com/ai-security-in-2026-prompt-injection-the-lethal-trifecta-and-how-to-defend/)). The **lethal trifecta** — (1) access to private data, (2) exposure to untrusted content, (3) ability to exfiltrate — is the key heuristic: an agent with all three is exploitable. Best current mitigations are architectural, not model-based:
- **Dual-LLM / CaMeL pattern** ([InfoQ on DeepMind CaMeL](https://www.infoq.com/news/2025/04/deepmind-camel-promt-injection/)): a privileged LLM never sees untrusted content; a quarantined LLM processes it with no tools/state and returns structured, labeled data. CaMeL adds capability-based data-flow control.
- **Spotlighting** (delimiting/encoding untrusted spans to signal provenance) — helps but is bypassable.
- **"Agents Rule of Two"** ([Simon Willison, 2026](https://simonw.substack.com/p/new-prompt-injection-papers-agents)): an agent should have at most two of {untrusted input, access to sensitive systems, ability to change state/communicate externally} without human approval.
Treat detection/classifier filters as defense-in-depth only, never as a control boundary.

### Improper Output Handling (LLM05) — the highest-yield code-review target

This is where prompt injection becomes RCE/SQLi/XSS. Per [OWASP LLM05](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/), treat **all model output as untrusted user input**. Dangerous sinks to grep for:
- `eval()` / `exec()` / `Function()` / `os.system` / `subprocess`/`child_process.exec` fed by model output → RCE (e.g. CVE-2024-8309 in LangChain: model-generated SQL via an exec path).
- String-concatenated SQL/NoSQL/Cypher from model output → injection (use parameterized queries only).
- Model output rendered as HTML/Markdown without sanitization → stored/reflected XSS (sanitize + strict CSP).
- Model output into file paths → path traversal; into URLs for `fetch`/`requests` → SSRF; into template engines → SSTI; into `pickle`/`yaml.load`/`Marshal` → unsafe deserialization.
Enforce structured output (JSON schema / function-call args) and validate it before any sink.

### MCP (Model Context Protocol) security in 2026

The [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) (beta, led by Vandana Verma Sehgal) is the first standard taxonomy: MCP01 Token Mismanagement & Secret Exposure, MCP02 Privilege Escalation, MCP03 Tool Poisoning, MCP04 Supply Chain/Dependency Tampering, MCP05 Command Injection, MCP07 Insufficient AuthN/AuthZ, MCP08 Lack of Telemetry, MCP09 Shadow Servers, MCP10 Context Over-Sharing. Key risks ([Checkmarx](https://checkmarx.com/zero-post/11-emerging-ai-security-risks-with-mcp-model-context-protocol/)):
- **Tool poisoning**: malicious instructions hidden in tool *descriptions/schemas* (model-visible, human-invisible). The MCPTox benchmark found most of 20 agents across 45 servers vulnerable.
- **Confused deputy**: MCP server acting as OAuth proxy uses another user's credentials; every action must be bound to explicit, validated user context.
- **Prompt injection via tool results**: tool output is untrusted content — same trifecta logic applies.
- **Token/secret exposure**: secrets in logs, model context, or tool outputs.
- **Over-broad scopes / rug pulls / typosquatting / tool shadowing**: pin and review tool/manifest updates; require approval for behavior changes; verify provenance.

The [MCP authorization spec (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) hardened auth: MCP servers are OAuth Resource Servers; clients **MUST** use Resource Indicators (RFC 8707) to bind tokens to a canonical server URI; servers **MUST NOT** pass through tokens and **MUST** validate token audience. No-token-passthrough is now a hard review check.

### Agentic security — OWASP Top 10 for Agentic Applications (Dec 2025 / 2026)

The [Agentic Top 10](https://www.indusface.com/learning/owasp-top-10-agentic-ai/) (reviewed by NIST, Turing Institute, Microsoft AI Red Team, AWS) governs autonomous systems: ASI01 Agent Goal Hijack, ASI02 Tool Misuse/Exploitation, ASI03 Identity & Privilege Abuse, ASI04 Agentic Supply Chain, ASI05 Unexpected Code Execution (RCE), ASI06 Memory & Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents. Guiding principle: **least agency** — "the threat is not malfunction, it is the misuse of normal behavior." Controls: distinct short-lived per-agent identity, human-in-the-loop for high-impact actions (money, admin, customer-data writes, code exec), sandboxed code execution (no `eval`, gated shell), validation between autonomous stages, circuit breakers/blast-radius limits, and monitoring *what agents do* not just *what they say*. Context: 88% of orgs deploying agents reported security incidents ([Help Net Security, 2026](https://www.helpnetsecurity.com/2026/02/23/ai-agent-security-risks-enterprise/)).

### RAG / Vector & Embedding security (LLM08 / ASI06)

RAG is "the forgotten attack surface." Threats ([Christian Schneider](https://christian-schneider.net/blog/rag-security-forgotten-attack-surface/), [Mend](https://www.mend.io/blog/vector-and-embedding-weaknesses-in-ai-systems/)):
- **Knowledge-base poisoning**: PoisonedRAG showed 5 malicious docs in millions → 90% attacker-controlled answers; poisoning ChromaDB+LangChain stacks works ~95% of the time.
- **Indirect prompt injection** via retrieved docs/tool output (Slack AI, ChatGPT memory incidents).
- **Embedding inversion**: vectors reconstruct source text; encrypt/access-control vector stores, rate-limit bulk reads.
- **Cross-tenant leakage**: semantic overlap + weak isolation leaks Tenant B docs to Tenant A; ANN indexes leak distribution via timing. Strongest control = physical per-tenant DB isolation, minimum = enforced namespace + per-query tenant filter at the DB layer, plus cross-tenant retrieval tests.

### Actionable code-review checklist (apply per PR/repo)

**Output handling (LLM05/MCP05/ASI05) — highest priority:**
- [ ] No model/tool output reaches `eval`/`exec`/`Function`/`os.system`/`subprocess`/`child_process` without sandboxing + allowlist.
- [ ] All DB access from model output uses parameterized queries/ORM bindings (no string concat).
- [ ] Model output rendered to UI is sanitized (DOMPurify/equivalent) and served under a strict CSP.
- [ ] Model output into file paths, URLs (SSRF), templates (SSTI), deserializers is validated against allowlists.
- [ ] Structured outputs validated against a schema before use.

**Prompt injection & agency (LLM01/06, ASI01/02):**
- [ ] Untrusted content (RAG docs, web, emails, tool results) is segregated/labeled, never concatenated raw into instruction context.
- [ ] Check the lethal trifecta / Rule-of-Two: no path combines private data + untrusted input + exfiltration without human approval.
- [ ] High-impact tools (payments, deletes, sends, admin) require human-in-the-loop or out-of-band confirmation.
- [ ] Tools follow least privilege; no over-scoped filesystem/network access.

**MCP & tools (MCP01/02/03/07):**
- [ ] No `resource`/token passthrough; tokens audience-validated (RFC 8707).
- [ ] Tool descriptions/schemas reviewed for injected instructions; tool sources pinned and provenance-verified.
- [ ] Every tool action bound to explicit, validated user identity (no confused deputy).

**Secrets & disclosure (LLM02/07, MCP01):**
- [ ] No secrets/API keys/PII in prompts, system prompts, tool outputs, or logs; secrets from a vault, scrubbed from model context and logs.
- [ ] System prompts contain no sensitive logic/keys; assume they will leak.

**Resource & cost (LLM10):**
- [ ] Token/iteration caps, recursion/loop limits, per-user rate limits, and budget circuit breakers on agent loops and tool chains.

**RAG/vector (LLM08/ASI06):**
- [ ] Write access to knowledge bases controlled; ingested content validated.
- [ ] Per-tenant isolation enforced at the DB layer; vector store access-controlled/encrypted; cross-tenant retrieval tested.

**Supply chain (LLM03/MCP04/ASI04):**
- [ ] Models, datasets, adapters, and MCP servers/deps come from verified sources with integrity checks and update review.

**Observability (MCP08/ASI):**
- [ ] Log tool calls, data touched, and systems reached; baseline agent behavior and alert on drift.

## Key takeaways

- The current governing standards are three OWASP lists: Top 10 for LLM Applications 2025, the OWASP MCP Top 10 (beta), and the OWASP Top 10 for Agentic Applications (Dec 2025/2026) — a generic agent should map findings to all three.
- Prompt injection (LLM01) has NO reliable general fix in 2026; defenses are architectural (dual-LLM/CaMeL, spotlighting, least-agency) — never trust a classifier/filter as a security boundary since '99% is a failing grade'.
- Use the 'lethal trifecta' and 'Agents Rule of Two' as the single most portable review heuristic: flag any code path combining private-data access + untrusted input + an exfiltration/state-change channel without human approval.
- Improper Output Handling (LLM05) is the highest-yield code-level check and is language-agnostic: grep for model/tool output flowing into eval/exec/subprocess (RCE), string-concatenated SQL (SQLi), unsanitized HTML/Markdown (XSS), file paths (traversal), URLs (SSRF), templates (SSTI), and deserializers — works identically in TS/Go/Python/Java.
- Treat ALL model output AND all tool/RAG results as untrusted user input; enforce schema-validated structured output before any sink.
- MCP-specific checks: no token passthrough (RFC 8707 audience binding), review tool descriptions/schemas for hidden injected instructions (tool poisoning), bind every action to a validated user identity (confused deputy), pin/verify tool provenance (rug pulls/typosquatting).
- Agentic-specific checks: least agency, distinct short-lived per-agent identities, human-in-the-loop for money/admin/data-write/code-exec, sandboxed code execution (ban eval, gate shell), circuit breakers and validation between autonomous stages to stop cascading failures.
- RAG/vector security applies to any project with embeddings: knowledge-base poisoning (5 docs can flip answers 90%), indirect prompt injection via retrieved docs, embedding inversion, and cross-tenant leakage — require DB-layer tenant isolation and access-controlled/encrypted vector stores.
- Secrets hygiene is cross-cutting: no keys/PII in prompts, system prompts, tool outputs, or logs; assume system prompts WILL leak (LLM07), so they must carry no sensitive logic or credentials.
- Unbounded Consumption (LLM10) matters for cost/DoS in agent loops: require token/iteration caps, recursion limits, rate limits, and budget circuit breakers — a frontend/backend-agnostic check.
- Supply chain now spans models, datasets, LoRA adapters, MCP servers, and deps — require verified sources, integrity checks, and review of behavior-changing updates even from trusted maintainers.
- Observability is a control, not a nicety: monitor what agents DO (tools called, data touched, systems reached), not just what they say; baseline behavior and alert on drift (rogue-agent / goal-hijack detection).

## Sources

- https://genai.owasp.org/llm-top-10/
- https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/
- https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- https://owasp.org/www-project-mcp-top-10/
- https://checkmarx.com/zero-post/11-emerging-ai-security-risks-with-mcp-model-context-protocol/
- https://www.indusface.com/learning/owasp-top-10-agentic-ai/
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- https://www.infoq.com/news/2025/04/deepmind-camel-promt-injection/
- https://simonw.substack.com/p/new-prompt-injection-papers-agents
- https://airia.com/ai-security-in-2026-prompt-injection-the-lethal-trifecta-and-how-to-defend/
- https://christian-schneider.net/blog/rag-security-forgotten-attack-surface/
- https://www.mend.io/blog/vector-and-embedding-weaknesses-in-ai-systems/
- https://www.helpnetsecurity.com/2026/02/23/ai-agent-security-risks-enterprise/
- https://www.practical-devsecops.com/owasp-mcp-top-10/
- https://focused.io/lab/improper-ai-output-handling---owasp-llm05

