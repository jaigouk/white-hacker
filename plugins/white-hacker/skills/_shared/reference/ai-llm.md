# AI / LLM / MCP / Agentic security appendix (inner-loop checklist)

> Loaded on demand when `sec-detect` sets `SCAN-PLAN.json` `ai_pass:true` (an LLM/agent/MCP dep is
> present). This is the **stable inner-loop checklist** (yearly cadence); the **fast, dated**
> technique tier lives in `.claude/skills/ai-attack-kb/reference/` and is loaded per-class on demand
> (`ai-llm-review` attaches each finding's `kb_refs` to those entry ids). Mapped to **OWASP Top 10
> for LLM Applications 2025**, the **OWASP MCP Top 10**, and the **OWASP Top 10 for Agentic
> Applications 2026**. Pattern-first (dangerous → safe). ≤400 lines.
>
> **The single most important stance:** treat **all model output and all tool/RAG/MCP results as
> untrusted user input** (Agents Rule of Two). The **highest-yield code check is LLM05 Improper
> Output Handling** — that is where prompt injection becomes RCE/SQLi/XSS/SSRF. **LLM01 prompt
> injection itself is architectural**, has no general fix, and is **exclusion-listed**
> (`exclusion-rules.md` rule 11) — report it as a *design note*, never as a line-level HIGH.

Category tags: `injection` `data-exposure` `AuthN/AuthZ` `ssrf` `deserialization` `xss` `resource`.

---

# 1. LLM01:2025 — Prompt Injection  (ARCHITECTURAL — design note, not a HIGH finding)
KB: `ai-attack-kb/reference/prompt-injection.md`.

Crafted input (direct, or **indirect** via retrieved docs / tool output / web / email) overrides
intended instructions. As of 2026 there is **no reliable general fix** — models cannot separate
instructions from data. Per `exclusion-rules.md` rule 11, do **not** emit "prompt injection" as a
line-level code vuln; instead flag **missing architectural defenses**:
- **Dangerous:** untrusted/retrieved content concatenated raw into the prompt or system prompt; a
  single privileged model both reading untrusted content and holding tools/secrets.
- **Safe (architectural):** dual-LLM / **CaMeL** (a quarantined, tool-less model processes untrusted
  content and returns structured, labeled data); **spotlighting** (delimit/encode untrusted spans);
  least agency. Never rely on a classifier/filter as a control boundary ("99% is a failing grade").
- Output as a **design note** with the trifecta test (§3), not a HIGH; the *reportable* consequence
  is the LLM05 sink it reaches (§2).

# 2. LLM05:2025 — Improper Output Handling  ★ HIGHEST-YIELD CODE CHECK ★
KB: `ai-attack-kb/reference/data-exfil.md` (exfil sinks) + `prompt-injection.md` (the source).

This is the reportable code bug: **model/tool/RAG output flowing into a dangerous sink** without
validation. Treat model output exactly like raw user input. Grep the sinks (language-agnostic):
- **Code exec → RCE:** model output into `eval`/`exec`/`Function()`/`os.system`/`subprocess`/
  `child_process.exec`/`ProcessBuilder`.
  - Safe: never exec model output; if unavoidable, sandbox + argv array + allowlist (no shell).
- **SQL/NoSQL → injection:** model output string-concatenated into a query.
  - Safe: parameterized queries / ORM bindings only.
- **HTML/Markdown → XSS:** model output rendered to the DOM (`innerHTML`, `dangerouslySetInnerHTML`,
  `v-html`, auto-rendered markdown).
  - Safe: sanitize (DOMPurify) + strict CSP; block `javascript:`/`data:` URLs.
- **File path → traversal**, **URL → SSRF** (cross-link `core-checklist.md` §3 / `api.md` API7),
  **template → SSTI**, **`pickle`/`yaml.load`/`Marshal`/`readObject` → unsafe deserialization**.
- **Categorize as `improper-output-handling`** whenever the tainted *source* is model / tool / RAG
  output — **even when the sink is SSRF / SQLi / XSS / path / SSTI / deser.** The sink-specific
  category (`ssrf`, `injection`, `xss`, …) is for *user-input* sources; a **model-output** source rolls
  up to LLM05 (the AI root cause). E.g. a model-chosen URL passed to `requests.get` is
  `improper-output-handling`, not `ssrf`.
- Rule: **enforce structured output (JSON schema / function-call args) and validate it BEFORE any
  sink.** A schema-validated structured value used in a parameterized call is the clean look-alike —
  it must NOT be flagged.

# 3. Lethal trifecta / Agents Rule of Two  (architectural test)
KB: `prompt-injection.md` + `excessive-agency.md` + `data-exfil.md`.

The single most portable heuristic. An agent path is exploitable when it combines **all three**:
1. access to **private data**, 2. exposure to **untrusted content**, 3. an **exfiltration /
state-change** channel — without human approval. "**Agents Rule of Two**": hold at most two of these
unattended; the third requires a human gate or hard isolation.
- **Test each agent/tool path:** does it hold ≥2 legs? If all 3 → architectural HIGH-risk design
  note (which leg to cut: quarantine untrusted input, drop the egress, or gate the data).

# 4. MCP — token passthrough / tool poisoning / confused deputy
KB: `ai-attack-kb/reference/tool-poisoning.md`.

- **Token passthrough (forbidden):** the server forwards the caller's incoming token to a downstream
  API. Safe: the MCP server validates token **audience** (RFC 8707 Resource Indicators, per the MCP
  auth spec 2025-11-25) and mints its own downstream credential — **never** passes the token through.
- **Tool poisoning:** instructions hidden in a tool's `description`/schema (model-visible,
  human-invisible). Safe: review tool metadata as untrusted; pin tool/manifest provenance (rug
  pulls, typosquatting); require approval for behavior-changing updates.
- **Confused deputy:** a tool/OAuth-proxy acting with another principal's credentials. Safe: bind
  every tool action to the **validated calling user's** identity.

# 5. RAG / Vector & Embedding (LLM08:2025) + cross-tenant leakage
KB: `ai-attack-kb/reference/rag-poisoning.md`.

- **Knowledge-base / vector poisoning:** a few malicious docs flip answers; also an **indirect
  prompt-injection** vector. Safe: control write access to the KB; validate/attribute ingested
  content; label retrieved content (don't concatenate raw into instructions).
- **Cross-tenant leakage:** Safe: enforce a per-tenant namespace + per-query tenant filter at the DB
  layer (ideally physical isolation); add a cross-tenant retrieval test.
- **Embedding inversion:** vectors reconstruct source text → encrypt/access-control the store,
  rate-limit bulk reads. Agent **memory poisoning** (ASI06) is the same class.

# 6. LLM10:2025 — Unbounded Consumption  (advisory-tier unless concrete impact)
KB: `ai-attack-kb/reference/excessive-agency.md` (loop limits).

Resource/cost DoS, model extraction, wallet-drain loops. Per `exclusion-rules.md`, report only with
a concrete amplification/complexity impact (not "missing rate limit" alone).
- Safe: token/iteration caps and recursion/loop limits on agent loops and tool chains; per-user rate
  limits; budget circuit breakers; output/where appropriate input size caps.

# 7. LLM06:2025 — Excessive Agency  (least agency)
KB: `ai-attack-kb/reference/excessive-agency.md`.

Too much autonomy/permission/tooling. The agentic-Top-10 framing: "the threat is not malfunction, it
is the misuse of normal behavior."
- **Dangerous:** high-impact tools (payments, deletes, sends, admin, shell/code-exec) callable by the
  agent with no human-in-the-loop; over-broad tool scopes; a shared long-lived god-credential.
- **Safe:** least-privilege per tool; distinct short-lived per-agent identity; **human-in-the-loop**
  for money/admin/data-write/code-exec; validation + **circuit breakers** between autonomous stages.

# 8. Sensitive information disclosure (LLM02:2025 / LLM07 System-Prompt Leakage)
KB: `ai-attack-kb/reference/data-exfil.md`.

- No secrets/API keys/PII in prompts, system prompts, tool outputs, or logs; pull secrets from a
  vault and scrub them from model context and logs.
- **Assume system prompts leak (LLM07):** they must carry no sensitive logic or credentials.

---

## How discovery / triage uses this appendix
`ai-llm-review` partitions the surface (system prompt / tool defs / RAG ingestion / **output
sinks** / MCP surface), then sweeps each section above. **Lead with LLM05** (§2) — it is the
highest-yield, reportable code check. Treat **LLM01 as an architectural design note** (§1, exclusion
rule 11), not a HIGH. For every candidate, attach `kb_refs` to the matching `ai-attack-kb` entry id,
and record `{file, line, category, source, sink, why-reachable}`. Severity is decided in triage
(`severity-rubric.md`), never here. The clean structured-output look-alike (schema-validated before
the sink) is **not** a finding.
