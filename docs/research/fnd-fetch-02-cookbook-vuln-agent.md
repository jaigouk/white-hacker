# fetch:cookbook-vuln-agent

> Source: workflow `white-hacker-research` (wycjclbk6), agent `fetch:cookbook-vuln-agent`

## The Anthropic "Vulnerability Detection Agent" Cookbook: Concrete Agent Design

The cookbook ([`06_The_vulnerability_detection_agent.ipynb`](https://github.com/anthropics/claude-cookbooks/tree/main/claude_agent_sdk), also at [platform.claude.com](https://platform.claude.com/cookbook/claude-agent-sdk-06-the-vulnerability-detection-agent)) builds a memory-safety bug hunter for a C "canary" target using the [Claude Agent SDK](https://platform.claude.com/docs/en/agent-sdk/python). It is deliberately minimal: **built-in Claude Code file tools (`Read`/`Grep`/`Glob`) scoped to a target directory are the entire scaffold** — no custom MCP server, no external scanner. The reusable lesson for a generic Claude Code security agent is the *pipeline shape and the prompt discipline*, not the C/ASAN specifics.

### Pipeline: Threat-Model -> Find -> Triage -> Report

A 4-stage sequential pipeline, with prior-stage output injected as text into the next stage's prompt (no message bus, just string interpolation):

| Stage | SDK primitive | Tools | Output |
|---|---|---|---|
| 1. Threat model (bootstrap + interview) | `ClaudeSDKClient` (multi-turn) | `Read, Write, Edit` (Bash disallowed) | `THREAT_MODEL.md` |
| 2. Find | `query()` (one-shot) | `Read, Grep, Glob` | XML-tagged findings |
| 3. Triage | `query()` | `Read, Grep` | Markdown verdict table |
| 4. Report | `query()` | none (`allowed_tools=[]`) | Strict JSON |

The notebook explicitly notes the design rationale: "one multi-turn `ClaudeSDKClient` session for the threat model and three one-shot `query()` calls for the rest." Threat-modeling uses a persistent client so the **interview turn inherits the bootstrap turn's `Read` tool outputs** without re-sending source; the later stages are stateless because their inputs are self-contained.

### SDK wiring (exact options)

All stages share one composition pattern. The system prompt inherits Claude Code's preset and appends an engagement-authorization preamble:

```python
system_prompt={"type": "preset", "preset": "claude_code", "append": ENGAGEMENT_CONTEXT}
```

Note: as of Agent SDK v0.1.0, the `claude_code` preset is **no longer applied by default** — you must opt in explicitly ([modifying-system-prompts docs](https://platform.claude.com/docs/en/agent-sdk/modifying-system-prompts)). Per-stage options:

```python
# Threat model — multi-turn, can write files
tm_options = ClaudeAgentOptions(
    model=MODEL_NAME,                 # "claude-opus-4-7"
    cwd=str(TARGET_DIR),
    system_prompt={"type":"preset","preset":"claude_code","append":ENGAGEMENT_CONTEXT},
    allowed_tools=["Read","Write","Edit"],
    disallowed_tools=["Bash"],
    permission_mode="acceptEdits",
)
async with ClaudeSDKClient(options=tm_options) as tm_agent:
    await tm_agent.query(BOOTSTRAP_PROMPT); draft = await collect(tm_agent.receive_response())
    await tm_agent.query(INTERVIEW_PROMPT); await collect(tm_agent.receive_response())

# Find / Triage / Report — stateless query(), progressively fewer tools
find_options   = ClaudeAgentOptions(..., allowed_tools=["Read","Grep","Glob"], disallowed_tools=["Bash"])
triage_options = ClaudeAgentOptions(..., allowed_tools=["Read","Grep"],        disallowed_tools=["Bash"])
report_options = ClaudeAgentOptions(..., allowed_tools=[])
findings_text = await collect(query(prompt=FIND_PROMPT,   options=find_options))
triaged_text  = await collect(query(prompt=TRIAGE_PROMPT, options=triage_options))
report_json   = await collect(query(prompt=REPORT_PROMPT, options=report_options))
```

Model: `MODEL_NAME = "claude-opus-4-7"` (a real 2026 Opus ID — the 2026 migration guidance is "Replace Opus 4 with `claude-opus-4-7`"). A single model is used across all stages.

A shared `collect()` helper drains the async message stream, prints `ToolUseBlock` calls for observability, accumulates `TextBlock` text, and raises `RuntimeError` on a `ResultMessage` with `is_error` — a clean reusable stream-handling utility.

### Prompts — the load-bearing design

**Engagement context** (appended to every stage) establishes scope/authorization so the agent stays in defensive posture: "This is authorized security research conducted as a defensive security assessment on a self-contained canary target... The target is read-only source (no execution)."

**Bootstrap** asks for a draft threat model from source alone with an explicit "section 5: Open questions" listing what could NOT be determined — that section becomes the owner-interview agenda. **Interview** feeds `OWNER_ANSWERS` back to refine likelihood/impact and resolve open questions, then writes `THREAT_MODEL.md`.

**Find** carries the most reusable idea — an explicit **quality-tier rubric** that the cookbook calls "most of the difference between a report a security engineer acts on and one they ignore":
- HIGH VALUE (report): heap-buffer-overflow (esp. WRITE), use-after-free/double-free, stack/global-buffer-overflow
- LOW VALUE (note but keep looking): assertion failures, recursion DoS, null-deref at fixed small offsets

Findings are emitted as `<finding>` XML blocks with `id`, `file` (path:line), `category`, and a `description` covering root cause / attacker control / trigger condition.

**Triage** re-verifies each finding against source ("cite the line"), **re-derives severity from reachability across the trust boundaries in the threat model** rather than trusting the find agent's scores, and collapses duplicates by root cause — an independent pass that "catches overconfidence cheaply."

**Report** converts triaged text into JSON conforming to a strict schema where *every* field is `required` and `null` means "not applicable" (prevents silent field-dropping), with severity constrained to `enum: ["critical","high","medium","low"]`. The prompt demands "JSON only, no surrounding prose or code fences."

### "Subagents"

There are **no named subagent classes**. Each stage *is* an agent, distinguished only by its `ClaudeAgentOptions` (tool allowlist + prompt). This is the key reusable pattern: model a multi-step security review as a sequence of narrowly-scoped agent invocations, each with the minimum tools it needs, handing off via injected text.

## Production extension: the defending-code reference harness

The cookbook's production sibling is [`anthropics/defending-code-reference-harness`](https://github.com/anthropics/defending-code-reference-harness), which packages the same loop two ways:

1. **Six interactive Claude Code skills** in `.claude/skills/`: `/threat-model`, `/vuln-scan`, `/triage`, `/patch`, `/customize`, `/quickstart`. These run read/write only (no execution). Outputs are `THREAT_MODEL.md`, `VULN-FINDINGS.{json,md}`, `TRIAGE.{json,md}`, `PATCHES/`. Notably, `/triage` "correctly excludes bugs in test/fixture code," and `/customize` ports the pipeline to new languages.

2. **An autonomous sandboxed pipeline** (`bin/vp-sandboxed run <target> --runs 3 --parallel --stream --auto-focus`) of 7 stages — Build (compile w/ ASAN) -> Recon (partition attack surface) -> Find (N parallel agents, each in its own gVisor container) -> Verify (grader reproduces each crash in a fresh container) -> Dedupe (judge) -> Report -> Patch (patch agent + grader re-validates). Each agent runs in a **gVisor container with egress restricted to the Claude API only**; "only the PoC crosses from find agent to grader; the container state doesn't," which cuts false positives. Subagents can be pinned with `CLAUDE_CODE_SUBAGENT_MODEL=<model-id>` for reproducibility.

The harness frames language-porting around four questions, directly relevant to a multi-language agent: **What signals a finding? What's the PoC format? How do you build+run? What's the detector?** (For C/C++ the answers are ASAN crash signature / crashing input / Dockerfile+clang / ASAN; for a web service they become exception-or-canary / HTTP request sequence / container build / your instrumentation.)

## Managed product

[Claude Security](https://www.anthropic.com/product/security) is the managed version of this same find-and-triage capability — point it at a repo and Anthropic handles sandboxing/scaling. Its four stages mirror the cookbook: **Find** (traces data flows across files to catch logic and access-control flaws pattern-matchers miss), **Validate** (multi-stage verification, false-positive filtering, severity assignment), **Suggest fixes** (targeted patches that open in Claude Code for human review before shipping), and **Schedule** (scheduled scans with webhook integration). Anthropic cites this approach surfacing "over 500 previously unknown vulnerabilities" in open-source software.


## Key takeaways

- Use a 4-stage pipeline as the backbone: Threat-model -> Find -> Triage -> Report. The threat model scopes the scan ('aim before you shoot'); a separate triage pass re-verifies and re-scores findings independently, which catches the find agent's overconfidence cheaply.
- Model each stage as its own agent invocation distinguished only by ClaudeAgentOptions (tool allowlist + prompt) — there are no named subagent classes. Hand off between stages by injecting the prior stage's text output into the next prompt; no message bus needed.
- Pick the SDK primitive by statefulness: ClaudeSDKClient (multi-turn) only when a later turn must inherit earlier tool transcripts (e.g. threat-model bootstrap->interview); stateless query() for self-contained one-shots (find/triage/report).
- Enforce least privilege per stage via allowed_tools/disallowed_tools and taper tools down the pipeline: explore stages get Read/Grep/Glob, verify stages get Read/Grep, the report stage gets allowed_tools=[] (pure reasoning). Disallow Bash/execution unless running inside a sandbox.
- Built-in Read/Grep/Glob scoped to a target directory (cwd) is a sufficient read-only scanning scaffold for any language — no custom MCP server or external SAST tool is required to get value.
- A quality-tier rubric in the find prompt (explicit HIGH VALUE vs LOW VALUE categories, 'note but keep looking') is the single highest-leverage prompt element — it is the difference between a report an engineer acts on and one they ignore. Generalize the tiers per stack (e.g. authz/SSRF/injection for web, prompt-injection/tool-misuse for AI apps).
- Derive severity from reachability across the threat model's trust boundaries in the triage stage, not from the find agent's self-assessed scores; require each verdict to cite a source line and collapse duplicates by root cause.
- Always append an explicit engagement/authorization + scope preamble to the system prompt to keep the agent in a defensive, read-only-by-default posture, and opt into the 'claude_code' system-prompt preset explicitly (Agent SDK v0.1.0+ no longer applies it by default).
- Force structured output with a strict JSON schema where every field is required and null means 'not applicable' (severity as an enum), and demand 'JSON only, no code fences' — this prevents silently dropped findings and makes results machine-consumable by downstream tools/webhooks.
- Triage should explicitly exclude findings in test/fixture code — a known false-positive source the reference harness's /triage skill calls out.
- For execution-verified scanning (running PoCs), isolate each agent in its own sandbox (gVisor) with egress restricted to the Claude API, run N find agents in parallel, and pass only the PoC artifact (not container state) to a separate grader agent that reproduces in a fresh container — this is the false-positive-reduction pattern.
- Make the pipeline language-portable by parameterizing four questions: what signals a finding, the PoC format, how to build+run, and the detector. Pin subagent models (CLAUDE_CODE_SUBAGENT_MODEL) for reproducibility, and use claude-opus-4-7 (the 2026 Opus ID) for the reasoning-heavy threat-model/triage stages.

## Sources

- https://platform.claude.com/cookbook/claude-agent-sdk-06-the-vulnerability-detection-agent
- https://github.com/anthropics/claude-cookbooks/tree/main/claude_agent_sdk
- https://github.com/anthropics/defending-code-reference-harness
- https://www.anthropic.com/product/security
- https://platform.claude.com/docs/en/agent-sdk/modifying-system-prompts
- https://platform.claude.com/docs/en/agent-sdk/python
- https://github.com/anthropics/claude-agent-sdk-python

