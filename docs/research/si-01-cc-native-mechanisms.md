# Self-Improvement Research — si:cc-native-mechanisms

> Source: workflow `self-improving-white-hacker-research` (w3b87zsau), agent `si:cc-native-mechanisms`

## Native Claude Code Primitives for Continuous Improvement (as of June 2026)

This maps Claude Code's native extension surface onto the **Model / Harness / Context** learning-surface model. The *Context* surface is what the model reads each session (memory, skill descriptions, rules); the *Harness* surface is deterministic machinery the runtime executes regardless of what the model decides (hooks, settings, schedulers, permissions); the *Model* surface is reasoning work the model performs (reflection passes, skill authoring, memory curation). A self-improving white-hat agent uses the Harness to *capture* signal deterministically, the Model to *distill* it into knowledge, and the Context to *re-inject* it next session.

### 1. Agent Skills as a living knowledge base (Context + Model)

A skill is a directory with `SKILL.md` (required) plus optional `references/`, `examples.md`, and `scripts/`. Only the YAML `name`+`description` (capped at 1,536 chars in the listing) load at startup; the body loads when invoked, and reference files load on demand via bash Read. This **progressive disclosure** is exactly what makes a skill a scalable knowledge base: an attack-technique corpus can be megabytes on disk and cost ~0 tokens until a task touches it ([skills docs](https://code.claude.com/docs/en/skills), [best practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)).

Recommended layout for an AI-attack KB skill:

```text
~/.claude/skills/ai-attack-kb/
├── SKILL.md                 # overview + table of contents (keep <500 lines)
├── reference/
│   ├── prompt-injection.md  # loaded on demand
│   ├── data-exfil.md
│   └── tool-poisoning.md
└── scripts/
    └── check_corpus_freshness.py
```

```yaml
---
name: ai-attack-kb
description: Catalog of known LLM/agent attack techniques (prompt injection, tool poisoning, data exfil) with detection patterns. Use when reviewing agent code, MCP servers, or prompts for AI-specific security risks.
---
# AI Attack Knowledge Base
- Prompt injection → see [reference/prompt-injection.md](reference/prompt-injection.md)
- Tool/MCP poisoning → see [reference/tool-poisoning.md](reference/tool-poisoning.md)
- Data exfiltration → see [reference/data-exfil.md](reference/data-exfil.md)
```

Key rules from the best-practices doc: keep `SKILL.md` <500 lines; **references one level deep** (Claude only partial-reads nested refs with `head`); give long reference files a table of contents; **avoid time-sensitive phrasing** ("before August 2025") — use a `## Old patterns` `<details>` section so deprecated techniques don't pollute current guidance. Crucially, the doc endorses **agent self-authoring**: "Claude models understand the Skill format natively… simply ask Claude to create a Skill." The recommended loop is *Claude A* (authors/refines the skill) ↔ *Claude B* (uses it, reveals gaps) — directly implementable as a reflection subagent + slash command (below). Skills support **live change detection**: edits under `~/.claude/skills/` or project `.claude/skills/` take effect mid-session without restart, so an agent can rewrite its own KB and use it immediately. `${CLAUDE_SKILL_DIR}` lets bundled scripts resolve regardless of cwd.

### 2. File-based memory & self-editing (Context + Model)

Two systems load every session ([memory docs](https://code.claude.com/docs/en/memory)):

| | CLAUDE.md | Auto memory |
|---|---|---|
| Writer | You | Claude |
| Loaded | In full, every session | First 200 lines / 25KB of `MEMORY.md` |
| Location | `~/.claude/CLAUDE.md`, `./CLAUDE.md`, `./.claude/CLAUDE.md`, `CLAUDE.local.md`, managed policy | `~/.claude/projects/<project>/memory/` |

**Auto memory** (Claude Code v2.1.59+, on by default) is the agent's self-maintained store. It is a directory with a `MEMORY.md` index plus topic files (`debugging.md`, etc.); only the index loads at startup, topic files load on demand. Claude writes to it during a session when it judges something worth remembering ("Writing memory"). This is the *primary* native self-improvement channel: findings persist across sessions per-repo without any manual step. Files are plain markdown, auditable/editable via `/memory`. `autoMemoryDirectory` in settings.json relocates it; `autoMemoryEnabled:false` or `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` disables it.

For *curated*, hand-written knowledge use CLAUDE.md (target <200 lines) plus **`.claude/rules/`** files, which can be **path-scoped** with `paths:` frontmatter so a "review MCP servers carefully" rule only loads when touching `**/mcp/**`. `@path` imports organize but **do not save context** (imported files load in full at launch). The bundled **`consolidate-memory`** skill (and the matching `anthropic-skills:consolidate-memory`) is a native reflective pass that merges duplicates, fixes stale facts, and prunes the `MEMORY.md` index — the exact "keep the KB current" operation, runnable on a schedule.

**Safe self-editing**: memory/skills are markdown the model edits with normal Write/Edit tools, gated by permissions. The doc is explicit that CLAUDE.md/auto-memory are *context, not enforced config* — "to block an action regardless of what Claude decides, use a PreToolUse hook." So guardrails belong in the Harness layer, not memory.

### 3. Hooks — deterministic capture of traces & findings (Harness)

Hooks ([hooks docs](https://code.claude.com/docs/en/hooks)) are shell/HTTP/MCP/prompt/agent handlers the runtime fires at lifecycle events, receiving JSON on stdin. The 2026 event set is large; the most useful for a learning agent:

- **PostToolUse / PostToolUseFailure** — fire after each tool call (and failures separately). Append every command + result, or every failed exploit attempt, to a JSONL findings log. Cannot block (tool already ran) — pure capture.
- **PreToolUse** — fires before a tool; exit 2 or `permissionDecision:"deny"` blocks. Use for hard guardrails (block `rm -rf`, block writes outside the KB) *and* to log attempted-dangerous actions.
- **Stop / SubagentStop** — fire when the agent/subagent finishes; can inject `additionalContext` or block to force a follow-up. Ideal trigger for an automatic reflection nudge ("save what you learned to memory").
- **SessionStart** — inject `additionalContext` (e.g. latest CVE digest, KB freshness status) and can set `reloadSkills:true`.
- **SessionEnd** — persist the transcript/findings on exit.
- **UserPromptSubmit** — add context or block prompts.
- **InstructionsLoaded** — audit exactly which CLAUDE.md/rules loaded and why.
- **PreCompact/PostCompact** — preserve findings before context is summarized away.

Capture pattern (PostToolUse hook in `settings.json`):

```json
{
  "hooks": {
    "PostToolUse": [
      { "matcher": "Bash|mcp__.*",
        "hooks": [{ "type": "command",
          "command": "~/.claude/hooks/log-finding.sh" }] }
    ]
  }
}
```

```bash
#!/bin/bash
INPUT=$(cat)
jq -nc --arg ts "$(date -u +%FT%TZ)" \
  --arg tool "$(jq -r .tool_name <<<"$INPUT")" \
  --arg cmd  "$(jq -r '.tool_input.command // ""' <<<"$INPUT")" \
  --arg out  "$(jq -r '.tool_output // ""' <<<"$INPUT" | head -c 500)" \
  '{ts:$ts,tool:$tool,cmd:$cmd,out:$out}' >> ~/.claude/findings.jsonl
```

Hooks can also be scoped in skill/subagent frontmatter (`hooks:` field), so a "pentest" skill can carry its own capture logic. Note: the JSON field-name casing in some examples above (e.g. `match`/`PostTool`) appears in summarized output; the authoritative schema is `hooks.<EventName>[].matcher` + `hooks[]` — verify exact keys against the live doc before shipping.

### 4. Scheduled refresh — three native options (Harness)

| Mechanism | Runs on | Needs session open | Persistent | Min interval |
|---|---|---|---|---|
| **`/loop`** (bundled skill) | your machine | Yes | restored on `--resume` if unexpired | 1 min |
| **Cron / `CronCreate`** (session-scoped) | your machine | Yes (fires when idle) | 7-day expiry | 1 min |
| **Routines / `/schedule`** (cloud) | Anthropic infra | **No** | Yes | 1 hour |
| **Desktop scheduled tasks** | your machine | No | Yes | 1 min |

Session-scoped scheduling ([scheduled-tasks docs](https://code.claude.com/docs/en/scheduled-tasks), v2.1.72+) uses `CronCreate`/`CronList`/`CronDelete` with standard 5-field cron (`0 9 * * *` = 9am local). Recurring tasks **auto-expire after 7 days**; fires happen between turns, not mid-response. Good for "every 6h, run `/refresh-attack-kb`" *within* a long-running session.

For unattended, durable KB refresh, **Routines** ([blog](https://claude.com/blog/introducing-routines-in-claude-code)) are the right primitive: created via `/schedule` in the CLI or at claude.ai/code, they run on Anthropic-managed infra on a cron schedule, via per-routine API endpoint+token, or on GitHub events, with built-in repo + connector access (fresh clone, no local files). Example: *"Every night at 2am: search for new 2026 LLM-attack disclosures, update `reference/*.md`, open a draft PR."* Limits (Apr 2026): Pro 5/day, Max 15/day, Team/Enterprise 25/day; legacy `/schedule` CLI tasks are now Routines. GitHub Actions with a `schedule` trigger is a fourth path for CI-driven refresh.

### 5. Subagents for a reflection/learning pass + manual triggers (Model + Context)

Subagents ([sub-agents docs](https://code.claude.com/docs/en/sub-agents)) are `.claude/agents/<name>.md` files with frontmatter (`name`, `description`, `tools`, `model`, `permissionMode`, `skills`, `memory`, `hooks`). Two features make them the learning engine:

- **Persistent subagent memory** (`memory: user|project|local`) → `~/.claude/agent-memory/<name>/` (or project/local). On each run the first 200 lines of its `MEMORY.md` are injected, and Read/Write/Edit auto-enabled, with system-prompt instructions to curate. A dedicated `reflection` subagent accumulates "patterns/recurring issues" across sessions — a learning store independent of the main agent.
- **`skills:` preload** injects full skill content (not just description) at subagent startup, so a reviewer subagent always carries the attack KB.

A learning-pass subagent (`.claude/agents/kb-curator.md`):

```markdown
---
name: kb-curator
description: Reflects over recent findings and updates the attack KB skill. Use proactively at end of a security review.
tools: Read, Write, Edit, Grep, Glob, Bash
model: sonnet
memory: project
skills: [ai-attack-kb]
---
Read ~/.claude/findings.jsonl since last run. For each novel technique,
add/update the matching reference/*.md in the ai-attack-kb skill. Keep
SKILL.md's table of contents in sync. Record what you changed to your memory.
```

**Slash commands** to trigger learning manually are just skills with `disable-model-invocation: true` (so only you run `/refresh-attack-kb`, `/reflect`). A skill with `context: fork` + `agent: kb-curator` runs the curation in an isolated subagent. The `loop.md` file (`.claude/loop.md`) customizes the bare `/loop` maintenance prompt for self-paced background upkeep.

### 6. settings.json as harness guardrails (Harness)

[Settings](https://code.claude.com/docs/en/settings) precedence: managed > CLI > local > project > user; **`permissions` arrays merge across scopes and `deny` always wins**. For a self-editing agent, confine writes to the KB/memory and block escape:

```json
{
  "autoMemoryEnabled": true,
  "autoMemoryDirectory": "~/.claude/agent-memory",
  "permissions": {
    "allow": ["Read(./**)", "Write(~/.claude/skills/ai-attack-kb/**)",
              "Write(~/.claude/agent-memory/**)"],
    "deny":  ["Read(./.env*)", "Read(./secrets/**)", "Bash(curl *)",
              "Write(/etc/**)", "Bash(rm -rf *)"]
  },
  "hooks": { "PreToolUse": [ { "matcher": "Write|Edit",
    "hooks": [{ "type": "command", "command": "~/.claude/hooks/guard.sh" }] } ] },
  "disableSkillShellExecution": false
}
```

Managed-only keys (`allowManagedHooksOnly`, `allowManagedPermissionRulesOnly`, `strictPluginOnlyCustomization`, `disableSkillShellExecution`, `sandbox.enabled`, version pinning) let an org lock the harness. `disableSkillShellExecution:true` neutralizes `` !`cmd` `` injection in non-managed skills — relevant if the KB ingests untrusted skill content.

### What is and isn't natively possible

**Natively possible:** persistent per-repo self-written memory (auto memory); on-demand KB via skills/references with ~0 idle token cost; live skill edits mid-session; deterministic capture of every tool call/finding/failure via hooks; scheduled autonomous refresh (cloud Routines, desktop tasks, session cron, `/loop`); reflection/curation subagents with their own cross-session memory; manual learning triggers as slash commands; and hard guardrails via permissions + PreToolUse hooks. The native `consolidate-memory` skill already implements memory curation.

**Not natively possible (must be built on top):** no built-in eval harness ("there is not currently a built-in way to run these evaluations" — you write your own JSON-rubric runner); no automatic semantic dedup/ranking of KB entries (a curator subagent must do it); session cron expires at 7 days (use Routines/desktop for longer); cloud Routines get a fresh clone with **no local-file access** and a **1-hour minimum** interval; auto memory is **machine-local**, not synced across machines/cloud; subagents can't spawn subagents; and CLAUDE.md/memory are advisory, never enforcement — enforcement is hooks/permissions only.

## Key takeaways

- Auto memory (`~/.claude/projects/<project>/memory/`, v2.1.59+, on by default) is the primary native self-improvement channel: Claude writes findings itself, only the `MEMORY.md` index (200 lines/25KB) loads at startup, topic files load on demand — make the white-hat agent route durable attack-detection learnings here per-repo.
- Build the AI-attack knowledge base as a Skill with progressive disclosure: SKILL.md <500 lines as a table of contents, detailed technique files in `reference/` (one level deep, each with its own TOC), scripts in `scripts/` — costs ~0 tokens until a task triggers it; live change detection means the agent can rewrite its own KB and use it the same session.
- Capture signal deterministically with hooks the harness runs regardless of model choices: PostToolUse/PostToolUseFailure append every tool call and failed exploit to a JSONL findings log; Stop/SubagentStop inject a 'save what you learned' nudge; SessionStart injects a freshness/CVE digest and can set reloadSkills:true.
- Run a reflection/learning pass as a dedicated subagent with `memory: project` (persistent agent-memory dir) and `skills: [ai-attack-kb]` preloaded — the docs' recommended Claude-A-authors / Claude-B-uses loop maps directly onto a kb-curator subagent triggered by a slash command.
- Schedule autonomous KB refresh with the right tier: cloud Routines (`/schedule`, Anthropic infra, no machine needed, 1h min, fresh clone — no local files) for nightly disclosure scans + draft PRs; session cron/`/loop` (1min, 7-day expiry) for in-session upkeep; Desktop scheduled tasks for durable local-file access.
- The native `consolidate-memory` skill already does the 'keep KB current' job (merge duplicates, fix stale facts, prune index) — wire it into a schedule rather than reinventing memory curation.
- Avoid time-sensitive phrasing in the KB: use a `## Old patterns` <details> section for deprecated techniques so superseded attacks don't pollute current detection guidance; this is the doc-endorsed way to age out knowledge.
- Guardrails belong in the harness, never in memory: CLAUDE.md/auto-memory are advisory context the model may ignore — use PreToolUse hooks (exit 2 / permissionDecision:deny) and settings.json permissions (deny wins, merges across scopes) to confine self-writes to the KB/agent-memory dirs and block secret reads/network egress.
- Manual learning triggers are just skills with `disable-model-invocation: true` (e.g. `/refresh-attack-kb`, `/reflect`); add `context: fork` + `agent: kb-curator` to run curation in an isolated subagent context.
- Known native gaps to engineer around: no built-in eval runner (write a JSON-rubric harness yourself, eval-driven before docs), no automatic KB dedup/ranking, 7-day session-cron expiry, auto memory is machine-local (not synced), and subagents cannot spawn subagents.
- Use `.claude/rules/` with path-scoped `paths:` frontmatter for curated always-on security rules that only load when touching matching files (e.g. `**/mcp/**`, `**/*.prompt`), keeping per-session context lean while still injecting relevant guardrails.
- Verify exact hook JSON schema keys against the live doc before shipping — summarized fetches showed some inconsistent casing (e.g. `PostTool`/`match`); the authoritative shape is `hooks.<EventName>[].matcher` plus a `hooks[]` array of `{type, command}` handlers.

## Sources

- https://code.claude.com/docs/en/skills
- https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices
- https://code.claude.com/docs/en/memory
- https://code.claude.com/docs/en/hooks
- https://code.claude.com/docs/en/sub-agents
- https://code.claude.com/docs/en/scheduled-tasks
- https://claude.com/blog/introducing-routines-in-claude-code
- https://code.claude.com/docs/en/settings
- https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview

