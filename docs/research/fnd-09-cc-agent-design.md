# research:cc-agent-design

> Source: workflow `white-hacker-research` (wycjclbk6), agent `research:cc-agent-design`

## Claude Code Agent / Subagent / Skill Design Best Practices (2026)

This section synthesizes Anthropic's 2026 documentation on how to structure subagents, skills, and slash commands, and how to assemble a reusable, project-agnostic security-review agent that composes into a TL/QA/Dev/white-hacker team workflow.

### 1. Subagent definition files: structure and frontmatter

A subagent is a Markdown file with YAML frontmatter; the body becomes the subagent's system prompt (it does *not* receive the full Claude Code system prompt). Files live at four scopes, resolved by priority when names collide: managed settings (org), `--agents` CLI flag (session), `.claude/agents/` (project, check into VCS), `~/.claude/agents/` (user, all projects), and a plugin's `agents/` directory (lowest). Identity comes only from the `name` field, not the file path ([Create custom subagents](https://code.claude.com/docs/en/sub-agents)).

Only `name` and `description` are required. The full supported field set as of 2026:

| Field | Purpose |
|---|---|
| `name` | lowercase-hyphen unique id; hooks receive it as `agent_type` |
| `description` | when Claude should delegate (drives automatic invocation) |
| `tools` | allowlist (inherits all if omitted) |
| `disallowedTools` | denylist (applied before `tools`) |
| `model` | `sonnet`/`opus`/`haiku`, full id (e.g. `claude-opus-4-8`), or `inherit` (default) |
| `permissionMode` | `default`, `acceptEdits`, `auto`, `dontAsk`, `bypassPermissions`, `plan` |
| `skills` | preloads full skill content into context at startup |
| `mcpServers`, `hooks` | scoped MCP/lifecycle hooks (ignored for plugin subagents) |
| `memory` | `user`/`project`/`local` persistent cross-session memory dir |
| `maxTurns`, `effort`, `isolation: worktree`, `background`, `color`, `initialPrompt` | execution controls |

`permissionMode`, `mcpServers`, and `hooks` are **ignored for plugin subagents** for security reasons — relevant if you distribute the security agent as a plugin.

### 2. SKILL.md format and progressive disclosure

A skill is a directory with a required `SKILL.md` (YAML frontmatter + Markdown body) plus optional supporting files. Locations: enterprise (managed), `~/.claude/skills/<name>/` (personal), `.claude/skills/<name>/` (project), and `<plugin>/skills/<name>/`. The directory name becomes the `/command` you type; the `name` frontmatter is only a display label (except for a plugin-root SKILL.md). Custom commands have been **merged into skills** — `.claude/commands/foo.md` and `.claude/skills/foo/SKILL.md` both create `/foo` ([Extend Claude with skills](https://code.claude.com/docs/en/skills)).

Skill frontmatter (all optional, `description` recommended): `name`, `description`, `when_to_use`, `argument-hint`, `arguments`, `disable-model-invocation`, `user-invocable`, `allowed-tools`, `disallowed-tools`, `model`, `effort`, `context: fork`, `agent`, `hooks`, `paths`, `shell`. The combined `description`+`when_to_use` is truncated at 1,536 chars in the listing — **put the key use case first**.

**Progressive disclosure operates in three stages**: (1) only metadata (name+description, ~100 tokens) is preloaded at startup; (2) the full SKILL.md body loads when the skill is invoked/relevant; (3) bundled reference files and scripts load only when SKILL.md points to them. Authoring rules ([Skill authoring best practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)): keep SKILL.md **under 500 lines**; split large content into one-level-deep reference files (`reference/finance.md`); give reference files >100 lines a table of contents; use forward-slash paths; prefer utility scripts (executed, not loaded) for deterministic work; avoid time-sensitive claims and "too many options."

### 3. Skills vs. subagents vs. slash commands

| | Slash command / skill | Subagent | Agent team |
|---|---|---|---|
| Context | Runs **inline** in main conversation | **Own context window**, returns summary only | Each teammate **fully independent** context |
| Communication | n/a | Reports back to caller only | Teammates **message each other** + shared task list |
| Best for | Reusable prompts/checklists/procedures | Verbose/self-contained work, tool isolation | Parallel work needing discussion |

Anthropic's guidance: use a **skill** for reusable prompts/workflows in the main context; a **subagent** to isolate verbose output or enforce tool restrictions; **agent teams** when workers must collaborate. A skill can bridge into subagent context via `context: fork` + `agent:`, and a subagent can pull skills via its `skills:` field ([skills-explained](https://claude.com/blog/skills-explained)). Note `disable-model-invocation: true` = user-only (manual `/cmd`); `user-invocable: false` = Claude-only (background knowledge).

### 4. Restricting tools for safety

Two complementary mechanisms. For subagents: `tools` (allowlist) or `disallowedTools` (denylist); the canonical read-only reviewer uses `tools: Read, Grep, Glob, Bash` (no Write/Edit). For finer control, a `PreToolUse` hook can validate individual Bash commands and `exit 2` to block them (e.g. allow SELECT, block INSERT/UPDATE/DELETE). For skills, `allowed-tools` *pre-approves* listed tools (does not restrict), while `disallowed-tools` removes tools from the pool. Session-wide, deny `Skill` or `Agent(name)` in `permissions.deny`. Use `bypassPermissions` only with extreme caution. Best-practice quote: "Limit tool access: grant only necessary permissions for security and focus."

### 5. Multi-agent / team patterns (TL/QA/Dev/white-hacker)

Agent teams are **experimental**, enabled with `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` (v2.1.32+). A **team lead** spawns **teammates** (each a full independent Claude session), coordinating via a **shared task list** (pending/in-progress/completed with dependencies) and a **mailbox** (`SendMessage`). Crucially, **a teammate can be spawned from a subagent definition** — its `tools` allowlist and `model` apply, and its body is appended to the teammate's prompt — so a single `security-reviewer` definition is reusable both as a delegated subagent *and* as a team member ([agent teams](https://code.claude.com/docs/en/agent-teams)).

This maps cleanly to a TL/QA/Dev/white-hacker workflow: the **lead = TL** breaks work into tasks; **Dev** teammates implement (consider `permissionMode` requiring plan approval for risky changes); **QA** validates tests; the **white-hacker** uses the `security-reviewer` definition to audit in parallel. Quality gates are enforceable via `TaskCompleted`/`TeammateIdle` hooks (`exit 2` to send feedback and keep working). Caveats: teammates **load CLAUDE.md/skills/MCP but not the lead's conversation history**, so put task detail in the spawn prompt; subagent `skills`/`mcpServers` fields do **not** apply on the teammate path; start with **3–5 teammates**; assign distinct, non-overlapping file ownership to avoid conflicts. For non-collaborative parallel review, plain subagents are cheaper.

### 6. Structuring a reusable, project-agnostic security-review agent

Anthropic ships a built-in `/security-review` skill and an open-source reference at [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review). Its design is a strong template for a project-agnostic white-hat agent:

- **Vulnerability taxonomy** (language-agnostic): Input Validation (SQLi, command injection, XXE, template/NoSQL injection, path traversal); AuthN/AuthZ (bypass, privilege escalation, session/JWT flaws); Crypto & Secrets (hardcoded creds, weak algorithms, cert-validation bypass); Code Execution (insecure deserialization, pickle/YAML, eval injection, XSS); Data Exposure (sensitive logging, PII, API key leakage).
- **Three-phase methodology**: (1) research repo context/existing security patterns, (2) compare new code against established secure practices, (3) trace data flows through injection points.
- **High-confidence bias + false-positive filtering**: keep only findings with confidence ≥8; explicitly exclude DoS, rate-limiting gaps, generic hardening, memory-safety issues in memory-safe languages, and theoretical races. Report HIGH/MEDIUM only.
- **Structured output**: per finding — file location, severity, category, description, exploit scenario, remediation.

To make it **project-agnostic and composable**: define it once as `~/.claude/agents/security-reviewer.md` (user scope) or a plugin so it works across TS/Go/Python/Java and backend/frontend/AI repos; set `tools: Read, Grep, Glob, Bash` and `model: opus` (or `inherit`) for deep reasoning with no write access; rely on `git diff` for diff-aware scanning rather than hardcoded paths; keep the taxonomy in SKILL.md but push language-specific checklists into one-level-deep reference files loaded on demand; enable `memory: project` so it accumulates per-repo patterns. The same definition then drives the local `/security-review`, a delegated subagent, the white-hacker teammate in an agent team, and the [GitHub Action](https://www.anthropic.com/news/automate-security-reviews-with-claude-code) for PR-time CI gating.

## Key takeaways

- Define the security agent ONCE as a Markdown+YAML file with required `name`+`description`; the same definition is reusable as a /security-review skill, a delegated subagent, and an agent-team teammate (its `tools` allowlist and `model` carry over on the teammate path).
- Make it read-only and project-agnostic: `tools: Read, Grep, Glob, Bash` (no Write/Edit), `model: opus` or `inherit`, and drive scanning from `git diff` rather than hardcoded paths so it works across TS/Go/Python/Java and backend/frontend/AI repos.
- Store at user scope (`~/.claude/agents/`) or as a plugin for cross-project reuse; project scope (`.claude/agents/`, checked into VCS) when the config is repo-specific. Identity comes from the `name` field, not the path.
- Use progressive disclosure: keep SKILL.md under 500 lines with the vulnerability taxonomy inline, and push language-specific checklists into one-level-deep `reference/*.md` files that load only when needed (metadata ~100 tokens preloaded; body on invoke; references on demand).
- Write a specific, third-person `description` with concrete triggers and key terms (it drives automatic delegation and is truncated at 1,536 chars in the listing) — put the primary use case first.
- Adopt Anthropic's security taxonomy (injection, authn/authz, crypto & secrets, code execution, data exposure) plus a high-confidence bias: keep only findings with confidence >=8, report HIGH/MEDIUM only, and explicitly filter out DoS, rate-limiting, generic hardening, and memory-safety in memory-safe languages.
- Restrict tools at multiple layers: `tools`/`disallowedTools` for the allowlist, `PreToolUse` hooks (`exit 2`) to block dangerous Bash subcommands, and `permissions.deny` for session-wide blocks; avoid `bypassPermissions`.
- Choose the right primitive: skills = reusable inline prompts/procedures; subagents = isolated context + tool restriction + summary-only return; agent teams = collaborating workers with a shared task list and SendMessage mailbox.
- For TL/QA/Dev/white-hacker workflows use agent teams (`CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`): lead=TL spawns Dev/QA/security teammates; enforce gates with `TaskCompleted`/`TeammateIdle` hooks; teammates load CLAUDE.md/skills/MCP but NOT the lead's history, so put detail in the spawn prompt.
- Prefer plain subagents over teams for non-collaborative parallel review (lower token cost); reserve teams for work needing discussion/adversarial cross-checking, and start with 3-5 teammates with non-overlapping file ownership.
- Note plugin-distribution constraints: plugin subagents ignore `permissionMode`, `mcpServers`, and `hooks`; and a subagent's `skills`/`mcpServers` fields do not apply when it runs as an agent-team teammate.
- Structure findings with a fixed output template (file, severity, category, description, exploit scenario, remediation) and validate against an eval set before sharing; reuse the same definition for the CI GitHub Action to gate PRs.

## Sources

- https://code.claude.com/docs/en/sub-agents
- https://code.claude.com/docs/en/skills
- https://code.claude.com/docs/en/agent-teams
- https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices
- https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview
- https://claude.com/blog/skills-explained
- https://github.com/anthropics/claude-code-security-review
- https://github.com/anthropics/claude-code-security-review/blob/main/.claude/commands/security-review.md
- https://support.claude.com/en/articles/11932705-automated-security-reviews-in-claude-code
- https://www.anthropic.com/news/automate-security-reviews-with-claude-code

