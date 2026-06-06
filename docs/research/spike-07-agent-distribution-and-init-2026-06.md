# Spike-07: Distribution shape + project-detecting init for the white-hacker agent (2026-06)

**Status:** RESOLVED
**Date:** 2026-06-06
**Confidence:** HIGH (canonical Anthropic docs + 3 qualifying >1k★ repos verified live; one GitHub
contents API call was rate-limited from this host, noted inline)
**Author:** white-hacker agent
**Supersedes/extends:** ADR-014 (thin: "distribute by copy or plugin", flagged "requested layout,
not researched"). This spike resolves it and recommends a new **ADR-017** (see Decision).

---

## Question

Today everything lives under this repo's `.claude/` (agent, skills, commands, hooks, KB).
That makes it work *here* (dogfooding), but it conflates two different things and leaves the
distribution + onboarding story unverified. Resolve:

1. **Canonical distribution shape.** What is the *current* (2026) Anthropic-blessed way to
   package + distribute a Claude Code agent bundle (agent + skills + commands + hooks + KB)?
   Plugin? Marketplace? Plain copy? What does the official plugin layout look like
   (`.claude-plugin/plugin.json`, `marketplace.json`, the `/plugin` flow), and how does it
   differ from a project's `.claude/`?

2. **Dev-repo vs distributable separation.** How do we cleanly differentiate
   *"this repo's own `.claude/` (used to build/dogfood the agent)"* from
   *"the artifact a user installs into their project"*? Is the right move:
   (a) this repo IS the plugin/marketplace (payload at root, dogfooded via a self-reference),
   (b) a `plugin/` (or similar) payload subtree + a thin dev `.claude/`, or
   (c) a separate published package? What do popular, actively-maintained repos do?

3. **Project-detecting init / install step.** Each target repo is different (language, stack,
   framework, monorepo, AI/LLM presence, available scanners). The agent **profile** and config
   should be *optimized per project*, not one-size-fits-all. What are the best-practice
   mechanisms for an init/install step that **detects the project and refines the profile**?
   Candidates to verify: `/init`-style generation, SessionStart hooks, plugin install hooks,
   an `npx`/CLI installer/generator, output styles, `${CLAUDE_PROJECT_DIR}`, conditional
   skill/command loading. Where should the *generated, project-specific* profile live vs the
   *generic, shipped* profile?

4. **Profile optimization specifics.** Given our generic `white-hacker.md`, *what* is safe and
   useful to specialize per project (stack appendices, scanner registry pruning, threat-model
   seed, severity/scoring standard, exclusion rules) — and what must stay generic to preserve
   identity (ADR-004 identity preservation, ADR-005 size caps)?

### Out of scope (this spike)
- Implementing the installer/generator (follow-up tickets).
- CI distribution (covered by Phase 6 / ADR-006); only note interactions.

---

## Constraints on evidence (hard rules for this spike)
- **Recency:** today is **2026-06-06**. Reject any source older than **3 months**
  (i.e. published/updated before ~**2026-03-06**) unless it is canonical Anthropic reference
  documentation that is still current. Date every citation.
- **GitHub bar:** any referenced GitHub project must have **> 1,000 stars** AND be
  **actively maintained** (commit activity within the recency window). Record stars + last-commit.
- **Authority order:** Anthropic official docs (`code.claude.com/docs`, `docs.claude.com`,
  `anthropic.com/engineering`) outrank community/blog sources. Prefer canonical docs for the
  mechanism; use community repos for *layout/onboarding patterns* only.

---

## Method

1. Fetch current Anthropic docs for plugins, plugin marketplaces, plugin reference, settings,
   skills, sub-agents, slash-commands, memory/CLAUDE.md, hooks (SessionStart), CLI `/init`.
2. Survey ≥3 qualifying GitHub repos (>1k stars, active) that distribute CC agents/skills/
   plugins or are marketplaces, for *dev-repo-vs-payload* layout and *install/init* patterns.
3. Survey project-detection / profile-generation patterns (installers, SessionStart hooks,
   generators, output styles).
4. Synthesize against our existing ADR-014 / ARCHITECTURE §8; decide and spawn follow-up tickets.

---

## Findings

All Anthropic claims fetched live from `code.claude.com/docs` on 2026-06-06 (pages show no
"last-updated" stamp; content is the current published reference). GitHub repos verified for
`>1k★` + a commit within the recency window (last-push dates below). Items I re-verified myself
(not just via subagent) are marked **[verified]**.

### F1 — Canonical distribution shape: it's the **plugin + marketplace** system, not `.claude/` copy

The current (2026) Anthropic-blessed way to ship an agent **bundle** (agent + skills + commands +
hooks + MCP/KB) is a **Claude Code plugin** distributed through a **marketplace** — exactly the
shape of bundle we have. Copying `.claude/` is the ad-hoc fallback, not the product form.

- **Plugin layout** (`plugins-reference`): a plugin is a self-contained directory. **Only**
  `plugin.json` lives in `.claude-plugin/`; **all component dirs are at the plugin root** —
  `skills/`, `agents/`, `commands/`, `hooks/hooks.json`, `.mcp.json`, `.lsp.json`,
  `output-styles/`, `bin/`, `settings.json`, `scripts/`. **[verified]** verbatim doc warning:
  > "The `.claude-plugin/` directory contains the `plugin.json` file. All other directories
  > (commands/, agents/, skills/, output-styles/, themes/, monitors/, hooks/) must be at the
  > plugin root, not inside `.claude-plugin/`."
- `plugin.json` **required field: `name`** (kebab-case) only; everything else optional
  (`version`, `description`, `author`, `license`, `repository`, component-path overrides,
  `dependencies`). **[verified]**
- **Marketplace** = `.claude-plugin/marketplace.json` at a repo root; required `name`, `owner`,
  `plugins[]`. Each plugin entry has `name` + `source` (relative `./plugins/<name>`, or
  `{source: github|git-subdir|url|npm, …}` with optional `sha` pinning). **One repo can host a
  whole marketplace of many plugins**; `metadata.pluginRoot: "./plugins"` shortens sources.
- **Install:** `claude plugin marketplace add owner/repo[@ref]` → `claude plugin install
  name@marketplace [--scope user|project|local]` (in-session: `/plugin marketplace add`,
  `/plugin install`). **Dev/test without installing:** `claude --plugin-dir ./plugins/white-hacker`
  (also `--plugin-dir <zip>` / `--plugin-url`). Validate with `claude plugin validate`.
- **Plugin vs project `.claude/` are structurally different** (not the same files in a new root):
  plugin uses `.claude-plugin/plugin.json` + root-level component dirs and **namespaced** skills
  (`/white-hacker:security-review`); project `.claude/` uses flat `settings.json`/`agents`/
  `skills`/`commands` with **unnamespaced** names. **Critical:** a **`CLAUDE.md` at the plugin
  root is NOT loaded** — plugins contribute context only through skills/agents/hooks. **[verified]**

### F2 — Dev-repo vs distributable separation: `.claude/` = dev/dogfood, `plugins/<name>/` = payload

The dominant 2026 layout across qualifying repos puts the **shipped payload at `plugins/<name>/`**
(each with its own `.claude-plugin/plugin.json`), the **catalog at repo-root
`.claude-plugin/marketplace.json`**, and keeps the **repo's own dev config in a separate root
`.claude/`** (or no root `.claude/` at all, dogfooding via a self-registered marketplace).

| Repo | ★ | Last push | Dev config | Shipped payload |
|------|----|-----------|-----------|-----------------|
| `anthropics/claude-code` | 130,625 **[verified]** | 2026-06-06 **[verified]** | `.claude/commands/` (Anthropic devs) | `plugins/*/` + root `.claude-plugin/marketplace.json` |
| `anthropics/claude-plugins-official` | 29,506 | 2026-06-06 | none committed | `plugins/*/` (+ `external_plugins/*` via `git-subdir`/`url`+`sha`) |
| `wshobson/agents` | 36,445 | 2026-06-05 | none (pure dogfood) | `plugins/*/` (84) + multi-harness manifests |
| `VoltAgent/awesome-claude-code-subagents` | 21,290 | 2026-05-27 | `.claude/settings.local.json` (contrib perms) | `categories/*/` bundles |

→ **`.claude/` and `plugins/<name>/` are siblings with different jobs.** Our current repo
conflates them: the *payload* (agent/skills/commands/hooks/KB) is sitting in the repo's *dev*
`.claude/`. The documented migration path is literally `.claude/commands → plugin/commands`,
`.claude/agents → plugin/agents`, `settings.json hooks → plugin/hooks/hooks.json`.

### F3 — Project-detecting init: there is **no plugin install hook**; use SessionStart/Setup + a generator

There is **no `onInstall`/`postInstall` plugin hook**. The native install/onboarding mechanisms:

- **`SessionStart` hook** — fires on session begin/resume (`source`: startup/resume/clear/compact).
  A `command` hook runs a detection script (env has `CLAUDE_PROJECT_DIR`) and returns
  `hookSpecificOutput.additionalContext` (**injected into context at session start**), plus
  `watchPaths`, `reloadSkills`, `sessionTitle`; can persist Bash env via `CLAUDE_ENV_FILE`.
  **Plugins can ship SessionStart hooks**, but a filed bug
  ([anthropics/claude-code#16538](https://github.com/anthropics/claude-code/issues/16538)) reports
  plugin-scoped SessionStart `additionalContext` may not surface — **project/user-scope hooks work**,
  so put the detector at project scope.
- **`Setup` hook** — fires only on `claude --init-only` / `-p --init` / `-p --maintenance`. This is
  the native **"one-time install/CI prep"** event: detect the stack and scaffold a project-scope
  layer, then exit. `claude --init-only` runs Setup+SessionStart and exits.
- **`/init`** analyzes the codebase and generates **CLAUDE.md only** (build/test/conventions); it
  does **not** generate agent profiles, and it's interactive (not scriptable). `CLAUDE_CODE_NEW_INIT=1`
  upgrades it to a multi-phase flow that can also propose skills/hooks behind a review gate.
- **Generators:** `claude --agents '<json>'` injects a session-scoped tailored subagent; a script can
  write `.claude/agents/<name>.md` and select it via the `agent` setting; `initialPrompt` frontmatter
  fires a detection prompt on the agent's first turn. The `/agents` "Generate with Claude" button is
  UI-only (not scriptable). Community installers use `npx <tool> init` (e.g. `ruvnet/ruflo` 58,219★
  2026-06-06; `davila7/claude-code-templates` 27,800★ 2026-06-06).

**Hard limits / cautions that bind the init design:**
- CLAUDE.md should stay **< 200 lines** ("longer files … reduce adherence"); auto-memory loads only
  first 200 lines / 25 KB.
- Skill `description`+`when_to_use` budget is **1,536 chars** (always in context).
- Hook output (incl. `additionalContext`) capped at **10,000 chars** (overflow → file + preview).
- **`additionalContext` must be written as FACTUAL STATEMENTS, not imperative instructions** — the
  docs warn imperative phrasing "can trigger Claude's prompt-injection defenses." (Directly relevant:
  white-hacker is itself an injection target and treats all injected content as untrusted.)
- **CLAUDE.md is context, not enforcement** — "to block an action … use a PreToolUse hook instead."
- **No built-in identity-drift guard** in stock Claude Code — preserving identity under
  auto-customization is on us (our ADR-004 + Phase-9 eval gate).

### F4 — Profile-optimization: specialize a *project-scope companion*, never rewrite the shipped identity

Because (a) a plugin's identity lives in the agent `.md` + skills (plugin CLAUDE.md isn't loaded),
(b) settings/CLAUDE.md **layer by scope** (managed > cli > local > project > user; CLAUDE.md files
**concatenate** broad→specific), and (c) there is no identity-drift guard — the safe design is:
**ship a generic base (plugin/user scope) and have init emit a *project-scope companion layer*
(committed `.claude/`) that the generic agent consumes — never an edit of the shipped profile.**

- **Keep generic / identity-preserving (init must NOT rewrite — ADR-004):** the senior-security
  -engineer identity, posture (authorized-only / read-only / untrusted-input / Agents-Rule-of-Two /
  proposes-not-pushes), the review-loop stages, FP discipline, severity-by-preconditions, the JSON
  output contract, and tool scoping.
- **Safe to specialize per project (init output, project scope, gated by Phase-9 corpus):** which
  per-language appendices load (skill `paths:` frontmatter auto-loads on matching files), the
  **scanner registry pruned to installed tools**, a **threat-model seed** (assets / entry points /
  trust boundaries from docs+git history), the **scoring standard** (CVSS vs org bug-bar — ask),
  `config/fp-rules` defaults, whether the **AI/LLM pass** applies (LLM deps present), and monorepo
  partition hints.
- **Reuse, don't reinvent:** we already have `sec-detect` (stack→`SCAN-PLAN.json`) and
  `sec-threat-model` (→`THREAT_MODEL.md`). The "init" is essentially **running those once at
  onboarding and persisting the result as the committed project profile**, plus an optional factual
  SessionStart context line — not a new detection subsystem. Per-review `sec-detect` still runs.

---

## Decision

1. **`.claude/` is correct for dogfooding here, but the *distributable* must be a Claude Code
   plugin published via a marketplace.** Restructure: shipped payload → `plugins/white-hacker/`
   (`.claude-plugin/plugin.json` + root-level `agents/ skills/ commands/ hooks/ scripts/`),
   catalog → repo-root `.claude-plugin/marketplace.json`; keep a **thin dev `.claude/`** and
   dogfood via `--plugin-dir ./plugins/white-hacker` (or self-registered marketplace). Repo
   `CLAUDE.md` stays **dev-only** (it is not shipped; plugin-root CLAUDE.md isn't loaded anyway).

2. **Identity lives in the agent `.md` + skills, not a plugin CLAUDE.md.** Audit that the posture/
   identity is fully self-contained in `agents/white-hacker.md` + skills before the move.

3. **Project-detecting init = run `sec-detect` + `sec-threat-model` once at onboarding and persist
   a committed *project-scope companion* layer** the generic agent reads — plus an optional
   **project-scope** SessionStart hook emitting the detected facts as **factual** `additionalContext`
   (≤10k chars, not imperative). It **never** rewrites the shipped identity; every generated artifact
   passes the **Phase-9 keep-or-revert gate** and size caps. Honor bug #16538 (project scope).

4. **Supersede ADR-014 with a new ADR-017** capturing 1–3, and refresh ARCHITECTURE §8.

**Confidence: HIGH.** Mechanisms are from canonical Anthropic docs; the layout is what the three
largest actively-maintained reference repos actually do. Implementation is deferred to the
follow-up tickets (plan-first; nothing is built until the plan is approved).

**Follow-up tickets opened:** new workstream **Phase 10 — Distribution & Onboarding**
([`docs/plan/phase-10-distribution-init.md`](../plan/phase-10-distribution-init.md)), tasks
**T-10.1 … T-10.7** (ADR-017 → manifests+tests → payload migration → identity/limits reconcile →
init/profile generator → SessionStart factual-context → onboarding docs).

---

## Sources

**Anthropic official docs** (fetched 2026-06-06; current published reference):
- [Plugins reference](https://code.claude.com/docs/en/plugins-reference) — plugin/marketplace schema, directory rules, CLI **[verified]**
- [Create plugins](https://code.claude.com/docs/en/plugins) — plugin vs `.claude/`, migration path
- [Plugin marketplaces](https://code.claude.com/docs/en/plugin-marketplaces) — `marketplace.json`, sources, install commands
- [Settings](https://code.claude.com/docs/en/settings) — scope precedence (managed>cli>local>project>user)
- [Memory](https://code.claude.com/docs/en/memory) — CLAUDE.md hierarchy, `/init`, `<200 lines`, `CLAUDE_CODE_NEW_INIT`
- [Hooks](https://code.claude.com/docs/en/hooks) — SessionStart/Setup, `additionalContext` (factual-not-imperative; 10k cap), `CLAUDE_ENV_FILE`
- [Skills](https://code.claude.com/docs/en/skills) — `paths:` auto-load, 1,536-char budget, per-skill `model`/`allowed-tools`/`context: fork`
- [Sub-agents](https://code.claude.com/docs/en/sub-agents) — `--agents` JSON, `agent` setting, `initialPrompt`, "Generate with Claude" (UI-only)
- [CLI reference](https://code.claude.com/docs/en/cli-reference) — `--init-only`, `--plugin-dir`, env vars

**GitHub (all >1k★, active; verified)** — last-push dates from the research sweep:
- [anthropics/claude-code](https://github.com/anthropics/claude-code) — 130,625★, pushed 2026-06-06, not archived **[verified live]**
- [anthropics/claude-plugins-official](https://github.com/anthropics/claude-plugins-official) — 29,506★, 2026-06-06
- [wshobson/agents](https://github.com/wshobson/agents) — 36,445★, 2026-06-05
- [VoltAgent/awesome-claude-code-subagents](https://github.com/VoltAgent/awesome-claude-code-subagents) — 21,290★, 2026-05-27
- [davila7/claude-code-templates](https://github.com/davila7/claude-code-templates) — 27,800★, 2026-06-06
- [ruvnet/ruflo](https://github.com/ruvnet/ruflo) — 58,219★, 2026-06-06 (`npx … init` generator pattern)
- [anthropics/claude-code#16538](https://github.com/anthropics/claude-code/issues/16538) — plugin SessionStart `additionalContext` bug

**Dropped for failing the bar** (recorded for audit): `wshobson/commands` (2,500★ but last push
2025-10-12, stale), `anthropics/claude-plugins-community` (166★), `Cranot/claude-code-guide`
(2,792★ but pushed 2026-02-14, > 3 months), plus several < 1k★ template repos.
