# Spike-06: Verify Current (2026-06) Claude Code Hooks Protocol

**Status:** RESOLVED  
**Date:** 2026-06-06  
**Confidence:** HIGH  
**Author:** white-hacker agent

---

## Question

What is the CURRENT (2026-06) Claude Code hooks protocol? Specifically:

1. **stdin_json_shape** — the exact JSON delivered to a PreToolUse hook on stdin
2. **exit_code_semantics** — what exit codes do (0, 2, others) and whether exit 2 blocks the tool call
3. **settings_registration** — the exact settings.json shape to register a PreToolUse hook with a matcher
4. **bash_matcher_can_inspect_and_block** — can a PreToolUse hook matched on Bash read tool_input.command and block by exit 2?
5. **permissions_deny_alternative** — what settings.json permissions.deny can express and whether deny rules apply to Bash sub-commands

---

## Method

Fetched official Claude Code documentation directly from the source:
- https://code.claude.com/docs/en/hooks.md — PreToolUse hook protocol specification
- https://code.claude.com/docs/en/settings.md — settings.json schema reference
- https://code.claude.com/docs/en/permissions.md — comprehensive permission rules syntax

No reliance on memory or inference; all findings are from official docs dated 2026-06-05 (last update).

---

## Findings

### 1. stdin_json_shape

**Exact JSON delivered to PreToolUse hooks on stdin:**

```json
{
  "session_id": "abc123",
  "transcript_path": "/path/to/transcript.jsonl",
  "cwd": "/current/working/directory",
  "permission_mode": "default",
  "effort": {
    "level": "medium"
  },
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "rm -rf /tmp/build"
  }
}
```

**Key fields:**
- `session_id` (string): current session identifier
- `transcript_path` (string): path to conversation JSON
- `cwd` (string): current working directory
- `permission_mode` (string): one of `"default"`, `"plan"`, `"acceptEdits"`, `"auto"`, `"dontAsk"`, or `"bypassPermissions"`
- `effort` (object with `level` field): `"low"` / `"medium"` / `"high"` / `"xhigh"` / `"max"`
- `hook_event_name` (string): always `"PreToolUse"` for this event
- `tool_name` (string): name of tool (e.g., `"Bash"`, `"Edit"`, `"Write"`, `"Read"`)
- `tool_input` (object): tool-specific arguments; for Bash, contains `"command"` (string)

**Note:** The `tool_input` object structure varies by tool. For Bash it is `{ "command": "..." }`. For Edit/Write it would contain path and content.

---

### 2. exit_code_semantics

| Exit Code | Behavior | Details |
|-----------|----------|---------|
| **0** | Success | Hook succeeds. Claude Code parses stdout for [JSON output](#json-output). If no JSON output is produced, the hook makes no permission decision and normal permission flow applies. |
| **2** | Blocking error | **Tool call is blocked immediately.** Stderr is fed to Claude as an error message. No permission prompts are shown. This exit code **blocks the tool call outright.** |
| **Other** (1, 3+) | Non-blocking error | Stderr is shown in the transcript with the hook name. Execution continues normally (tool call proceeds as if the hook had no decision). |

**JSON output alternative (exit 0 only):**

Exit with code 0 and output JSON on stdout to provide structured permission decisions:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Destructive command blocked by hook"
  }
}
```

**Available permissionDecision values:**
- `"allow"` — allows the tool call
- `"deny"` — blocks the tool call
- `"ask"` — escalates to permission dialog
- `"defer"` — defers to normal permission flow (same as exit 0 with no JSON)

**Additional JSON fields (optional):**
- `permissionDecisionReason` (string): reason shown to Claude
- `updatedInput` (object): modified tool input to be used (only for `"allow"`)
- `additionalContext` (string): context injected into Claude's understanding

**Exit 2 vs JSON deny:** Exit 2 **blocks immediately without prompting**. JSON `permissionDecision: "deny"` also blocks but may allow other flows (such as asking the user). Exit 2 is the hard block.

---

### 3. settings_registration

**Complete hook registration in settings.json:**

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "if": "Bash(rm *)",
            "command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/block-rm.sh",
            "args": [],
            "timeout": 600
          }
        ]
      }
    ]
  }
}
```

**Structure:**

1. **Top-level key:** `"hooks"`
2. **Event key:** `"PreToolUse"` (other events: `PostToolUse`, `PostToolUseFailure`, `PermissionRequest`, `PermissionDenied`)
3. **Matcher group:** array of objects, each with:
   - `"matcher"` (string): filter by tool name
   - `"hooks"` (array): hook handlers to run
4. **Hook handler:** object with:
   - `"type"` (required): `"command"`, `"http"`, `"mcp_tool"`, `"prompt"`, or `"agent"`
   - `"if"` (optional): permission rule pattern to narrow further (e.g., `"Bash(rm *)"`)
   - `"command"` (required for type=command): executable path
   - `"args"` (optional): array of arguments
   - `"timeout"` (optional, default 600): seconds before canceling
   - `"statusMessage"` (optional): custom spinner message

**Matcher values and semantics:**

| Matcher Value | Behavior |
|---------------|----------|
| `"*"` or omitted | Match all tools; fires on every PreToolUse |
| Letters/digits/`_`/`\|` | Exact string or pipe-separated list (e.g., `"Bash"`, `"Edit\|Write"`, `"Bash\|Read"`) |
| Other characters | JavaScript regex (e.g., `"^Notebook"` matches tools starting with Notebook) |
| `"mcp__serverName__.*"` | All tools from specific MCP server (e.g., `"mcp__memory__.*"` matches all memory tools) |

**Example with multiple matchers:**

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "if": "Bash(rm *)",
            "command": "/path/to/block-rm.sh",
            "timeout": 600
          }
        ]
      },
      {
        "matcher": "Edit",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/log-edits.sh",
            "timeout": 300
          }
        ]
      }
    ]
  }
}
```

---

### 4. bash_matcher_can_inspect_and_block

**Answer: YES, fully supported.**

A PreToolUse hook matched on `Bash` can:
1. Read the full command from `tool_input.command` on stdin (JSON key: `tool_input.command`)
2. Parse and inspect the command
3. Block by exiting with code **2**
4. Optionally provide structured JSON deny decision on stdout with exit 0

**Example hook script (.claude/hooks/block-destructive.sh):**

```bash
#!/bin/bash
COMMAND=$(jq -r '.tool_input.command' <<< "$1")

# Block rm -rf
if echo "$COMMAND" | grep -q 'rm -rf'; then
  jq -n '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: "Destructive command blocked"
    }
  }'
  exit 0  # Return JSON with deny decision
fi

exit 0  # Allow (no decision = normal flow)
```

**Or simply block with exit 2:**

```bash
#!/bin/bash
COMMAND=$(jq -r '.tool_input.command' <<< "$1")

if echo "$COMMAND" | grep -q 'rm -rf'; then
  echo "Destructive rm -rf blocked by hook" >&2
  exit 2  # Hard block, no prompt
fi

exit 0
```

**Confirmation:** The docs explicitly show a "Block edits to protected files" example where a hook reads the tool input and returns a permission decision.

---

### 5. permissions_deny_alternative

**settings.json permissions.deny can express:**

```json
{
  "permissions": {
    "deny": [
      "Bash",
      "Bash(*)",
      "Bash(rm *)",
      "Bash(git push *)",
      "Bash(npm run build)",
      "Read(.env)",
      "Read(.env.*)",
      "Read(./secrets/**)",
      "Read(~/.ssh/**)",
      "Read(//Users/alice/private/**)",
      "Edit(/src/**/*.ts)",
      "WebFetch(domain:example.com)"
    ]
  }
}
```

**Deny rules have two forms:**

1. **Bare tool name** (e.g., `"Bash"`): removes the tool from Claude's context entirely; Claude never sees it
2. **Scoped pattern** (e.g., `"Bash(rm *)`): leaves the tool visible; blocks matching calls when Claude attempts them

**Bash-specific deny patterns:**

| Pattern | Blocks | Does NOT block |
|---------|--------|--------|
| `Bash` or `Bash(*)` | All Bash commands | — |
| `Bash(rm *)` | `rm -rf /tmp`, `rm file.txt` | `echo`, `ls` |
| `Bash(git push *)` | `git push origin main` | `git pull`, `git commit` |
| `Bash(curl *)` | `curl http://...` | `wget` |
| `Bash(* --help *)` | Any command with `--help` | Commands without `--help` |

**Wildcard semantics:**

- `*` matches any sequence of characters (including spaces)
- Space before `*` matters: `Bash(ls *)` matches `ls -la` (word boundary) but not `lsof` (no boundary)
- `:*` suffix is equivalent to ` *` at the end: `Bash(ls:*)` == `Bash(ls *)`
- Patterns can have `*` at start, middle, or end

**Compound command handling (Bash sub-commands):**

**YES — deny rules apply to Bash sub-commands.**

From the docs:
> Claude Code is aware of shell operators, so a rule like `Bash(safe-cmd *)` won't give it permission to run the command `safe-cmd && other-cmd`. The recognized command separators are `&&`, `||`, `;`, `|`, `|&`, `&`, and newlines. **A rule must match each subcommand independently.**

Example:
- **Deny rule:** `Bash(rm *)`
- **Command:** `echo foo && rm -rf /` 
- **Result:** BLOCKED — the `rm -rf /` subcommand matches the deny rule

The permission system parses compound commands and checks each subcommand independently. **All subcommands must be allowed** for the compound to execute.

**Process wrapper stripping:**

Before matching Bash rules, Claude Code strips these fixed wrappers:
- `timeout`, `time`, `nice`, `nohup`, `stdbuf`
- `xargs` (bare, with no flags)

So `Bash(grep *)` matches both `grep pattern` and `xargs grep pattern`.

**Read/Edit deny rules:**

These use gitignore patterns with anchors:

| Pattern | Anchor | Scope |
|---------|--------|-------|
| `Read(.env)` | Current directory | Matches `.env` at or under `cwd/` |
| `Read(/src/**)` | Project root | Matches files under `<project>/src/` |
| `Read(~/.ssh/**)` | Home directory | Matches files under `~/.ssh/` |
| `Read(//Users/alice/**)` | Filesystem root | Matches paths under `/Users/alice/` |

---

## Decision

**The 2026-06 Claude Code hooks protocol is fully documented and stable.** All five questions have clear, specification-level answers verified against official source docs. No ambiguity remains.

**Key design patterns confirmed:**

1. **stdin_json_shape** is well-defined with common fields (`session_id`, `cwd`, `hook_event_name`, `tool_name`, `tool_input`)
2. **exit_code_semantics** are clean: exit 0 = no decision (normal flow) or JSON decision; exit 2 = hard block; other = non-blocking error
3. **settings_registration** is a nested structure: `hooks[EventName][{matcher, hooks[]}]`; matcher supports exact names, pipes, and regex
4. **bash_matcher_can_inspect_and_block** is fully supported; hooks can read `tool_input.command` and return exit 2 or JSON deny
5. **permissions_deny_alternative** is comprehensive: bare tool names, scoped patterns with wildcards, compound command parsing, process wrapper stripping

**Confidence: HIGH**

All findings are from official Claude Code docs (https://code.claude.com/docs/en/hooks.md, https://code.claude.com/docs/en/permissions.md, https://code.claude.com/docs/en/settings.md), dated 2026-06-05. No inference or memory involved.

---

## Sources

- [Claude Code Hooks Documentation](https://code.claude.com/docs/en/hooks.md) — PreToolUse hook protocol, stdin JSON schema, exit code semantics, permission decisions
- [Claude Code Settings Documentation](https://code.claude.com/docs/en/settings.md) — hook registration format in settings.json
- [Claude Code Permissions Documentation](https://code.claude.com/docs/en/permissions.md) — comprehensive permission rule syntax, deny patterns, compound command parsing, process wrapper stripping

