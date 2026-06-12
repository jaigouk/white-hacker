---
name: design-ticket
description: Design a beads ticket (task / spike / bug) with type-aware validation and optional wave placement within an epic
allowed-tools: Agent, Bash, Read, Grep, Glob
---

# /design-ticket <description> [--type=task|spike|bug] [--epic=<id>]

Design a single beads ticket aligned with the templates under
[`docs/beads_templates/`](../../docs/beads_templates/) — `beads-ticket-template.md` (task),
`beads-bug-template.md` (bug), `beads-spike-template.md` (spike) — with built-in validation.
When `--epic <id>` is given,
the new ticket is placed in the correct execution wave of that epic and
the epic's "Execution Waves" section is updated to reflect the addition.

## Why This Exists

Tickets created from rough descriptions miss things that depend on type:
- **task**: existing patterns to copy, package/skill scope conflicts
- **spike**: clear exit criteria, time-boxed scope, what "done" looks like
  even when the answer is "we shouldn't do this"
- **bug**: reproduction steps, root-cause hypothesis, regression risk

And when a ticket is part of an epic, getting its **wave** right
determines whether it can run in parallel with siblings or blocks them.
This command does the type-aware analysis AND the wave placement in one
pass.

## Usage

```bash
# Standalone task
/design-ticket Add a sec-iac skill that scans Terraform for public S3 buckets

# Standalone spike (researches a question; output is a decision)
/design-ticket --type=spike Evaluate Opengrep vs Semgrep as the SAST capability

# Standalone bug (with repro context)
/design-ticket --type=bug sec-detect misses gitleaks output after tool-registry update

# Child of an existing epic — places it in the right wave
/design-ticket --epic=wh-pxn --type=task Wire the sec-iac skill into the artifact chain after sec-detect
```

If `--type` is omitted, default is `task`. If `--epic` is given, the
ticket is created with `--parent <epic-id>` and the epic's body is
updated.

## Process

### Phase 1 — Type-Aware Analysis

Launch a subagent matched to the ticket type. Each agent reads the repo
state relevant to that type and produces the ticket body matching the
right template.

| Type | Subagent | Reads | Produces (per template) |
|---|---|---|---|
| `task` | `tech-lead` | README, CLAUDE.md, similar skills under `plugins/white-hacker/skills/`, the artifact-chain schemas, existing patterns | Goal, Prerequisites, Steps, Files to Create/Modify, Verification, Acceptance Criteria, Rollback, Notes, References (`beads-ticket-template.md`) |
| `spike` | `researcher` | Related docs, prior research under `docs/research/`, upstream docs via WebFetch | Problem statement, Research questions, Investigation plan, Exit criteria ("we will know we're done when…"), Time box, Likely outcomes (`beads-spike-template.md`) |
| `bug` | `developer` + `qa-engineer` | git log around suspected files, recent commits, related tests, logs/metrics references | Reproduction (commands), Expected vs Actual, Suspected root cause (`file:line`), Files in scope, Acceptance Criteria (regression test), Severity↔Priority, Rollback (`beads-bug-template.md`) |

Each agent must populate at least: **Goal**, **Steps** (or Reproduction
for bugs), **Verification**, **Acceptance Criteria**, **Rollback**,
**References**. Skip sections that genuinely don't apply (e.g. "Storage"
for a doc-only ticket) but mark them `N/A` explicitly — never silently
drop a template section.

### Phase 2 — Validate the Design

Launch a `tech-lead` agent (or `qa-engineer` for bugs; route
security-relevant validation to `white-hacker`) with the right checklist
per type:

**task** (mostly skills + scripts + docs)
1. Existing patterns — does a similar skill / script already exist under
   `plugins/white-hacker/skills/`?
2. Package scope — does it fit the package shape
   (`scripts/{<mod>.py,pyproject.toml,conftest.py,tests/}`) and stay
   stdlib-first (ADR-015 floor) rather than hard-depending on a tool?
3. Naming conventions — skill / module / artifact names follow patterns?
4. Scope — is this one ticket or should it be split? (>8 new files, >3 dirs,
   spans >1 skill package → consider split)
5. Budget caps (ADR-005) — `SKILL.md` <500 lines, `description`+`when_to_use`
   ≤1,536, `reference/` one level deep?
6. Security — no secrets in code/logs/KB, capability behind an interface
   (ADR-015), no `ANTHROPIC_API_KEY` leaks in agent/Claude work?

**spike**
1. Is there a sharp question? ("Should we…" with a Yes/No answer at end)
2. Is the time box tight (≤ 1 week)? Spikes that grow into work should
   become a task.
3. Are exit criteria concrete? (Decision recorded, ADR drafted, doc
   updated — not "we learned something")
4. What's the no-go output? Even a "we shouldn't do this" must produce
   an artifact.

**bug**
1. Repro is in the description and works on a fresh checkout?
2. Suspected root-cause hypothesis is concrete (file:line or specific
   behavior), not "something with X"?
3. Acceptance includes a regression test or assertion?
4. Severity matches priority? (Review pipeline broken / missed vuln = P0,
   blocks one flow = P2, cosmetic = P3.)

**DO-NOT-COPY / primary-source-gated tickets (any type).** If the ticket
hardcodes named literals an attacker also controls — dropper/IOC
filenames, package names, YARA-style signatures, regex constants — every
such literal in the body must be TAGGED `[primary-sourced: <url|file:line>]`
or `[example-unverified]`. An `[example-unverified]` literal is
illustrative ONLY and MUST NOT be hardcoded (the dev re-derives it from a
primary source or drops it). This stops an unsourced example (e.g. a
community-YARA filename) from reaching the code, where the gate would then
have to strip it mid-wave.

Output one of: **APPROVED**, **APPROVED WITH FIXES** (list them),
**NEEDS REDESIGN** (explain).

### Phase 3 — Wave Assignment (only if `--epic <id>`)

Skip this phase when there is no `--epic` flag.

1. **Load the epic's current child set**:
   ```bash
   bd show <epic-id>
   bd list --status=open | grep "<epic-id>\."  # children with dotted IDs
   ```

2. **Determine this ticket's wave** by the wave-grouping rules below:
   - Identify which existing ticket(s) this new one will depend on.
   - Find their wave numbers in the epic's "Execution Waves" section.
   - This ticket's wave = max(deps' waves) + 1, unless it has no deps
     within the epic → Wave 1.

3. **Find parallel-safe siblings in the same wave**:
   - Same dep set + disjoint file scope + no semantic ordering → same wave.
   - If a sibling in the same wave touches the same files this new
     ticket will, either (a) move this ticket to the next wave, or
     (b) flag a file-coordination risk in the epic's Risks table.

4. **Update the epic's body**:
   - Add this ticket to the "Child Tasks" table with the wave number.
   - Update the "Execution Waves" ASCII to include this ticket in the
     right wave.
   - Update the "Dependency Graph" if new edges were created.
   - If a new coordination risk surfaced, add a row to "Risks & Mitigations".

5. **Wire dependencies in beads**:
   ```bash
   bd dep add <new-ticket-id> <parent-dep-id>   # for each dep
   ```

### Phase 4 — Create the Ticket

After approval:

```bash
bd create \
  --title="<short imperative title>" \
  --type=<task|spike|bug> \
  --priority=<0-4> \
  ${EPIC:+--parent=<epic-id>} \
  --description="<body from Phase 1, validated in Phase 2>"
```

If the epic was updated in Phase 3, also push the change:

```bash
bd update <epic-id> --description="<updated epic body>"
bd export -o .beads/issues.jsonl  # persist title + dep updates
```

### Phase 5 — Report

```
================================================================
TICKET DESIGN REPORT
================================================================
TITLE:       <title>
TYPE:        <task | spike | bug>
BEADS ID:    <created id>
PARENT:      <epic id | none>
WAVE:        <N | n/a>
SCOPE:       <N> files to create / modify

VALIDATION:
  Type-appropriate checks: [PASS | FIX APPLIED]
  Scope:                   [OK | SPLIT RECOMMENDED]
  Wave placement:          [OK | n/a]
  File-coordination risk:  [NONE | FLAGGED in epic risks]
  Dependencies wired:      [N edges]

EPIC UPDATE:
  Child Tasks table:       [updated | n/a]
  Execution Waves section: [updated | n/a]
  Dependency Graph:        [updated | n/a]

VERDICT: CREATED / NEEDS USER INPUT / NEEDS REDESIGN
================================================================
```

## Wave Grouping Rules

When designing tickets that are children of an epic, place each ticket in
the correct execution wave so parallel work is obvious.

### Definitions

- **Wave 1**: child tickets with no dependencies on other children of the
  same epic. Ready immediately when the epic starts.
- **Wave N+1**: depends on at least one ticket in Wave N. Cannot start
  until all of its dependencies are closed.
- A ticket's wave = `max(wave of each of its deps within the epic) + 1`.
  If it has no in-epic deps, it's Wave 1.

### Two tickets belong in the SAME wave iff ALL are true

1. **Same dependency set** — both depend on the same parent ticket(s)
   within the epic, OR both have no in-epic deps (both Wave 1).
2. **Disjoint file scope** — they don't both create or modify the same
   files. (Inspecting the "Files to Create/Modify" sections of each
   ticket — if they overlap, they can't be parallel.)
3. **No semantic ordering** — neither produces an artifact the other
   needs before starting. (E.g. "skill A's SKILL.md" depends on
   "wrapper X exists" is a semantic ordering — they can't be in the
   same wave.)
4. **Parallel-session-safe** — could be picked up by two different
   Claude Code sessions or two different humans without coordination
   beyond what's documented in the epic.

If a sibling exists in the same wave that violates rules 2 or 3, decide
between:

- **Move this ticket to the next wave**: cleanest, but slows the epic.
- **Document the coordination point in the epic's Risks & Mitigations
  table**: explicit handoff between parallel tickets. Pattern: "Ticket
  A lands first with line X commented out; ticket B uncomments it during
  its smoke test."

### Wave ordering

Waves run **strictly sequentially** at the wave boundary. All Wave N
tickets must be closed before any Wave N+1 ticket can start. Within a
wave, tickets run in parallel.

### Wave naming

Number waves starting from 1. An optional **Wave 0** can hold sibling
tickets that are NOT children of the epic but should ship before any
in-epic work (e.g. a doc cleanup that prevents stale references during
later analysis).

## Rules

1. **One ticket per `/design-ticket` invocation.** Quality drops when
   batching.
2. **Templates are not optional.** Every ticket must conform to its type's template —
   `beads-ticket-template.md` (task), `beads-bug-template.md` (bug), or
   `beads-spike-template.md` (spike). Mark `N/A` sections explicitly; don't drop them silently.
3. **Verify against the actual repo state.** Don't trust the user's
   description — read the files and check.
4. **User approves before creation.** Never auto-create tickets.
5. **Epic stays in sync.** When `--epic` is given and the design changes
   the epic (wave placement, deps, risks), update the epic in the same
   step. A child without a parent update is half-done work.
6. **Wave assignment uses the epic's existing waves as ground truth.**
   Don't invent new waves — fit into the existing structure or document
   why a new wave is needed.

## Self-contained-execution requirement

Tickets designed by this command must be **executable by a single agent
with no inter-agent messaging**. `/launch-team` defaults to
sequential-orchestrator mode (no SendMessage between spawned agents — see
[`launch-team.md`](launch-team.md) Failure Mode 1 for why), so each
ticket has to stand on its own when handed to a `developer` subagent.

Concretely this means:

1. **`Files to Create/Modify` is the source of truth for scope.** The
   developer reads only what the ticket says it owns. If a file is
   needed but not listed, the developer will refuse to touch it.
2. **Acceptance Criteria must be machine-verifiable.** Each AC item
   should be checkable by a command (preferred) or a one-line file:line
   assertion. Vague AC ("works correctly", "looks good") cannot be
   self-verified by the developer and will surface as ambiguity to QA.
3. **Verification commands must be self-executable.** The developer runs
   them as part of Phase 2; if they need data the ticket doesn't
   provide, the developer is stuck.
4. **Prerequisites must be enumerable.** The developer checks them at
   the start of Phase 2. Missing prereq → block, not guess.

Tickets that fail this bar still work in team-mode (a TL agent can
clarify mid-flight), but they break in sequential mode. Default to
self-contained.

## References

- [`docs/beads_templates/beads-ticket-template.md`](../../docs/beads_templates/beads-ticket-template.md) — task body structure (real gates: pytest + manifest + plugin validate, NOT ruff/mypy/coverage)
- [`docs/beads_templates/beads-bug-template.md`](../../docs/beads_templates/beads-bug-template.md) — bug body structure (repro · expected/actual · root-cause file:line · regression test · severity↔priority)
- [`docs/beads_templates/beads-spike-template.md`](../../docs/beads_templates/beads-spike-template.md) — spike body structure
- [`docs/beads_templates/beads-epic-template.md`](../../docs/beads_templates/beads-epic-template.md) — Execution Waves section format (kept aligned with this command's Phase 3)
- [`.claude/commands/launch-team.md`](launch-team.md) — execution modes (sequential default vs team opt-in); informs the self-contained-execution requirement above
- [`.claude/commands/groom.md`](groom.md) — what to run AFTER design but BEFORE claim, to re-validate against current state
