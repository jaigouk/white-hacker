# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->

## Ticket creation & grooming (templates are mandatory)

Every beads ticket MUST be **designed via `/design-ticket --type=<task|bug|spike>`** and conform to its
type template under [`docs/beads_templates/`](docs/beads_templates/):

| Type | Template | Load-bearing sections |
|------|----------|-----------------------|
| `task` | `beads-ticket-template.md` | Goal · Steps · Files to Modify · Acceptance Criteria · Quality Gates · Rollback |
| `bug` | `beads-bug-template.md` | Reproduction · Expected vs Actual · Root-cause `file:line` · regression-test AC · Severity↔Priority |
| `spike` | `beads-spike-template.md` | Problem · Research questions · Exit criteria · Time box |

- **Real quality gates** (in every template) are **pytest on the touched package + `validate_manifest.py` +
  `claude plugin validate` — NOT mypy / coverage / style** (a scoped correctness `ruff` runs repo-wide as
  pre-commit + CI per **ADR-032**, but is NOT a per-ticket gate) (Policy 12; `.claude/commands/launch-team.md`).
- **Never** hand-author a ticket body or `bd create` a one-line description — including follow-ups a
  team files mid-wave (route them through `/design-ticket`; `.claude/commands/launch-team.md` Rule 8).
- **Re-groom off-template tickets to the template before launch** (`/groom`, or re-design via
  `/design-ticket`). A `bd update <id> --description=…` with the template-shaped body is the mechanism;
  never `bd edit` (it opens `$EDITOR` and blocks agents).

## Self-improvement loop (operator-gated) — the team improves its OWN process

The team gets better over time by improving the **process artifacts it runs on** — the role profiles
(`.claude/agents/*.md`), the workflow commands (`.claude/commands/*.md`), the ticket templates
(`docs/beads_templates/*`), and the quality gates. **Only the operator applies such a change; never an
agent on its own.** This is the team's **PROCESS** loop. (Improvements to the project's own CODE/tests
that a retro surfaces flow the normal way — a follow-up ticket via `/design-ticket` + TDD — not this
text-edit-and-confirm loop.)

> **This is NOT `/sec-learn`.** `/sec-learn` + `/sec-kb-refresh` are the *product* outer loop (ADR-001):
> they edit ONLY the shipped reviewer's Context surface — the AI-attack KB, `_shared/reference/`
> checklists, `tool-registry.md` — and are **hard-confined OUT of process artifacts** by
> `plugins/white-hacker/hooks/confine_self_writes.py` (`ALLOW_SEGMENTS` = `ai-attack-kb` / `_shared/reference`
> / `PATCHES` / `evals/traces` only). Routing an "improve `.claude/agents/tech-lead.md`" item to `/sec-learn`
> is a dead end — it structurally cannot write there. Process improvements go through THIS loop instead.

**Inputs (the only two):**
- **Retros** — every wave's `/handoff` ends with a mandatory Retro; its items whose target is a role
  profile, command, ticket template, or gate feed this loop.
- **Operator feedback** — a correction or preference you give an agent in-session.

**Who proposes:** the **tech-lead** (the in-wave coordinator + closer). A worker (developer, QA,
researcher, white-hacker) that hits a role/process gap **raises it to the tech-lead** — it does not edit
a profile itself. (The **project-manager** owns *pre-wave* planning/grooming/wave-assignment, not in-wave
process edits or closing.)

**Protocol — propose, then confirm:**
1. The tech-lead drafts the **exact edit**: which file, the precise **old → new** text, and the
   **source** (the retro item or your feedback, quoted).
2. It **presents the proposal and WAITS.** No `.claude/agents/*`, command, template, or gate changes
   without your explicit confirmation **in-session**.
3. On approval the edit is applied to the working tree; **you review + commit** it — git is
   operator-gated.
4. Decline/amend → the agent records the decision and moves on; it does not re-propose unprompted.

**Provenance:** an applied edit is recorded in that wave's `.notes/handoff-<slug>.md` Retro under
**"Applied this wave (operator-confirmed)"** — which artifact changed + the driving retro item/feedback,
quoted. The trail survives there without cluttering the role files.

**Fail loud (Policy 12):** a process-artifact edit with no operator confirmation and no recorded source
is a process violation, not an improvement. When in doubt, propose and wait — never self-apply.

## Build & Test

_Add your build and test commands here_

```bash
# Example:
# npm install
# npm test
```

### Resource discipline (CPU & I/O)

A dev machine may run endpoint security with on-access file scanning (common in managed/enterprise environments). Saturating all CPU cores — or fanning out parallel Python/builds — serializes I/O **system-wide** and freezes the UI even with RAM free (RAM is not the bottleneck; more cores would not help — work expands to fill them). Every command-running agent in `.claude/agents/` carries these rules **inline** (subagents don't reliably inherit this file); keep this canonical copy in sync:

- **Test parallelism:** never `pytest -n auto` / "all cores" — at most `-n 4`; run serially if pytest-xdist isn't configured.
- **Multiprocessing:** never `os.cpu_count()`-sized pools — `<= 4` workers, e.g. `Pool(processes=min(4, (os.cpu_count() or 4)//2))`.
- **Priority:** prefix heavy/long commands with `nice -n 10 ` (e.g. `nice -n 10 uv run pytest -n 4`).
- **Native thread pools:** export `OMP_NUM_THREADS=4 MKL_NUM_THREADS=4 OPENBLAS_NUM_THREADS=4 VECLIB_MAXIMUM_THREADS=4 NUMEXPR_NUM_THREADS=4` for numeric/ML code.
- **One heavy task at a time:** finish or background one test/build/Python job before starting the next.
- **Scope file ops:** exclude `.venv`, `node_modules`, build output, `.git` from recursive scans/builds (each touched file is scanned).
- **Orchestrators** (tech-lead, project-manager): run at most 2 heavy subagents concurrently; never fan out one heavy Python task per agent across many agents.

## Architecture Overview

_Add a brief overview of your project architecture_

## Conventions & Patterns

**Public repo — no personal data, repo-relative paths only.** `jaigouk/white-hacker` is a PUBLIC
repo; nothing from outside it may be committed — no absolute home paths (`/Users/…`, `/home/…`, `~`),
no username, no installed-tool locations, no machine-environment / self-audit logs, **no machine-specific
details in agent profiles (`.claude/agents/*.md`) or `bd` memories** (which export to the committed
`.beads/issues.jsonl` — keep machine-specific notes in `.notes/`, gitignored). Use repo-relative
paths everywhere, **agent findings/reports included** — `plugins/white-hacker/skills/_shared/reference/finding-schema.json`
deterministically rejects an absolute `file`. **QA + security-audit evidence is local-only in
`.notes/{qa,security_audit}/`** (gitignored — never under `docs/`, never committed). **Dogfood:** review
our own ticket changes with the SHIPPED white-hacker (`plugins/white-hacker/`), improving it by use.
Canonical statement: `.claude/CLAUDE.md` § Security posture / QA flow.
