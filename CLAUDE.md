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
  `claude plugin validate` — NOT ruff / mypy / coverage** (Policy 12; `.claude/commands/launch-team.md`).
- **Never** hand-author a ticket body or `bd create` a one-line description — including follow-ups a
  team files mid-wave (route them through `/design-ticket`; `.claude/commands/launch-team.md` Rule 8).
- **Re-groom off-template tickets to the template before launch** (`/groom`, or re-design via
  `/design-ticket`). A `bd update <id> --description=…` with the template-shaped body is the mechanism;
  never `bd edit` (it opens `$EDITOR` and blocks agents).

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
