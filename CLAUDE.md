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


## Build & Test

_Add your build and test commands here_

```bash
# Example:
# npm install
# npm test
```

### Resource discipline (CPU & I/O)

This dev machine runs endpoint security (CrowdStrike) doing on-access file scanning. Saturating all CPU cores — or fanning out parallel Python/builds — serializes I/O **system-wide** and freezes the UI even with RAM free (RAM is not the bottleneck; more cores would not help — work expands to fill them). Every command-running agent in `.claude/agents/` carries these rules **inline** (subagents don't reliably inherit this file); keep this canonical copy in sync:

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
no username, no installed-tool locations, no machine-environment / self-audit logs. Use repo-relative
paths everywhere, **agent findings/reports included** — `plugins/white-hacker/skills/_shared/reference/finding-schema.json`
deterministically rejects an absolute `file`. `docs/qa/` and `.notes/` are gitignored (local-only).
Canonical statement: `.claude/CLAUDE.md` § Security posture.
