---
name: groom
description: Deep-groom a white-hacker ticket — verify repo/package/skill state, dependencies, scope, and feasibility before claiming it
allowed-tools: Read, Grep, Glob, Bash
---

# /groom <ticket-id>

Deep-groom a single white-hacker ticket before claiming it. Validates the ticket
against actual repo state — the skill/package layout, the shared contracts, the
ADRs, and the bd dependency graph — so you don't start on a stale assumption.

## Why This Exists

Tickets drift. A referenced skill dir may not exist, a cited ADR may have been
superseded, a `_shared` contract may have moved, or a blocker may still be open.
This command catches those gaps before you write a line of code, per Policy 8
(read before you write — groom each task right before doing it).

## Usage

```
/groom wh-abc123              # Deep-groom one ticket
```

Always groom ONE ticket at a time.

## Process

### Phase 1 — Load Context

```bash
bd show <ticket-id>
```

Read the ticket description, design, acceptance/verification criteria, and notes.
Note the package/skill it touches and the **Files to Modify** list.

### Phase 2 — Repo / Package State Verification

Check the ticket's assumptions against actual repo state:

| Check | How |
|-------|-----|
| Referenced skill/package exists | `ls plugins/white-hacker/skills/<skill>/` |
| `SKILL.md` present | `ls plugins/white-hacker/skills/<skill>/SKILL.md` |
| ADR-005 caps hold | `name`≤64, `description`≤1024, `SKILL.md`<500 lines, `reference/` one level deep — enforced by `plugins/white-hacker/skills/ai-attack-kb/scripts/lint_skill.py` |
| Package shape present | `ls plugins/white-hacker/skills/<skill>/scripts/{pyproject.toml,conftest.py,tests/}` |
| Cited ADRs resolve | `grep -n "ADR-0NN" docs/ARD.md` (ADRs are append-only — superseded ones say so) |
| Every named file is real | `ls`/Read each path in "Files to Modify" — a missing path is a grooming defect |

### Phase 3 — Dependency Check

Verify everything the ticket assumes is in place:

- [ ] **Beads blockers** — `bd blocked` / `bd show <id>`: are all `bd dep` blockers closed?
- [ ] **Shared contract** — does it consume `_shared/reference/finding-schema.json`? Confirm it exists and the fields used are present.
- [ ] **Shared utils** — does it call `_shared/scripts/{validate_findings.py,degradation.py}`? Read the export before building against it.
- [ ] **Tool/capability change** — if it adds or swaps a tool, is there a `_shared/reference/tool-registry.md` capability entry (ADR-015: depend on the capability, not the brand)?
- [ ] **KB linkage** — if it emits findings, do referenced `kb_refs` / `AISEC-…` ids resolve in `ai-attack-kb/reference/`?

### Phase 4 — Scope Check (Policy 3 — surgical)

| Metric | Threshold | Action |
|--------|-----------|--------|
| Skills/packages touched | > 1 | Should probably split |
| Mixes a skill + `_shared` | mixed | Consider splitting (`_shared` change = its own ticket) |
| Bundles a refactor with a fix | any | Split — stale neighbours get a NEW ticket, never a drive-by |
| Files in "Files to Modify" | sprawling | Split — two focused tickets beat one |

A fix never bundles a refactor. If grooming reveals a stale neighbour outside the
ticket's files, file a NEW bd task; do not widen this one.

### Phase 5 — Feasibility Simulation

For the package/skill the ticket plans to change:

1. **Find the pattern** — locate a similar existing skill/package and compare structure (e.g. `sec-vuln-scan/`, `deps-scan/`) before inventing a new shape.
2. **Verify cross-references resolve** — artifact-chain JSON validates against `finding-schema.json`; `kb_refs` resolve; the capability interface the ticket names exists (ADR-015).
3. **Would the package tests pass?** — `uv run --project plugins/white-hacker/skills/<skill>/scripts pytest plugins/white-hacker/skills/<skill>/scripts/tests -q` (never bare python/pytest, Policy 12). If a `scripts/` package is in scope, run it now to establish a green baseline.
4. **Check naming conventions** — findings `F-NNN` (`^F-[0-9]{3,}$`), KB ids `AISEC-<CLASS>-<NNN>`, skill frontmatter `name`/`description`, artifact filenames in the `THREAT_MODEL → SCAN-PLAN → VULN-FINDINGS → TRIAGE → PATCHES` chain.

### Phase 6 — Report

```
================================================================
GROOMING REPORT: <ticket-id>
================================================================

REPO / PACKAGE STATE:
  Skill/package exists:   [OK | MISSING: <path>]
  SKILL.md + ADR-005:     [OK | OVER CAP: <which> | N/A — no skill]
  Package shape:          [OK | MISSING: <pyproject.toml|conftest.py|tests/>]
  Cited ADRs resolve:     [ALL RESOLVE | DANGLING: <ids> | SUPERSEDED: <ids>]
  Files to Modify real:   [ALL EXIST | MISSING: <paths>]

DEPENDENCIES:
  Beads blockers:         [NONE | BLOCKED BY: <ids>]
  Shared contract/utils:  [MET | MISSING: <finding-schema.json|validate_findings.py|…>]
  Tool-registry entry:    [PRESENT | NEEDS ADD | N/A — not a tool change]

SCOPE (Policy 3):
  Skills touched: <N>  |  Touches _shared: <yes/no>  |  Bundled refactor: <yes/no>
  [OK | SPLIT RECOMMENDED — <reason>]

FEASIBILITY:
  Pattern reference:      plugins/white-hacker/skills/<similar-skill>/
  Package tests baseline: [GREEN | RED: <failures> | N/A — no scripts/]
  Cross-references:       [VALID | BROKEN: <schema|kb_refs|capability>]
  Naming conventions:     [PASS | ISSUES: <F-NNN|AISEC|frontmatter|artifact>]

================================================================
VERDICT: [READY | NEEDS UPDATE | NEEDS SPLIT]
================================================================
```

## Rules

1. **One ticket at a time.** Never batch-groom.
2. **Check actual state.** Don't trust the ticket's claims — `ls`/Read/grep every cited path; uncited "verified" is a grooming defect (Policy 8).
3. **Cite the decision, don't re-debate it.** If a structural question is settled, cite the ADR (`docs/ARD.md`) or `file:line` instead of re-arguing (Policy 1).
4. **Use `uv run`, never bare python/pytest.** Run package tests via `uv run --project … pytest` to establish a green baseline (Policy 12).
5. **Split before you bloat.** One package per ticket; a `_shared` change is its own ticket; stale neighbours get a NEW task — two focused tickets beat one sprawling one (Policy 3).
