---
name: groom
description: Deep-groom a white-hacker ticket — verify template conformance, repo/package/skill state, dependencies, scope, and feasibility before claiming it; persist the verdict to bd notes
allowed-tools: Read, Grep, Glob, Bash
---

# /groom <ticket-id>

Deep-groom a single white-hacker ticket before claiming it. Validates the ticket
against actual repo state — the skill/package layout, the shared contracts, the
ADRs, and the bd dependency graph — so you don't start on a stale assumption.

## Why This Exists

Tickets drift. A referenced skill dir may not exist, a cited ADR may have been
superseded, a `_shared` contract may have moved, a blocker may still be open, a
cited `file:line` may have shifted, a body claim may be **falsified by the live
code**, or a coordination "open question" may already be **resolved** by a now-closed
spike. The body may also be **off-template** (a thin paragraph instead of the type
template). This command catches those gaps before you write a line of code, per
Policy 8 (read before you write — groom each task right before doing it), and
**records the verdict + corrections on the ticket** so the next session inherits them.

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
Note the ticket **type** (task / bug / spike), the package/skill it touches, and the
**Files to Modify** list.

**Template conformance (Policy 11 — templates are mandatory).** Confirm the body follows its
type template under `docs/beads_templates/`:
- **task** (`beads-ticket-template.md`): Goal · Steps · Files to Modify · Acceptance Criteria · Quality Gates · Rollback
- **bug** (`beads-bug-template.md`): Reproduction · Expected vs Actual · Root-cause `file:line` · regression-test AC · Severity↔Priority · Rollback
- **spike** (`beads-spike-template.md`): Problem · Research questions · Exit criteria · Time box

An **off-template** ticket (a thin paragraph, missing sections, or a bug with no repro/root-cause)
is NOT ready. Re-groom it to the template HERE — rewrite via `bd update <id> --description="…"` with
the template-shaped body (preserve any existing DONE/increment notes) — or re-design via
`/design-ticket --type=<…>`. For a **bug**, also confirm the **priority matches the severity rubric**
(P0 pipeline-broken / missed-vuln · P1 wrong-result on common input · P2 blocks-one-flow or a live
security defect · P3 cosmetic); flag a mismatch.

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
| Cited `file:line` still accurate | Read each — line numbers DRIFT (a ±N shift is fine; a *wrong symbol* is a defect). Correct stale refs (e.g. a path that moved `deps-scan/reference/` → `_shared/reference/`) |
| No body claim FALSIFIED by live code | If the code contradicts a body assertion, the **source wins** (Policy 7) — **STRIKE** the stale claim in the body and record the correction; never weaken it to "both might be right" |

### Phase 3 — Dependency Check

Verify everything the ticket assumes is in place:

- [ ] **Beads blockers** — `bd blocked` / `bd show <id>`: are all `bd dep` blockers closed?
- [ ] **Coordination / open questions resolved** — if the body cites a spike or a sibling's decision as an OPEN question ("confirm the path with wh-NNN RQ-B", "schema finalized by wh-MMM"), check that ticket's status: a **closed spike may have RESOLVED it**, and the shipped code may already encode the answer (verify against the live tree — e.g. a Gate-2 hook hardcoding the agreed path). A resolved coordination item is a body **correction**, not a blocker — strike the "confirm before step 1" framing.
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
3. **Would the package gates pass?** — the REAL gates (Policy 12; **NOT ruff / mypy / coverage**): `nice -n 10 uv run --project plugins/white-hacker/skills/<skill>/scripts --with pytest pytest plugins/white-hacker/skills/<skill>/scripts/tests -q` · `uv run python packaging/validate_manifest.py .` · `claude plugin validate ./plugins/white-hacker` (never bare python/pytest). If a `scripts/` package is in scope, run the package test now for a green baseline. Outer-loop tickets (KB/registry/eval corpus) also: `evals/score.py` + `evals/keep_or_revert.py`.
4. **Check naming conventions** — findings `F-NNN` (`^F-[0-9]{3,}$`), KB ids `AISEC-<CLASS>-<NNN>`, skill frontmatter `name`/`description`, artifact filenames in the `THREAT_MODEL → SCAN-PLAN → VULN-FINDINGS → TRIAGE → PATCHES` chain.

### Phase 6 — Report

```
================================================================
GROOMING REPORT: <ticket-id>
================================================================

TEMPLATE / BODY:
  Type:                   [task | bug | spike]
  Template conformance:   [OK | OFF-TEMPLATE — re-groomed to <template> | missing: <sections>]
  Cited file:line drift:  [ACCURATE | CORRECTED: <ref→ref> | DANGLING: <ref>]
  Falsified body claims:  [NONE | STRUCK: <claim> (source: <file:line>)]
  Bug priority vs rubric: [MATCHES | MISMATCH: <P? → P?> | N/A — not a bug]

REPO / PACKAGE STATE:
  Skill/package exists:   [OK | MISSING: <path>]
  SKILL.md + ADR-005:     [OK | OVER CAP: <which> | N/A — no skill]
  Package shape:          [OK | MISSING: <pyproject.toml|conftest.py|tests/>]
  Cited ADRs resolve:     [ALL RESOLVE | DANGLING: <ids> | SUPERSEDED: <ids>]
  Files to Modify real:   [ALL EXIST | MISSING: <paths>]

DEPENDENCIES:
  Beads blockers:         [NONE | BLOCKED BY: <ids>]
  Coordination resolved:  [N/A | RESOLVED by <closed-spike-id> — body corrected | STILL OPEN: <id>]
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

### Phase 7 — Persist the Verdict

The printed report is ephemeral. Record the outcome on the ticket so the next session / the dev
inherits it (this is how a wave stays groomed across sessions):

```bash
bd update <ticket-id> --notes="GROOMED <YYYY-MM-DD> — VERDICT: <READY|NEEDS UPDATE|NEEDS SPLIT>. <corrections: stale paths fixed (old→new), claims struck (source file:line), coordination resolved, cited file:line you read>."
```

If grooming corrected the BODY (off-template, stale path, falsified claim, resolved coordination),
also rewrite it: `bd update <ticket-id> --description="…"` with the template-shaped body, then
`bd export -o .beads/issues.jsonl` to persist.

**Public repo (binding).** `--notes`/`--description` export to the git-tracked `.beads/issues.jsonl`.
Use **repo-relative POSIX paths only** — NEVER absolute/home paths (`/Users/…`, `~`), usernames,
tool-install locations, or machine details (`.claude/CLAUDE.md` § Security posture). Machine-specific
notes belong in `.notes/` (gitignored), never in a bd ticket.

## Rules

1. **One ticket at a time.** Never batch-groom.
2. **Check actual state.** Don't trust the ticket's claims — `ls`/Read/grep every cited path; uncited "verified" is a grooming defect (Policy 8).
3. **Cite the decision, don't re-debate it.** If a structural question is settled, cite the ADR (`docs/ARD.md`) or `file:line` instead of re-arguing (Policy 1).
4. **Use `uv run`, never bare python/pytest.** Run package tests via `uv run --project … pytest` to establish a green baseline (Policy 12).
5. **Split before you bloat.** One package per ticket; a `_shared` change is its own ticket; stale neighbours get a NEW task — two focused tickets beat one sprawling one (Policy 3).
6. **Templates are mandatory (Policy 11).** An off-template ticket is NOT ready — re-groom it to its type template (or re-design via `/design-ticket`) before launch. Bugs especially need a `file:line` root cause, a regression-test AC, and a severity-matched priority. The real gates are pytest + manifest + plugin-validate — **NOT ruff / mypy / coverage**.
7. **Source wins on conflict (Policy 7).** When live code contradicts the body, STRIKE the stale claim and cite the `file:line`; a closed spike may have already resolved a coordination "open question". Never average to "both might be right".
8. **Persist the verdict.** Record GROOMED/VERDICT + corrections to `bd update <id> --notes` (Phase 7) — the printed report is not enough. Repo-relative paths only, no machine data (it exports to the public `.beads/issues.jsonl`).
