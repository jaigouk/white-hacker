---
name: groom
description: Deep-groom an infrastructure ticket — verify scope, dependencies, storage, and deployment feasibility
allowed-tools: Read, Grep, Glob, Bash
---

# /groom <ticket-id>

Deep-groom a single infrastructure ticket before claiming it. Validates the ticket against actual cluster state and repo contents.

## Why This Exists

Infrastructure tickets often have stale assumptions — a PV size that doesn't fit, a port that's already taken, a dependency that doesn't exist yet. This command catches those gaps before you start working.

## Usage

```
/groom beads-abc123           # Deep-groom one ticket
```

Always groom ONE ticket at a time.

## Process

### Phase 1 — Load Context

```bash
bd show <ticket-id>
```

Read the ticket description, acceptance criteria, and any notes.

### Phase 2 — Cluster State Verification

Check the ticket's assumptions against actual repo state:

| Check | How |
|-------|-----|
| Referenced apps exist | `ls apps/base/<app>/` |
| Referenced infra exists | `ls infrastructure/base/<component>/` |
| Storage available | Compare ticket's PV needs vs README.md allocations |
| Ports available | `grep -rn "nodePort:" apps/ infrastructure/` |
| HelmRepo exists | `ls infrastructure/base/helm-repos/` |
| Namespace exists | `grep -rn "kind: Namespace" apps/base/<app>/` |

### Phase 3 — Dependency Check

Verify all dependencies the ticket assumes:

- [ ] **Services** — does the ticket need PostgreSQL, Redis, MinIO? Are they deployed?
- [ ] **Secrets** — does the ticket reference Vault paths? Is ESO configured?
- [ ] **Storage** — does the ticket need PVs? Is the StorageClass available?
- [ ] **Helm repos** — does the ticket use a chart? Is the HelmRepository registered?
- [ ] **Blocking tickets** — are there `bd dep` dependencies? Are they closed?

### Phase 4 — Scope Check

| Metric | Threshold | Action |
|--------|-----------|--------|
| New files to create | > 8 | Consider splitting |
| Directories touched | > 3 | Consider splitting |
| Multiple namespaces | > 1 | Should probably split |
| Both infra + app changes | mixed | Consider splitting |

### Phase 5 — Feasibility Simulation

For each manifest the ticket plans to create or modify:

1. **Check the pattern** — find a similar existing app and compare structure
2. **Verify references** — do all cross-references resolve? (service selectors, PVC→PV, secret keys)
3. **Validate kustomize** — would the planned kustomization.yaml build?
4. **Check naming** — do names follow conventions?

### Phase 6 — Report

```
================================================================
GROOMING REPORT: <ticket-id>
================================================================

CLUSTER STATE:
  Storage available:    [OK | WARNING: only Xgi left on pi01]
  Port conflicts:       [NONE | CONFLICT: port N used by <service>]
  Dependencies met:     [ALL MET | MISSING: <list>]
  HelmRepo available:   [YES | NEEDS CREATION]

SCOPE:
  New files: <N>  |  Directories: <N>  |  Namespaces: <N>
  [OK | SPLIT RECOMMENDED — <reason>]

FEASIBILITY:
  Pattern reference:    apps/base/<similar-app>/
  Naming conventions:   [PASS | ISSUES: <list>]
  Cross-references:     [VALID | BROKEN: <list>]

DEPENDENCIES:
  Beads blockers:       [NONE | BLOCKED BY: <ids>]
  Service dependencies: [MET | MISSING: <list>]

================================================================
VERDICT: [READY | NEEDS UPDATE | NEEDS SPLIT]
================================================================
```

## Rules

1. **One ticket at a time.** Never batch-groom.
2. **Check actual state.** Don't trust the ticket's claims — verify against the repo.
3. **Verify storage math.** Check README.md allocations before approving PV changes.
4. **Split before you bloat.** Two focused tickets beat one sprawling one.
