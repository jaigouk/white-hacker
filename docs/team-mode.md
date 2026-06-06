# white-hacker in a team (TL / QA / Dev / white-hacker)

How to run the security review in the two supported execution modes, and how it gates a team's
merge. The agent definition `.claude/agents/white-hacker.md` (§Team-workflow) is the behavioral
source of truth; this doc is the operator guide + spawn prompts.

## Mode matrix

| Mode | When | How findings return | Default? |
|------|------|---------------------|----------|
| **Sequential / subagent** | The lead (or `/security-review`) invokes white-hacker at the review phase, after Dev implements + QA tests. | Returns **only** the `TRIAGE.json` summary + the `SECURITY-REPORT.md` path (never raw discovery). | ✅ default |
| **Team mode** | A persistent agent-team where white-hacker is a standing teammate. **Opt-in, experimental.** | Routes findings to the **tech-lead** via `SendMessage`; exits cleanly on WAIT. | opt-in |

### Sequential / subagent mode (default)
The lead spawns white-hacker as a subagent for the review phase. It runs the inner loop
(threat-model → detect → discovery → triage → report) and returns the **triaged summary + report
path only**. This is the recommended mode for almost everything — no special flags.

### Team mode (opt-in, experimental)
Enable agent teams with the experimental flag **`CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`** (verify
the exact flag name + the minimum Claude Code version against the current Claude Code docs before
relying on it — this is an experimental surface that may change). In team mode white-hacker is a
standing **teammate**:
- **On its first turn** it loads `SendMessage` (`ToolSearch({query:"select:SendMessage"})`); if that
  doesn't load, it replies "SendMessage unavailable; cannot route findings" and exits.
- It sends findings to the **tech-lead**, **not** the dev (the lead owns merge/blocking decisions).
- On **WAIT** states (nothing to review yet) it **exits cleanly** rather than spinning.

## Spawn prompt (team mode) — route to the tech-lead

> **Carry-over caveat (load-bearing, PLAN §7.1):** a subagent's `skills` / `mcpServers` config does
> **NOT** carry over when it runs as a **teammate**. So the spawn prompt must inline the operational
> detail the teammate needs — it can't assume the `sec-*` skills auto-load. Put the methodology
> pointer (run the `/security-review` loop), the return contract, and the routing rule in the
> **spawn prompt** itself.

```
You are the white-hacker (senior security engineer) on this team. Run the security review loop
(threat-model → detect → discovery → triage → report) on the current diff. Return ONLY the
TRIAGE.json summary (counts + per-finding {file,line,category,severity,owasp}) and the
SECURITY-REPORT.md path — never raw discovery output, never secret values. SendMessage your
findings to the TECH-LEAD (not the dev). If there is nothing to review yet (WAIT), exit cleanly.
Do not run /sec-patch unless the tech-lead explicitly asks.
```

## Merge gate (team mode)
The lead must not treat the review as "complete" until white-hacker actually produced its triaged
artifact. The **`gate_review`** hook (`.claude/hooks/gate_review.sh`) backs this on a
`TaskCompleted` / `TeammateIdle` event: it blocks (exit 2) while `TRIAGE.json` is absent, and once
present emits **only** the summary counts + the report path (never raw discovery). Register it as a
composable `hooks` entry alongside `confine_patch_writes` + `guard_bash` (ADR-016) — registration is
the one operator-authorized step (committed `.claude/settings.json`).

## Return contract (both modes)
Triaged-only: `{summary.counts, per-finding (file,line,category,severity,owasp,first_link), report
path}`. Never raw discovery candidates; never secret values (decision-makers see only
`{file,line,category,diff}`). CI gates the same JSON on `counts.high == 0` (`ci_gate.py`).
