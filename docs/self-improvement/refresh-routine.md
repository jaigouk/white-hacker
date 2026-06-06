# KB refresh routine (sec-kb-refresh) — cadence + how to schedule it

How to run `sec-kb-refresh` (T-8.6) as a recurring, off-peak job that opens a **draft PR** of dated
KB candidate entries. **This document defines the routine; it does NOT create a live schedule.**
The operator creates it deliberately (see below) — nothing here arms a timer by itself.

> **Operator note (this project):** scheduled/autonomous runs are **opt-in only**. The refresh
> poller `poll_feeds.py` is fully usable **manually**; only create the cloud Routine if you want
> hands-off currency, and you can disable it any time.

## What the routine runs
- `python .claude/skills/sec-kb-refresh/scripts/poll_feeds.py <feed> <fetched-content>` per feed,
  diffing against `evals/feed-state.json` (deltas only), then drafts schema-conforming entries,
  runs `validate_kb` + `dedupe_kb`, and opens a **draft PR** (it **never auto-merges**). It runs to
  completion on a fresh clone (stdlib + pyyaml; jsonschema for the validate step).

## Cadence tiers (si-08 §4) — match the feed's update rate; **hourly minimum** granularity
| Tier | Cadence | Feeds (access type) |
|------|---------|---------------------|
| **daily** | once/day, off-peak | OSV.dev query + GHSA REST (JSON APIs); arXiv cs.CR (RSS, LLM-filtered); Embrace The Red + Simon Willison (RSS) |
| **weekly** | once/week | Microsoft / Google security blogs (RSS); NIST CSRC project pages (HTML) |
| **monthly** | once/month (version-string diff) | OWASP LLM / Agentic / MCP Top 10 (HTML); MITRE ATLAS `dist/` (YAML/STIX) |

Cadence is **hourly-minimum** (the scheduler's floor); pick the slowest cadence that keeps each
feed current. The routine **shares the account usage quota → schedule it off-peak.**

## How to create it (operator, opt-in)
This repo's convention is **no autonomous schedulers by default.** When you want it:
- Use the **`/schedule`** skill (a cloud Routine) with an off-peak daily cron for the daily tier
  (and separate weekly/monthly routines, or one daily routine that internally rate-limits the
  slower feeds via `feed-state.json`). Point it at the pipeline above.
- The Routine must: run on a fresh clone, open a **draft PR**, and **never auto-merge** (the
  Phase-9 keep-or-revert gate + human review decide what merges).

## How to disable it
- Remove/disable the Routine (`/schedule` manage, or `CronDelete` for a session job). The poller
  and `feed-state.json` remain for manual runs.

## Provenance / safety
- Touches the **fast tier only** (`ai-attack-kb/reference/`); never the stable `_shared/reference/`
  checklists or the frozen `evals/` corpus + gate.
- Live fetching honors the egress allow-list in `confine_self_writes` (T-8.4); entries carry
  mandatory `source`+`url`+`retrieved`; no secret values are ever written.
