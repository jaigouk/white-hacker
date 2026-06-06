---
name: sec-kb-refresh
description: Poll authoritative AI-threat feeds (OWASP GenAI, MITRE ATLAS, OSV/GHSA, trackers), extract NEW attack techniques AND newly-useful security tools, and propose dated entries (KB + tool-registry) with source provenance for human approval. Use on a schedule (routine) or manually to keep both current.
disable-model-invocation: true
---

# sec-kb-refresh — the input arm (feeds → dated draft entries → PR)

The OUTER loop's **currency arm**: it ingests "new ways to hack AI products." It polls the
authoritative feeds (`docs/research/si-07-threat-feeds.md`), extracts **new techniques** *and*
**newly-useful tools**, and proposes **dated, sourced, schema-conforming** entries — as a **draft PR,
never auto-merged**. It touches the **fast tier only** (`ai-attack-kb/reference/`); the stable
`_shared/reference/` checklists are out of scope (cadence reconcile).

## Pipeline (`scripts/poll_feeds.py`, tested on recorded fixtures — no network in tests)
1. **Poll incrementally.** For each feed, fetch and parse, then **diff against last-seen markers in
   `evals/feed-state.json`** so only **deltas** are processed (an unchanged feed yields zero new
   items). Parsers cover OSV query JSON, MITRE ATLAS YAML, and atom/RSS (OWASP/blog/arXiv).
   *Live* fetching honors the egress allow-list enforced by `confine_self_writes` (T-8.4).
2. **Extract.** LLM-extract each new item into a candidate technique **or a newly-useful tool**, and
   map it to a `technique_class` (the five stems) + an ATLAS/OWASP/CVE **source**.
3. **Draft.** Render schema-conforming dated entries — **`metadata.source`+`url`+`retrieved` are
   mandatory** (`to_candidate_entry` / `render_entry`); `confidence` starts low (auto-extracted).
4. **Validate.** Run `validate_kb` (schema + size caps) and `dedupe_kb` (no duplicate ids; flag
   shared-xref merges) on the drafts before proposing.
5. **Propose.** Open a **draft PR, never auto-merge**. Also write the freshness digest consumed by
   `inject_cve_digest.sh` (SessionStart).

## Also proposes tools (ADR-015)
New scanners/red-team tools discovered in the feeds are proposed as additions to
**`_shared/reference/tool-registry.md`**, mapped to a capability — tooling knowledge evolves like
attack-technique knowledge. Same draft-PR / human-approval gate.

## Guardrails
- **Fast tier only**, **never auto-merge**, **draft PR** for a human; `disable-model-invocation`
  (manual / scheduled trigger, never self-fires). Confined by `confine_self_writes` (writes only the
  KB lane; the frozen corpus + gate scripts are denied). No secret values in any entry.

## Verification criteria (definition of done)
- [ ] Poller diffs incrementally vs `feed-state.json` and parses OSV/ATLAS/atom fixtures into candidates — `test_poll_feeds.py` (>1 feed type; unchanged feed → 0 new).
- [ ] Drafted entries pass `validate_kb` (mandatory source+url+retrieved) and `dedupe_kb` — tested on poller output.
- [ ] States "fast tier only / never auto-merge / draft PR" + proposes `tool-registry` additions (ADR-015); de-stubbed.
- [ ] No network in tests (fixtures only); live polling honors the egress allow-list.
