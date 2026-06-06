# Self-Improvement Research — si:autonomous-skill-gen

> Source: workflow `self-improving-white-hacker-research` (w3b87zsau), agent `si:autonomous-skill-gen`

## Autonomous self-authoring of procedural memory (skills/KB) for a white-hat Claude Code agent

### The spec the agent must obey when writing a skill

A skill is just a directory with a `SKILL.md` (YAML frontmatter + Markdown body) plus optional `scripts/`, `references/`, `assets/` subdirs. The [Agent Skills specification](https://agentskills.io/specification) (Anthropic, open-sourced Dec 18 2025) fixes the hard constraints the self-writer must validate against:

| Field | Required | Hard limit / rule |
|---|---|---|
| `name` | yes | 1–64 chars, lowercase `a-z0-9` + hyphens, no leading/trailing/consecutive hyphens, **must match parent dir name**, no reserved words `anthropic`/`claude`, no XML tags |
| `description` | yes | 1–1024 chars, non-empty, third-person, says *what it does + when to use it*, no XML tags |
| `compatibility` | no | ≤500 chars |
| `metadata` | no | string→string map (use for `source`, `version`, `created`, `cwe`) |
| `license`, `allowed-tools` | no | `allowed-tools` is experimental, space-separated, e.g. `Bash(git:*) Read` |

Progressive-disclosure budget (from the spec and [best-practices doc](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)): only `name`+`description` (~100 tokens/skill) are pre-loaded at startup; the full `SKILL.md` body (keep **under 500 lines / <5000 tokens**) loads on activation; `references/*.md`, `scripts/`, `assets/` load *only when read*. Keep references **one level deep** from `SKILL.md` (Claude does partial `head -100` reads on nested chains and misses content), and give reference files >100 lines a table of contents. Validate with `skills-ref validate ./skill` from the [reference library](https://github.com/agentskills/agentskills).

This maps cleanly onto a security KB: the always-loaded index is the set of one-line `description`s ("Detects indirect prompt injection in tool-result text. Use when reviewing agent/MCP tool outputs…"), and the depth — payloads, CWE/ATLAS mappings, detection regexes, remediation — lives in `references/` and `scripts/`, consuming zero context until a matching task triggers it.

### Triggers for a self-write

Distinguish *capture* (cheap, automatic, regex-gated) from *commit* (gated, validated, human-approved) — the architecture used by [claude-reflect](https://github.com/BayramAnnakov/claude-reflect), which is the closest real 2026 implementation. Triggers for the security agent:

1. **Novel vuln class found** — the agent encountered a pattern not covered by any existing skill `description`. → propose a *new* skill (`detecting-<class>`).
2. **Recurring false-positive** — same finding flagged then dismissed N≥2 times. → *patch* the offending skill's "false positives / exclusions" section, not a new skill.
3. **User correction** — "no, that's not exploitable because…", "use X not Y". Captured every prompt by a hook (Stage-1 regex catches `no, use`, `don't`, `actually`, `remember:` with a 0.60–0.95 confidence score), validated semantically at review time.
4. **New technique from a feed** — a new MITRE ATLAS technique (e.g. v5.4.0's *Publish Poisoned AI Agent Tool*, *Escape to Host*) or OWASP Top-10-for-Agentic-Applications-2026 risk (ASI01 Goal Hijack, ASI10 Rogue Agents). A scheduled routine ingests the feed and proposes KB entries.

### Management actions (create / patch / edit / write_file)

- **create**: new skill dir + `SKILL.md` (+ `references/`). Use when no existing `description` overlaps the new capability.
- **patch**: append/replace a *section* of an existing skill (add a false-positive exclusion, add a new payload variant to `references/payloads.md`). Default action — prefer over create to fight skill sprawl.
- **edit**: tighten the `name`/`description` for triggering accuracy (the metadata is what Claude uses to select among 100+ skills).
- **write_file / consolidate**: dedup pass — merge semantically-similar entries into one canonical version (claude-reflect's `/reflect --dedupe`).

### Guardrails (the non-negotiables)

- **Schema caps enforced mechanically**, not by trust: a `scripts/validate_skill.py` (or `skills-ref validate`) checks name≤64, desc≤1024, name==dirname, no reserved words, body<500 lines, references one-level-deep. Wire it as a **PreToolUse hook** so a malformed self-write is *blocked* (exit code 2) before `Write` touches disk — hooks are deterministic and "cannot hallucinate," unlike CLAUDE.md guidance which is advisory.
- **Dedup vs existing**: before create, embed/grep the proposed `description` against all existing skill descriptions; if cosine-similar or keyword-overlapping above threshold, route to *patch* instead. This is the single biggest defense against an always-loaded index that bloats over time.
- **Human-approval gate**: *every* self-write to procedural memory is a proposal, never an autocommit. claude-reflect's `/reflect` shows a table with Apply / Edit-before-applying / Skip per item; that human review "remains the final approval gate before any modifications." For the security agent, commit proposals as a **git branch + PR**, never to the default branch — so the diff is reviewable and revertible.
- **Must-link-a-source for AI-threat entries**: any KB entry describing an attack technique MUST carry `metadata.source` with a real URL/ID (MITRE ATLAS `AML.Txxxx`, OWASP `ASIxx`, CVE, or a dated feed item) and a `metadata.retrieved` date. Add this as a *blocking* validator rule for entries tagged `ai-threat` — refuse to write an unsourced threat claim. This is what keeps the knowledge base current and auditable rather than hallucinated; ground it in living sources ([MITRE ATLAS](https://atlas.mitre.org/), now v5.4.0+, 16 tactics/84 techniques; [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)).
- **No time-bombs**: per best-practices, never write "before August 2025 use X"; use a collapsible "Old patterns / deprecated" section so entries age gracefully.
- **Avoid over-broad descriptions**: a security skill whose `description` triggers on everything poisons selection for all other skills — keep triggers specific.

### Concrete capture-learning workflow

```
SKILL.md  →  capturing-learnings  (the meta-skill that writes other skills)
Workflow checklist (copy into response, check off):
- [ ] 1. CLASSIFY trigger: novel-class | false-positive | user-correction | feed-item
- [ ] 2. DEDUP: grep/embed proposed description vs existing skill descriptions
        → overlap? switch action create→patch, name the target skill
- [ ] 3. SOURCE: if ai-threat, resolve a real source id+URL+date; abort if none
- [ ] 4. DRAFT: minimal SKILL.md (name<=64, desc<=1024, third person, body<500 lines)
        depth → references/<topic>.md (one level deep, TOC if >100 lines)
        detection logic → scripts/ (deterministic, self-documenting constants)
- [ ] 5. VALIDATE: run scripts/validate_skill.py (== PreToolUse gate); fix loop
- [ ] 6. SELF-CRITIQUE: is this generalizable or a single-incident overfit?
        is the claim accurate, or "technically true but misleading"?
- [ ] 7. PROPOSE: write to a feature branch; open PR with diff + rationale + source
- [ ] 8. HUMAN GATE: Apply / Edit / Skip → only merge on human approval
- [ ] 9. POST-MERGE: log to audit trail (who/when/source/diff)
```

Hooks wire this into Claude Code natively: a `UserPromptSubmit`/`PostToolUse` hook runs `capture_learning.py` to *queue* candidates cheaply (regex, no LLM cost); a `SessionStart` hook surfaces the pending queue; a `post-commit` hook reminds to run `/reflect`. The expensive semantic validation and the write happen only inside the gated `/reflect`-style review. A **scheduled routine** (cron) handles the feed-ingestion trigger: pull ATLAS/OWASP/CVE deltas, draft proposals, open a PR, and leave them for human review — never auto-merge.

### Safety checklist before any self-write is committed

- [ ] Frontmatter valid: `name` ≤64 + matches dir + no reserved words; `description` ≤1024, third person, what+when.
- [ ] Body <500 lines; depth pushed to `references/` one level deep; refs >100 lines have a TOC.
- [ ] `skills-ref validate` / `validate_skill.py` passes (enforced by PreToolUse hook, not trust).
- [ ] Dedup checked: not a near-duplicate of an existing skill (else it's a patch).
- [ ] If `ai-threat`: `metadata.source` = real ATLAS/OWASP/CVE id + URL + `retrieved` date present.
- [ ] No time-sensitive phrasing; deprecated content in an "Old patterns" section.
- [ ] Description triggers are specific (won't hijack selection of other skills).
- [ ] Self-critique passed: generalizable, accurate, not an overfit to one incident.
- [ ] Written to a branch/PR with a human-readable diff + rationale — never default branch, never autocommit.
- [ ] Human approved (Apply/Edit/Skip); decision + diff + source journaled to an audit log.
- [ ] No secrets/credentials/live exploit payloads that shouldn't persist embedded in the committed text.


## Key takeaways

- Enforce the spec caps mechanically, not by trust: name<=64 + must equal parent dir name + no 'anthropic'/'claude' reserved words; description<=1024 third-person what+when. Wire skills-ref validate (or a validate_skill.py) as a PreToolUse hook that blocks (exit 2) any malformed self-write before Write touches disk.
- Keep the always-loaded index tiny by treating each skill's one-line description as the index entry (~100 tokens pre-loaded); push all depth (payloads, CWE/ATLAS mappings, detection regex) into references/ and scripts/ which cost zero context until read. SKILL.md body must stay under 500 lines / ~5000 tokens.
- References must be exactly one level deep from SKILL.md — Claude does partial head -100 reads on nested chains and silently misses content. Give any reference file >100 lines a table of contents.
- Separate cheap CAPTURE (every-prompt regex hook, confidence-scored, queues candidates with no LLM cost) from gated COMMIT (semantic validation + write happen only inside a human-reviewed /reflect-style step). This is the claude-reflect two-tier pattern and it is the right shape for the security agent.
- Four triggers, each routing to a specific action: novel vuln class -> create new skill; recurring false-positive (N>=2 dismissals) -> patch the skill's exclusions section; user correction -> patch/edit; new technique from a feed -> scheduled routine drafts a PR. Default to PATCH over CREATE to fight skill-index sprawl.
- Dedup before every create: embed/grep the proposed description against all existing descriptions; on overlap, convert create->patch. Provide a consolidate/--dedupe pass that merges semantically-similar entries into one canonical version.
- Mandatory source-linking for AI-threat entries: a blocking validator rule requires metadata.source (real MITRE ATLAS AML.Txxxx, OWASP ASIxx, or CVE) + URL + retrieved date; refuse to persist an unsourced threat claim. This is what keeps the KB current and auditable instead of hallucinated.
- Keep the threat KB pinned to living sources and refresh on a cron routine: MITRE ATLAS (v5.4.0+, 16 tactics/84 techniques, added 'Publish Poisoned AI Agent Tool' and 'Escape to Host') and OWASP Top 10 for Agentic Applications 2026 (ASI01 Goal Hijack ... ASI10 Rogue Agents). Ingest deltas, draft proposals, open PRs — never auto-merge.
- Human-approval gate is non-negotiable: every self-write is a proposal committed to a feature branch + PR (never the default branch, never autocommit), reviewed as a diff with Apply/Edit/Skip, and the decision+diff+source is journaled to an audit log for revertibility.
- Add a self-critique step before proposing: is the learning generalizable or an overfit to one incident? Is it 'technically true but misleading'? Claude can misattribute a single failure — the human review and this check catch overgeneralization.
- Avoid time-bombs and over-broad triggers: no 'before August 2025' phrasing (use a collapsible Old-patterns section); keep security-skill descriptions specific so they don't hijack skill selection for everything.
- Native Claude Code primitives cover the whole loop: hooks for deterministic capture+validation gates, a 'capturing-learnings' meta-skill for the create/patch workflow, slash command for the review/approval step, scheduled routine/cron for feed ingestion, and git PR as the durable human-in-the-loop checkpoint.

## Sources

- https://agentskills.io/specification
- https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices
- https://github.com/agentskills/agentskills
- https://github.com/BayramAnnakov/claude-reflect
- https://www.blog.brightcoding.dev/2026/03/24/claude-reflect-transform-claude-code-into-a-self-learning-powerhouse
- https://www.mindstudio.ai/blog/self-learning-claude-code-skill-learnings-md
- https://code.claude.com/docs/en/agent-sdk/hooks
- https://www.pixelmojo.io/blogs/claude-code-hooks-production-quality-ci-cd-patterns
- https://atlas.mitre.org/
- https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/
- https://zenity.io/blog/current-events/mitre-atlas-ai-security
- https://simonwillison.net/2025/Dec/19/agent-skills/
- https://arxiv.org/html/2606.01138

