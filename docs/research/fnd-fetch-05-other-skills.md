# fetch:other-skills

> Source: workflow `white-hacker-research` (wycjclbk6), agent `fetch:other-skills`

## The defending-code-reference-harness skill suite (besides `vuln-scan`)

Anthropic's [defending-code-reference-harness](https://github.com/anthropics/defending-code-reference-harness) ships six Claude Code skills plus an autonomous `vuln-pipeline`. Beyond `vuln-scan`, the five relevant skills are **`quickstart`**, **`threat-model`**, **`triage`**, **`patch`**, and **`customize`**. They form a deliberate, file-passing pipeline: each writes JSON+MD artifacts that the next consumes, while sharing one hard safety invariant — **static analysis only; never execute target code**.

### How they chain

```
/quickstart (orientation)
      │
/threat-model → THREAT_MODEL.md ──┐
                                  ├─ steer
/vuln-scan → VULN-FINDINGS.json ──┘
      │
/triage VULN-FINDINGS.json → TRIAGE.json + TRIAGE.md   (verify, dedup, rank, route)
      │
/patch TRIAGE.json → PATCHES/bug_NN/{patch.diff, patch_result.json} + PATCHES.{md,json}
```

`customize` sits orthogonally: it re-targets the autonomous `vuln-pipeline` (the execution-verified backend that `patch` and `triage` can also ingest) to a new language/vuln-class/detector.

### Per-skill digest

| Skill | Frontmatter `name` / args | Input | Output | Core method |
|---|---|---|---|---|
| **quickstart** | `quickstart` · `[question]` (blank = intro) | repo docs/source, or a question | none (conversational) | Two modes by `$ARGUMENTS`: **Intro** (30-sec orient + offer "Guided first run" of threat-model→vuln-scan→triage on `targets/canary`) and **Help** (answers from repo as ground truth via a routing-map table, cites `> source:`, hands next command). Never runs `vuln-pipeline`. |
| **threat-model** | `threat-model` · `[bootstrap-then-interview\|bootstrap\|interview] <target-dir> [--vulns] [--design-doc] [--seed] [--fresh]` | codebase + optional CVE/design-doc/seed | `<target-dir>/THREAT_MODEL.md` (per `schema.md`) | Three modes; Step-0 safety preamble (static only, public DBs only — NVD/GHSA/trackers, no fuzzing/network). Interview uses the 4-question framework (what are we building / what can go wrong / what do we do / did we do well). Emits top-5 threats by likelihood×impact + open questions. |
| **triage** | `triage` · `<findings-path> [--auto] [--votes N] [--repo PATH] [--fp-rules FILE] [--fresh]` | scanner output (JSON/dir/markdown/pipeline `results/`) | `TRIAGE.json` + `TRIAGE.md` | Six phases: ingest/normalize → dedup (deterministic + 1 semantic agent) → **N-vote adversarial verify** (default 3, "default: scanner is WRONG", 16 exclusion rules) → rank by derived exploitability (preconditions×access level) → route (CODEOWNERS→git log→module) → output. Checkpointed via `_lib/checkpoint.py`. |
| **patch** | `patch` · `<findings-path> [--repo PATH] [--top N] [--id fNNN] [--model M] [--fresh]` | `TRIAGE.json` (canonical), `VULN-FINDINGS.json`, or pipeline dir | `PATCHES/bug_NN/{patch.diff,patch_result.json}`, `PATCHES.{md,json}` | Two modes: **exec** (delegate to `vuln-pipeline patch` ladder: build→reproduce→regress→re-attack) and **static** (per-finding patch subagent + isolated reviewer; inert diffs only). **Never applies diffs** — no `--apply` by design. |
| **customize** | `customize` · (interactive) | the repo itself | rewritten `harness/` prompts, parsers, target config | 5 steps: read 8+ pipeline files → 2-round interview → present plan → execute in dependency order → validate on a planted-bug canary. Maps every file to rewrite / light-edit / unchanged across six axes of variation. |

### Triage — the verification engine worth copying

`triage` is the most reusable design. Its **adversarial N-of-N voting** spawns `candidates × votes` independent `general-purpose` subagents, each told to assume the scanner is wrong and re-derive the claim from source. The verifier prompt enforces a 4-step procedure (read cited line → trace reachability backward and quote the first call-site `file:line` → hunt protections → stress-test each on *every* path) and a fixed verdict block (`VERDICT/CONFIDENCE/REFUTE_REASON/EXCLUSION_RULE/FIRST_LINK/RATIONALE`). The **16 exclusion rules** are a generic false-positive filter (volumetric DoS, test/dead code, intended design, memory-safety in safe langs, SSRF path-only, prompt-injection-into-LLM, auto-escaped-XSS-without-raw-hatch, UUID-flagged-predictable, theoretical TOCTOU, etc.). Ranking is independent of verification — severity comes from a preconditions × access-level matrix (0 preconds + unauth-remote = HIGH; 3+ or local = LOW), with a threat-model match allowed to bump at most one step. Noise tolerance (precision/recall/ask) decides tie-breaks. Output JSON contains every input finding exactly once (duplicates reference canonical).

### Cross-cutting design patterns (the load-bearing ones for a generic agent)

1. **Static-only invariant, restated in every subagent prompt.** No builds, no test runs, no dependency install, no network — applied to orchestrator *and* every Task. "Couldn't write a PoC" is explicitly weak evidence; high-confidence HIGHs recommend a *human-built* PoC instead. This makes the suite language-agnostic and safe to run on untrusted code.

2. **Prompt-injection isolation via context starvation.** `patch`'s reviewer subagent is deliberately given only `{file, line, category, diff}` — never the finding's `description`/`recommendation`/author `rationale` — so instructions injected into source-derived prose can't pass *both* the author and the gate. `triage`'s semantic-dedup agent likewise gets only id/file/line/category/title. **Every Task sets `subagent_type` explicitly; forking is banned** because a forked agent inherits the orchestrator's full context (all other findings, scanner prose), breaking independence. *Observed live during this research:* the `customize` SKILL.md repeatedly caused a fetcher model to "execute" its interview instead of reproducing it — concrete proof that skill/source text is treated as instructions and must be isolated.

3. **Capability removal, not capability gating.** `patch` has no `--apply` flag "by design: the capability isn't present, so it can't be prompt-injected into use." Write scope is whitelisted to `./PATCHES/` and `./.patch-state/` only; `find` and `git apply` are not in `allowed-tools`. This is stronger than asking the model to "be careful."

4. **File-backed checkpointing for long runs.** `triage`/`patch` persist per-phase JSON to `./.{triage,patch}-state/` via a single atomic `_lib/checkpoint.py` helper (`load/save/shard/append/reset/done`). `progress.json` is the single source of truth for resume; never glob stale shards. The **Write→`--from` pattern** keeps target-derived bytes out of Bash argv (heredoc/stdin could break out to shell). Useful for a generic agent that may exhaust context on large repos.

5. **Parallel-Task scaling with explicit ceilings.** All Task calls for a phase go in one assistant message (concurrent); shard into batches of ~40 above the spawn ceiling. There's a documented `async_launched` recovery path (parse completion notifications, or re-spawn a smaller synchronous batch — never poll transcript files).

6. **Verification class vs. outcome separation.** `patch.verified` records *how* it was checked (`ladder_passed`/`ladder_failed`/`static_review_only`) distinctly from `review` (ACCEPT/REJECT). Downstream tooling branches on the class. Mirrors `triage`'s split of `severity` (precondition-derived, used for sorting) from `severity_label` (presentation format: CVSS 3.1/4.0/OWASP/bug-bar).

7. **Interactive-by-default with `--auto` escape and `--fresh` reset.** `triage`, `threat-model`, `customize` interview via `AskUserQuestion` (batched, ≤4 questions/call, free-text via "Other"); `--auto` substitutes conservative defaults (treat all external entry points untrusted; precision tie-break). Every stateful skill takes `--fresh` to ignore checkpoints.

8. **Customize's abstraction insight** is the key to multi-language reach: the pipeline's generic shape is *agent crafts input → run target in sandbox → detector fires → verify/analyze/report*. Only the **prompts and the stack-trace parser (`asan.py`)** are domain-specific; orchestration (`cli.py`, `agent.py`, `docker_ops.py`, the flow files) is unchanged. A generic security agent should isolate detector/parser/prompt logic behind the same seam so TS/Go/Python/Java/AI targets swap cleanly.

These patterns — static-only invariant, adversarial multi-vote verification with a shared exclusion-rule list, context-starved isolated reviewers, capability removal, derived-exploitability ranking, and a parser/prompt seam for language portability — are exactly the reusable scaffolding for a generic white-hat review agent.


## Key takeaways

- Static-analysis-only is the suite's universal invariant — no build/run/install/network, restated in every subagent prompt and applied to orchestrator + all Tasks. This is what makes a review agent language-agnostic (TS/Go/Python/Java/AI) and safe on untrusted code; a generic agent should adopt it verbatim and explicitly note that 'no PoC' is weak evidence, recommending human-built PoCs for high-confidence HIGHs.
- Adversarial N-of-N voting (triage, default 3) is the most portable verification primitive: each independent subagent assumes the scanner is WRONG and re-derives from source via read→trace-reachability-backward→hunt-protections→stress-test-every-path, ending in a fixed VERDICT/CONFIDENCE/REFUTE_REASON/EXCLUSION_RULE/FIRST_LINK/RATIONALE block.
- The 16 exclusion rules in triage are a ready-made, language-neutral false-positive filter (volumetric DoS, test/dead code, intended design, memory-safety in safe langs, SSRF path-only, prompt-injection-into-LLM, auto-escaped XSS without raw-HTML hatch, UUID-flagged-predictable, theoretical TOCTOU, etc.) — reuse and extend per-stack via a --fp-rules-style hook.
- Prompt-injection defense is by context starvation: patch's reviewer sees only {file,line,category,diff} (never finding prose or author rationale) so injected instructions can't pass both author and gate; semantic-dedup agent sees only id/file/line/category/title. A generic agent must isolate source-derived text from the decision-making subagent.
- Always set subagent_type and never fork — forking leaks the orchestrator's full context (all findings, scanner prose) into every subagent and destroys verifier independence. Live confirmation: the customize SKILL.md repeatedly made a fetcher model 'execute' its interview instead of reproducing it, proving skill/source text is read as instructions.
- Capability removal beats capability gating: patch has no --apply flag 'by design' and whitelists writes to ./PATCHES/ and ./.patch-state/ only (no git apply, no find in allowed-tools). For a review agent, omit any code-mutating tool rather than instructing the model not to use it.
- Separate verification CLASS from OUTCOME: patch.verified = ladder_passed/ladder_failed/static_review_only is distinct from review = ACCEPT/REJECT; triage separates precondition-derived severity (sorting) from severity_label (CVSS 3.1/4.0/OWASP/bug-bar presentation). Downstream tooling branches on class, not outcome.
- Rank by DERIVED exploitability, not scanner category: severity = min over (precondition count, required access level) — 0 preconds + unauth-remote = HIGH, 3+/local-only = LOW — with a threat-model match allowed to bump at most one step. Keep ranking independent of the verify decision so 'real' never inflates into 'critical'.
- The suite chains via on-disk artifacts (THREAT_MODEL.md → VULN-FINDINGS.json → TRIAGE.json → PATCHES/), each skill consuming the prior's JSON; threat-model output steers the scan. A multi-skill design should pass structured JSON files (every input finding appearing exactly once, duplicates referencing a canonical) rather than conversational state.
- File-backed checkpointing (./.{triage,patch}-state/ via one atomic checkpoint.py with load/save/shard/append/reset/done; progress.json as single source of truth) plus the Write→--from pattern (keeps target bytes out of Bash argv) lets long runs resume after context exhaustion — essential for large multi-language repos.
- Customize's portability seam: only the prompts and the stack-trace parser (asan.py) are domain-specific; orchestration (cli.py, agent.py, docker_ops.py, flow files) stays unchanged across vuln-class/language/detector. Structure a generic agent so detector + parser + taxonomy prompts swap behind a stable orchestration layer, mapped along six axes (vuln class, target shape, detection mechanism, input modality, isolation boundary, dedup signature).
- Interactive-by-default with safe fallbacks: use batched AskUserQuestion (≤4 questions, free-text 'Other') to capture trust boundary, threat model, scoring standard, and noise tolerance; provide --auto (treat all external entry points untrusted, precision tie-break) and --fresh (ignore checkpoints). Parallelize all per-phase Tasks in one message, shard at ~40, with an async_launched recovery path.

## Sources

- https://github.com/anthropics/defending-code-reference-harness
- https://raw.githubusercontent.com/anthropics/defending-code-reference-harness/main/.claude/skills/threat-model/SKILL.md
- https://raw.githubusercontent.com/anthropics/defending-code-reference-harness/main/.claude/skills/triage/SKILL.md
- https://raw.githubusercontent.com/anthropics/defending-code-reference-harness/main/.claude/skills/patch/SKILL.md
- https://raw.githubusercontent.com/anthropics/defending-code-reference-harness/main/.claude/skills/customize/SKILL.md
- https://raw.githubusercontent.com/anthropics/defending-code-reference-harness/main/.claude/skills/quickstart/SKILL.md
- https://github.com/anthropics/defending-code-reference-harness/tree/main/.claude/skills
- https://github.com/anthropics/defending-code-reference-harness/blob/main/docs/blog-post.md

