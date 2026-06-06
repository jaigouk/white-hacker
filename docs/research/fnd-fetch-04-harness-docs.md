# fetch:harness-docs

> Source: workflow `white-hacker-research` (wycjclbk6), agent `fetch:harness-docs`

## Anthropic's Defending Code Reference Harness — Pipeline, Triage, Patching, and Porting Model (2026)

The [`anthropics/defending-code-reference-harness`](https://github.com/anthropics/defending-code-reference-harness) is an open-source reference implementation (~2,200+ GitHub stars as of mid-2026) that deploys Claude as an autonomous agent to **discover, verify, triage, and patch** software vulnerabilities through a multi-agent pipeline. The reference target is **C/C++ memory-safety bugs**, built into an **ASAN-instrumented Docker image** and attacked inside **gVisor-isolated, network-locked containers**. Per Anthropic's own at-scale scanning, as of **May 22, 2026 they had disclosed 1,596 vulnerabilities, 97 of them patched** to their knowledge — and they note the bottleneck has shifted from discovery to **verification, triage, and patching** ([blog-post.md](https://github.com/anthropics/defending-code-reference-harness/blob/main/docs/blog-post.md)). This is the design pressure a generic review agent must absorb: discovery is cheap, *deciding what's real and fixing it* is the hard part.

### Pipeline stages and CLI

The autonomous loop is `recon → find → grade → judge → report → dedup → patch`, driven entirely through `bin/vp-sandboxed` (the harness refuses to spawn agents outside its sandbox; `scripts/setup_sandbox.sh` must run once first). Stages ([pipeline.md](https://raw.githubusercontent.com/anthropics/defending-code-reference-harness/main/docs/pipeline.md)):

| Stage | What it does | Isolation / oracle |
|---|---|---|
| **Build** | Target `Dockerfile` → ASAN-instrumented image (first scan only) | Docker + ASAN |
| **Recon** (optional) | Agent partitions the attack surface for parallel runs; skippable if `focus_areas:` is hand-written in the target's `config.yaml` | read-only source review |
| **Find** | One agent per run in a network-isolated container reads source, crafts malformed inputs, runs ASAN binary until an input **crashes 3 out of 3 times** | recall-optimized |
| **Grade** | A *second* agent in a *fresh* container re-runs the PoC: reproduces, is in project code, isn't mere memory exhaustion | precision-optimized adversarial verifier |
| **Judge** | Compares crashes against known bugs in `reports/manifest.jsonl`; classifies new / improved / duplicate (runs serially) | |
| **Report** | Per new bug, writes a structured exploitability analysis from *only* the PoC + source | |
| **Dedup** | Groups crashes by ASAN signature for summary | |
| **Patch** | Generates candidate patches per unique bug | |

CLI surface:
```
bin/vp-sandboxed recon  <target> --model <m>
bin/vp-sandboxed run    <target> --model <m> [--runs N --parallel] [--stream]
        [--auto-focus] [--find-only] [--accept-dos] [--novelty]
        [--max-turns N] [--engagement-context F] [--resume <results-dir>]
bin/vp-sandboxed report results/<target>/<ts>/ [--fresh]
bin/vp-sandboxed patch  results/<target>/<ts>/
bin/vp-sandboxed dedup  results/<target>/<ts>/
```
The single most transferable architectural idea: **separate the discovery agent (optimizes recall) from an independent verifier agent in a fresh container with no shared filesystem or conversation history.** Anthropic reports this adversarial verifier "roughly halved the rate of non-exploitable findings."

### Porting to a new language / vuln class (the "interview")

`customizing.md` does **not** present a literal numbered "3 porting questions" list; instead the `/customize` skill **reads the pipeline source and interviews you about your target**, and the interview probes exactly these axes ([customizing.md](https://raw.githubusercontent.com/anthropics/defending-code-reference-harness/main/docs/customizing.md)):

1. **The language** (what you're scanning).
2. **How a finding is detected** — i.e. what plays the role ASAN plays for C/C++ (the "executable oracle" that decides a finding is real).
3. **The build system** (build + test commands).
4. **Which vuln classes you care about.**

It then proposes a migration plan touching the **five places where language/vuln-specific logic lives** (the orchestration — `harness/cli.py`, `find.py`, `grade.py`, `report.py` — is "generic plumbing" and usually survives a port unchanged):

1. **Find & grade prompts** — what the find agent hunts for and what the grader accepts as a real crash (the "Crash Quality Tiers" and "Out of Scope" sections).
2. **Report & report grader** — the report's sections and the rubric that scores them.
3. **Patch & patch grader** — how a fix is requested and what counts as fixed.
4. **Crash signatures** — how detector output becomes a dedup signature.
5. **Target Dockerfile** — how the target builds with the detector active, plus build/test commands.

For a **generic, cross-language white-hat agent (TS/Go/Python/Java; backend/frontend/AI)**, the load-bearing insight is that the C/C++ harness's portability hinges on having a **deterministic detector** (ASAN). Most of those stacks lack one universal oracle, so the agent must define a *per-class* verification oracle: for SQLi/SSRF/path-traversal a reproducing request + observed effect; for authz bugs a privilege-boundary assertion; for prompt-injection/AI bugs a behavioral check that the injected instruction executed. The "interview" axes generalize cleanly into a **target profile** the agent should establish up front (language, detection oracle per vuln class, build/test commands, in-scope classes).

### Triage: dedup + severity

**Dedup is two-pass** ([triage.md](https://raw.githubusercontent.com/anthropics/defending-code-reference-harness/main/docs/triage.md)). The governing definition: *"Two findings are duplicates if fixing one fixes the other."*
- **Deterministic pass (cheap):** duplicate if findings are in the **same file**, have the **same category**, and reference **line numbers within ten lines** of each other.
- **Qualitative pass (LLM):** semantic reasoning to catch duplicates the deterministic pass misses (e.g. same root cause across files).

**Severity rubric** is **precondition-counting**, not impact-first. The verifier *"lists preconditions first, then maps the count to a score"*:

| Severity | Rule |
|---|---|
| **High** | **No** preconditions + unauthenticated remote access |
| **Medium** | **One or two** preconditions, OR an authenticated path |
| **Low** | **Three or more** preconditions, OR local-only |

Crucially, the rubric is **swappable** — "swap in your own scoring standard when the skill asks at the start of a run" (CVSS, an org bug-bar, etc.). For a generic agent, enumerating *preconditions before scoring* is a strong anti-inflation discipline that ports across all languages and is far more robust than asking the model to guess a CVSS vector cold.

### Patch validation ladder

Patches are validated through **four mandatory executable-oracle tiers in sequence, plus one advisory tier** ([patching.md](https://raw.githubusercontent.com/anthropics/defending-code-reference-harness/main/docs/patching.md)):

| Tier | Question | Method | Result field |
|---|---|---|---|
| **Build** | Does the patched tree compile? | `git apply` + `build_command` exit code | `t0_builds` |
| **Reproduce** | Is the original crash gone? | Exit 0 **AND** no `AddressSanitizer:` in output | `t1_poc_stops` |
| **Regress** | Did it break existing behavior? | `test_command` exit code (skipped if no suite) | `t2_tests_pass` |
| **Re-attack** | Root cause gone, or just this input? | A **fresh 50-turn find agent** attacks the patched binary; ASAN decides | `re_attack_clean` |
| **Style (advisory)** | Would a maintainer accept it? | LLM judgment, 0–10 — "advisory only, **never gates**" | |

**Pass criterion:** *"A patch passes when build, reproduce, regress (or no suite), and re-attack are all clean."* The **re-attack tier is the differentiator** — it distinguishes a real root-cause fix from one that merely papers over a single PoC input, and it generalizes to any stack: after patching, re-run the discovery agent against the fixed code and require it to find nothing. Style review being explicitly non-gating is a deliberate choice to keep machine-checkable oracles authoritative and keep subjective judgment out of the accept/reject decision.

### What a generic agent should borrow

The harness's transferable spine is: **threat-model → discovery (recall) → independent verification (precision) → triage (dedup + precondition severity) → patch with a re-attack gate**, every gate backed by an *executable oracle* and every adversarial step run in a *fresh, isolated context*. The hard part for a multi-language agent is supplying the per-class oracle that ASAN provides for free in the C/C++ reference.

## Key takeaways

- Architecture spine to copy: threat-model → discovery (recall-optimized) → independent verification (precision-optimized) → triage (dedup + severity) → patch-with-re-attack. Anthropic reports a separate adversarial verifier 'roughly halved' non-exploitable findings — run the verifier in a FRESH context with no shared filesystem/history.
- The reference harness is C/C++-specific because it leans on ASAN as a deterministic crash oracle. A generic TS/Go/Python/Java/AI agent has no single oracle, so it must define a per-vuln-class verification check (reproducing request+observed effect for SQLi/SSRF, privilege-boundary assertion for authz, behavioral execution check for prompt-injection).
- Porting 'interview' axes (use as the up-front target profile): (1) language, (2) how a finding is detected = the executable oracle, (3) build/test commands, (4) which vuln classes are in scope. There is no literal numbered '3 questions' list — it's these interview axes plus 5 customization points.
- Five customization points that hold language-specific logic: find/grade prompts, report+report-grader rubric, patch+patch-grader, crash/finding signatures for dedup, and the target Dockerfile/build. Orchestration code is generic and survives a port unchanged — keep your agent's orchestration decoupled from language specifics.
- Dedup is two-pass with one governing rule: 'two findings are duplicates if fixing one fixes the other.' Cheap deterministic pass = same file + same category + line numbers within 10 lines; then an LLM semantic pass for cross-file/same-root-cause dupes. This generalizes directly to any language.
- Severity is precondition-COUNTING, not impact-guessing: list preconditions first, then map — 0 preconditions + unauth remote = High; 1–2 or authenticated = Medium; 3+ or local-only = Low. Enumerating preconditions before scoring is a strong anti-severity-inflation discipline and is language-agnostic.
- Make the severity rubric swappable (CVSS / org bug-bar) and ask which to use at the start of a run — don't hard-code one scoring standard into a generic agent.
- Patch validation ladder = four mandatory executable-oracle tiers in order: Build (t0_builds) → Reproduce/PoC-stops (t1_poc_stops) → Regress/tests-pass (t2_tests_pass, skip if no suite) → Re-attack (re_attack_clean). Pass only when all are clean.
- The Re-attack tier is the key idea to port: after patching, unleash a fresh discovery agent on the fixed code and require it to find nothing — this distinguishes a true root-cause fix from one that only blocks a single PoC input (the variant/incomplete-fix problem).
- Style/maintainer-acceptability review is scored 0–10 by an LLM but is explicitly ADVISORY and never gates acceptance — keep subjective LLM judgment out of accept/reject decisions; let machine-checkable oracles be authoritative.
- Discovery requires reproducibility (PoC must crash 3/3 times) before a finding is graded — bake a 'must reproduce N times' gate into the agent to suppress flaky/low-signal reports.
- Sandboxing model for any autonomous review agent: gVisor/Docker isolation, snapshot after setup, then remove network during scanning with egress locked to the model API only (api.anthropic.com) — the setup→attack isolation split prevents agent-tool exfiltration and contains exploit execution.

## Sources

- https://github.com/anthropics/defending-code-reference-harness
- https://raw.githubusercontent.com/anthropics/defending-code-reference-harness/main/docs/customizing.md
- https://raw.githubusercontent.com/anthropics/defending-code-reference-harness/main/docs/triage.md
- https://raw.githubusercontent.com/anthropics/defending-code-reference-harness/main/docs/patching.md
- https://raw.githubusercontent.com/anthropics/defending-code-reference-harness/main/docs/pipeline.md
- https://github.com/anthropics/defending-code-reference-harness/blob/main/docs/blog-post.md
- https://www.anthropic.com/glasswing
- https://www.anthropic.com/engineering/claude-code-sandboxing

