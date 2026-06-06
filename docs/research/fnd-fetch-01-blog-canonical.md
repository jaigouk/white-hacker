# fetch:blog-canonical

> Source: workflow `white-hacker-research` (wycjclbk6), agent `fetch:blog-canonical`

## Anthropic's "Using LLMs to Secure Source Code" — The Find-and-Fix Loop

Anthropic published *Using LLMs to Secure Source Code* on **May 27, 2026** (canonical text mirrored at [`anthropics/defending-code-reference-harness/docs/blog-post.md`](https://github.com/anthropics/defending-code-reference-harness/blob/main/docs/blog-post.md)). It distills lessons from partnering with security teams at multiple organizations and from Anthropic's own open-source scanning. The thesis: **discovery has become cheap and parallelizable, so the bottleneck has shifted to verification, triage, and patching.** A profile designer should treat the document as a specification for a *defender's loop* that optimizes the whole pipeline, not just bug-finding.

### The six-step find-and-fix loop

The post structures everything around a repeating loop:

| Step | Purpose |
|---|---|
| 1. Threat model | Decide what counts as a vulnerability *before* scanning |
| 2. Sandbox | Isolate agents and prove exploits safely |
| 3. Discovery | Find vulnerabilities in source (optimize recall) |
| 4. Verification | Independently confirm exploitability (optimize precision) |
| 5. Triage | Deduplicate, assign severity, prioritize |
| 6. Patching | Apply fix, confirm nullification, hunt for variants |

The reference harness ships four interactive **skills** mapping to these steps — `threat-model`, `vuln-scan`, `triage`, `patch` — plus `/quickstart` and `/customize`, and the recommended model is **Claude Opus**.

### Threat-model fidelity is the top accuracy lever

The single strongest finding: **"the model performed best on systems with well-documented threat models, system design docs, requirements, and constraints. When the threat model was well-defined, the model's findings were exploitable 90 percent of the time."** Conversely, a cautionary tale describes reproducible, exploitable bugs being *dismissed* because "the bugs didn't fit the project's threat model" — illustrating the gap between model context and organizational context.

Practical guidance:
- **Bootstrap** the threat model from architecture docs, wikis, entry points, git history, and past CVE/security-fix commits; ask the model to cluster bug patterns and enumerate relevant vulnerability classes.
- **Interview** system owners with **Shostack's four questions**: *What are we building? What can go wrong? What are we doing about it? Did we do a good job?*
- Commit a **`THREAT_MODEL.md`** to the repo and reference dependencies' published security policies (vLLM, SQLite, ImageMagick are cited).

For a generic agent: threat-model fidelity is the universal precision multiplier. The agent should *demand or synthesize* a threat model first and feed it back into triage to calibrate severity.

### Discovery vs. verification: separate recall from precision

A core architectural principle: **"Discovery optimizes for recall; verification optimizes for precision,"** and the two must be *separate steps with separate agents*. Combining them causes self-censorship: **"When an agent tries to do both in the same step, it can self censor and exclude exploitable true positives."**

- **Discovery** uses simple, non-prescriptive prompts to find everything, including unlikely cases — prescriptive checklists narrow the model's creativity.
- **Verification** runs an **independent agent in a fresh container with no shared history**, prompted *adversarially* to **disprove** the discovery agent's findings — "assume each finding is a false positive and search for reasons the finding is wrong," including mitigations discovery missed.
- **Multi-vote verification**: run multiple independent verifiers and take a majority vote (the harness exposes `--votes 5`).

### PoC-driven false-positive reduction

The verification stage is anchored on **executable proof**: **"Validation is the biggest holdup and the PoC is the validation."** Where a sandbox can run the target, discovery produces a PoC (a script, crashing input, or failing test), and the verifier **rebuilds and detonates it** in a clean container. True positives require a working PoC.

The quantified payoff is the headline methodology stat: **"adding an adversarial verifier roughly halved the rate of non-exploitable findings... Requiring that verifier to also build a proof of concept confirming the exploit brought the false positive rate to near zero."** A generic agent should treat "produced a reproducing PoC" as the gate for promoting a finding from candidate to confirmed.

### Parallelization via partitioning, not brute force

Naive horizontal scaling fails: **"We initially tried to just horizontally scale and send more agents, but saw limiting returns,"** and another team that just added focus areas and agents got "tons of issues," mostly duplicates. The fix is **partition-then-fan-out**:

1. A lightweight first pass partitions the search space **by attack surface, endpoint, or component** so parallel agents don't converge on the same shallow bugs.
2. Parallel discovery agents each work one partition in isolated containers.
3. A final **system-level pass** uses partition findings as context to surface **cross-component** vulnerabilities.

The autonomous harness implements this as a 7-stage Docker/gVisor pipeline — Build (with ASAN), **Recon** (proposes "N distinct input-parsing subsystems worth attacking separately"), Find (N parallel agents crafting malformed inputs until a crash reproduces **3/3 times**), Verify, Dedupe, Report, Patch — invoked via `bin/vp-sandboxed run <target> --runs 3 --parallel --auto-focus`. Each agent runs in a gVisor container with **egress restricted to the Claude API only**, and the pipeline refuses to run outside the sandbox unless explicitly overridden.

### Triage: deduplication and an evidence-first severity rubric

**Deduplication — treat as the same finding:** same root cause worded differently; the same bug at multiple call sites; a missing global protection reported per-endpoint; cause and consequence flagged in the same path.

**Treat as distinct:** different vulnerability classes in one file; different variables reaching different sinks; two independent bugs in one helper; the same missing check on two endpoints that need separate fixes.

**Severity factors:** reachability, attacker control, preconditions, authentication, read vs. write, blast radius. The post gives a concrete starting rubric:

> Zero preconditions with unauthenticated remote access = **critical/high**; one or two preconditions, or an authenticated path = **medium**; three or more preconditions, or local-only = **low**.

Crucially, **the threat model is supplied during triage** to ground severity and curb overconfidence.

### The patching ladder

Patching is a validation ladder, written TDD-style (failing test first):

1. **Build** — patch compiles and new tests pass.
2. **Try to reproduce** — the original PoC must now fail.
3. **Check for regressions** — the original test suite still passes.
4. **Re-attack** — a *fresh* discovery agent runs an adversarial check on the patched code.

Best practices: fix the **root cause, not just the call site**; search for variants at two levels — **same pattern** (other call sites/copies) and **same class** (a codebase with one SQL injection tends to have more); and prefer **minimal patches**, avoiding refactors or drive-by cleanups. A noted failure mode: model patches "tend to be as restrictive as possible, to the point that they would break connections with other services."

### Headline statistics

- **"As of May 22, 2026, we had disclosed 1,596 vulnerabilities. To our knowledge, 97 of these have been patched."** (~6% patched at publication — underscoring that disclosure/remediation, not discovery, is now the bottleneck.)
- Adversarial verification **roughly halved** non-exploitable findings; adding PoC execution drove false positives **near zero**.

### Related products

The methodology underpins **Claude Security** (Anthropic's managed agentic vulnerability-detection product, which moved from closed preview to public beta in 2026) and the free **`claude-code-security-review`** GitHub action / Claude Code security plugin that runs a fast deterministic pattern match (flagging `eval()`, `new Function()`, `os.system()`, `child_process.exec()`, pickle deserialization, DOM injection) on file edits before any model call.

## Key takeaways

- Architect the agent as a six-step find-and-fix loop (threat-model, sandbox, discovery, verification, triage, patch) rather than a one-shot scanner — discovery is cheap, so invest profile complexity in verification/triage/patching where the real bottleneck lives.
- Make threat-model fidelity the first-class precision lever: have the agent synthesize or ingest a THREAT_MODEL.md from docs, git history, and past CVEs, and re-inject it during triage. Well-documented threat models yielded 90% exploitable findings — this generalizes across TS/Go/Python/Java and backend/frontend/AI.
- Strictly separate discovery (optimize recall, simple non-prescriptive prompts, find everything) from verification (optimize precision, adversarial, fresh container, no shared history) — combining them causes self-censorship that drops true positives.
- Use an adversarial verifier that tries to DISPROVE each finding, plus multi-vote (e.g. 5 votes); this alone roughly halved non-exploitable findings in Anthropic's data.
- Gate findings on an executable proof-of-concept: require the verifier to rebuild and detonate a PoC in a clean sandbox. PoC execution drove false-positive rates near zero — the universal true/false-positive discriminator regardless of language or stack.
- Parallelize by partitioning the attack surface FIRST (by endpoint/component/subsystem), then fan out, then run a system-level cross-component pass. Naive horizontal scaling produced mostly duplicates — bake partition-then-fan-out into any multi-agent profile.
- Encode explicit dedup rules (same root cause, same bug at many call sites, missing global protection reported per-endpoint, cause+consequence in one path = duplicate; different classes/variables/sinks/endpoints needing separate fixes = distinct) so triage is reproducible across project types.
- Adopt an evidence-first severity rubric keyed on reachability, attacker control, precondition count, auth state, read-vs-write, and blast radius: 0 preconditions + unauth remote = critical/high; 1-2 or authenticated = medium; 3+ or local-only = low.
- Use a patching ladder: build+new tests pass, original PoC stops reproducing, full regression suite passes, then a fresh agent re-attacks the patch. Fix root cause not the call site, keep patches minimal (avoid refactors), and watch for over-restrictive patches that break integrations.
- After patching, hunt variants at two levels — same pattern (sibling call sites) and same class (one SQLi implies more) — making variant search a standard post-fix step in the profile.
- Run untrusted target execution in a strong sandbox (gVisor) with egress locked to the model API only; keep read/write-only static skills unsandboxed but refuse to detonate code outside the sandbox. Make sandbox-gating language-agnostic via a configurable 'signal of finding' (ASAN crash, exception, canary file, DNS callback) and PoC format (crashing input, HTTP sequence).
- Anchor expectations on real 2026 numbers: 1,596 vulnerabilities disclosed as of May 22, 2026 with only 97 patched (~6%) — remediation/disclosure, not detection, is the scaling wall a defender agent should help close.

## Sources

- https://github.com/anthropics/defending-code-reference-harness/blob/main/docs/blog-post.md
- https://github.com/anthropics/defending-code-reference-harness
- https://www.anthropic.com/product/security
- https://www.anthropic.com/coordinated-vulnerability-disclosure
- https://thenewstack.io/anthropics-claude-security-beta/
- https://thehackernews.com/2026/02/anthropic-launches-claude-code-security.html
- https://cybersecuritynews.com/free-security-plugin-for-claude-code/

