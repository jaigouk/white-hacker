# ARD — Architecture Decision Records

Append-only log of significant decisions for the white-hacker agent. Each entry:
context → decision → rationale → alternatives → status. Newest decisions may supersede
older ones (note it explicitly). Companion to `ARCHITECTURE.md` (the *what/how*); this is
the *why*.

Status legend: `accepted` · `proposed` · `superseded by ADR-NNN`.

---

## ADR-001 — Core concept: nested inner review loop + outer self-improvement loop
**Status:** accepted
**Context:** The agent must (a) review code well and (b) stay current as AI-attack
techniques evolve. Two references inform it: the defending-code harness and the
Self-Improving Agent Architecture.
**Decision:** Model the system as **two nested loops over plain-text artifacts behind open
interfaces (Agent Skills, MCP)**. Inner loop (per review): threat-model → discovery (recall)
→ verification (precision) → triage → patch. Outer loop (across reviews/idle): trace →
reflect → propose text diffs → gate (eval keep-or-revert) → PR. The inner loop *consumes*
the knowledge base; the outer loop *edits* it. Retraining is out of scope.
**Rationale:** Most reliability is engineered outside the weights (Context/Harness surfaces);
text edits are cheap, testable, reversible. The KB-refresh is the input arm that ingests
"new ways to hack AI products."
**Alternatives:** Single-pass reviewer (rejected: no currency, no FP discipline); fine-tuned
model (rejected: expensive, slow, catastrophic-forgetting risk).

## ADR-002 — Trivy CLI-first, MCP optional
**Status:** accepted — see `docs/research/spike-01-trivy-mcp.md`, `poc-trivy-sca/`
**Decision:** Use the Trivy **CLI** via Bash as the SCA/IaC/secrets core; treat the official
`aquasecurity/trivy-mcp` server as an optional enhancement the agent uses only if present.
**Rationale:** CLI gives full flag control, identical local/CI behavior, and offline scans
(`--skip-db-update`, verified: 13 HIGH/CRITICAL found offline). The MCP server is a manual
plugin install, not a managed connector (registry returned 0 results). Never hard-depend on
`mcp__trivy__*`.
**Alternatives:** MCP-only (rejected: the legacy profile's mistake — fragile, unavailable by
default).

## ADR-003 — Graceful tool degradation; never block on a missing tool
**Status:** accepted — see `poc-tool-detection/` (12/12 tests)
**Decision:** Detect installed scanners; when a category has none, fall back to a
Read/Grep/Glob heuristic pass and mark findings `tool_assisted:false` with capped confidence;
record `tools_unavailable` in the report.
**Rationale:** Verified locally only `trivy` + `govulncheck` are installed; a portable agent
cannot assume a toolbelt. Value floor = built-in Read/Grep/Glob.

## ADR-004 — Self-improvement on Context+Harness surfaces, human-in-loop first
**Status:** accepted — see `docs/research/spike-02-cc-native-automation.md`
**Decision:** Implement the outer loop with native Claude Code primitives: skills+`reference/`
(KB), hooks (capture + PreToolUse guardrails), `schedule`/routines (refresh), `consolidate-
memory` (reflection). Ship **human-in-the-loop** first (`/sec-learn`, `/sec-kb-refresh`
propose PRs), graduate toward autonomy gated by the eval corpus. Never auto-merge.
**Rationale:** All primitives verified present; memory/skills are *context, not enforced
config*, so hard guardrails must live in PreToolUse hooks (Harness).
**Alternatives:** External DSPy/GEPA runtime (rejected for v1: not needed; principle adopted
as lightweight reflection instead).

## ADR-005 — Skill size-cap guardrails
**Status:** accepted — see `docs/research/spike-03-skill-caps.md`
**Decision:** Enforce `description`+`when_to_use` ≤ **1,536** chars (Claude Code listing cap);
for portability also `description` ≤ 1,024 and `name` ≤ 64; `SKILL.md` < 500 lines;
`reference/` one level deep. The KB ratchet's size gate uses these numbers; a `lint_skill`
script (with tests) enforces them.
**Rationale:** Protects prefix-caching / context budget; prevents KB bloat/drift.

## ADR-006 — Tool supply-chain pinning
**Status:** accepted — see `docs/research/spike-01` addendum
**Decision:** Pin security tools to known-good versions; install via brew or digest/GPG-
verified artifacts; never auto-install from unpinned sources. Pin GitHub Actions to commit
SHA and Docker base images to digest.
**Rationale:** Trivy binary 0.69.4 / images 0.69.5–0.69.6 were malicious; the official Trivy
Action was compromised twice in 2026. The agent that scans for supply-chain risk must not be
a supply-chain victim.

## ADR-007 — Static-analysis-only by default; execution-verified PoC is opt-in
**Status:** accepted
**Decision:** Default scanning does no build/run/install/network. Execution-verified PoC
detonation is an opt-in, gVisor/Docker-sandboxed escalation (egress locked to the model API),
reserved for high-value HIGHs.
**Rationale:** Safe for side projects; PoC detonation is the strongest FP-killer but costly.
"No PoC" is weak evidence, not proof of safety.

## ADR-008 — Separate discovery (recall) from verification/triage (precision)
**Status:** accepted
**Decision:** Discovery and verification are distinct stages with **separate agents** and a
**fresh context** for verification; verification is adversarial (assume FP), N-of-N voting
(default 3); the decision-maker sees only `{file,line,category,diff}`.
**Rationale:** Combining them causes self-censorship that drops true positives; adversarial
verifiers roughly halve non-exploitable findings; context starvation defeats prompt injection.

## ADR-009 — One agent definition + composable skills chained via on-disk JSON
**Status:** accepted
**Decision:** Define the identity once (`.claude/agents/white-hacker.md`); implement each
stage as a skill; chain via files (`THREAT_MODEL.md → SCAN-PLAN.json → VULN-FINDINGS.json →
TRIAGE.json → PATCHES/`). Reusable as `/security-review`, subagent, and team teammate.
**Rationale:** Artifact-backed chaining is resumable, CI-gateable, and decouples stages.

## ADR-010 — Patch by capability-removal, not instruction
**Status:** accepted
**Decision:** white-hacker has no working-tree write / `git apply` capability; `sec-patch`
writes only to `./PATCHES/`. It proposes; humans apply.
**Rationale:** Structural safety beats instructions a prompt-injection could override.

## ADR-011 — Opengrep as the single cross-language SAST default
**Status:** accepted — see `docs/research/fnd-tool-matrix.md`
**Decision:** Default SAST = Opengrep (Semgrep-compatible rules, OSS taint/interprocedural,
LGPL-2.1); layer native linters (gosec/ruff-S+bandit/eslint-security/spotbugs+find-sec-bugs);
Semgrep CE optional when its first-party MCP is wanted.
**Rationale:** Free interprocedural taint that Semgrep moved to paid; one binary, 12+ langs.

## ADR-012 — Living KB separate from stable checklists; dated, sourced entries
**Status:** accepted — see `docs/research/si-04` (kb-design), `si-05` (eval)
**Decision:** Fast-moving AI-attack knowledge lives in `ai-attack-kb/reference/` as dated,
source-linked, status-tagged (active/archived/deprecated) entries; stable language/web
checklists live in `_shared/reference/`. Each KB entry maps technique → detection pattern →
checklist item.
**Rationale:** Separates what changes weekly from what's stable; provenance + dating keep it
auditable and prevent stale guidance polluting current reviews.

## ADR-013 — Process: plan-first, verification-criteria-per-task, spikes/PoCs, living docs
**Status:** accepted
**Decision:** No build before an approved plan (`docs/plan/`); every task carries checkable
verification criteria; uncertain assumptions get a `docs/research/spike-*.md` (optionally a
runnable `poc-*/` with tests) before being relied on; `README`/`PRD`/`DDD`/`ARCHITECTURE`/
`ARD`/`plan/*` are maintained, not write-once; ARD is append-only.
**Rationale:** User-mandated discipline; matches global TDD/DDD rules.

## ADR-014 — Scaffolding under `.claude/`; distribute by copy or plugin
**Status:** accepted
**Decision:** The active agent/skills live under this repo's `.claude/` so they work here;
for reuse in other projects, copy to `~/.claude/` (user scope) or package as a plugin.
Identity comes from the `name` field, not the path.
**Rationale:** Requested layout; user-scope/plugin gives cross-project reuse without forking.

## ADR-015 — Tools are a swappable capability layer behind interfaces (not a fixed list); the registry self-updates
**Status:** accepted — **governs ADR-002 and ADR-011, which are mere examples within it**
**Context:** The concept (defending-code loop + self-improvement), not any specific scanner, is
the product. The user noted "Trivy is just one tool" and "there can be other tools that I do not
know." The agent-tooling market churns fast.
**Decision:** Depend on **capabilities** (SAST · SCA · secrets · IaC · AI-redteam · …), never on
a brand — the ports-and-adapters principle from the Self-Improving Agent reference (§3). Keep an
**extensible tool registry** (`_shared/reference/tool-registry.md`) mapping capability → known
tools, where every named tool (Opengrep, Trivy, OSV-Scanner, gitleaks, …) is an **illustrative
default, not a requirement**. The agent **discovers** installed tools at runtime, maps them to
capabilities, and degrades to the Read/Grep/Glob floor when none exist (ADR-003). Crucially, the
registry is part of the **self-improving loop**: `sec-kb-refresh` and `sec-learn` can add tools
the agent didn't know — tooling knowledge evolves like attack-technique knowledge.
**Rationale:** Keeps the system durable as tools appear/merge/relicense; foregrounds the concept;
prevents the legacy profile's single-tool coupling. The floor guarantees value with zero tools.
**Alternatives:** A curated fixed tool matrix (rejected: ages fast, couples the agent to brands,
contradicts the "there are tools I don't know" reality).
