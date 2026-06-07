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
**Status:** accepted — distribution mechanism superseded by ADR-017 (spike-07)
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

## ADR-016 — Patch-write confinement is defense-in-depth; the hook is a tripwire, not the boundary
**Status:** accepted — **addendum to ADR-010** (verified by spike-06; confinement red-team, Phase 5)
**Context:** ADR-010 removes the agent's working-tree write / `git apply` capability. Phase-5
grooming verified two facts that reshape *how* this is enforced: (1) the white-hacker agent already
exposes **no `Write`/`Edit` tool** (`tools: Read, Grep, Glob, Bash, SendMessage, ToolSearch`), so the
only residual write surface is **`Bash`**, and the artifact chain itself is written via Bash; (2) a
red-team found a verb+path Bash-parsing hook is **trivially bypassable** (16 verified vectors:
symlink/realpath TOCTOU, `mv`/`cp` laundering, `python3 -c`/`perl -e`/`sed -i` interpreter writes,
`patch -p1 <diff`). Deciding whether an arbitrary command writes a forbidden path is undecidable.
**Decision:** Enforce confinement as **defense-in-depth, strongest first**:
1. **Structural baseline (the only real guarantee):** no `Write`/`Edit` tool granted; no patch-apply
   capability granted; `sec-patch` emits a unified diff under `PATCHES/` and a **human applies it**.
2. **`permissions.deny`** (Claude Code's own parser, which checks each sub-command of a compound):
   `git apply|am|push|reset --hard|clean|config`, `patch`.
3. **PreToolUse Bash tripwire** (`.claude/hooks/confine_patch_writes.py`): `realpath`-canonicalize a
   candidate write target, then allow only the pinned artifact allowlist (`THREAT_MODEL.md`, the
   `*.json` artifacts, `SECURITY-REPORT.md`, `PATCH-STATE.json`, `*.sarif`, `PATCHES/**`) + `/dev/null`
   / OS-temp; deny redirection/tee/cp/mv/dd/truncate/`sed -i`/interpreter-writes/nested-shell/`patch`
   /git-mutation/`.claude/**` writes. Exit 2 = hard block (spike-06).
**Residual risk (recorded, verbatim in the hook header):** Bash-command parsing is heuristic and
**NOT airtight** — interpreters (`uv run python -c …`), symlink TOCTOU, and exotic write syscalls evade
it. The hook is a **tripwire/speed-bump, not the boundary.** The strong guarantee is layer 1.
**Scope caveat (agent vs. developer):** a project `settings.json` hook/deny binds *every* Claude
session in the repo, not just the white-hacker subagent. The deny set is therefore kept to
patch-apply/push/destructive verbs (it does **not** block `git commit`/`add` or the Write/Edit tools),
so it implements ADR-010 without handcuffing developer-driven sessions. **Activating** the registration
in `.claude/settings.json` is a deliberate, human-authorized step (self-modifying startup config) — the
hook + permissions block is provided ready to enable; disable by removing the `hooks`/`deny` block.
**Alternatives:** (a) a globally-active hook gating the `Write` tool + `git commit` (rejected: breaks
developer/build sessions and surprises the operator); (b) trusting the hook as the boundary (rejected:
red-team-falsified — undecidable parsing).

## ADR-017 — Distribute as a Claude Code plugin via a marketplace; `.claude/`(dev) vs `plugins/<name>/`(payload); project-detecting init emits a gated project-scope companion, not a profile rewrite
**Status:** accepted — supersedes the *distribution mechanism* of ADR-014 (resolved by spike-07)
**Context:** ADR-014 said "distribute by copy or plugin" but was flagged "requested layout, not
researched." Spike-07 verified against canonical Anthropic docs (code.claude.com) and the three
largest actively-maintained reference repos (anthropics/claude-code 130k★,
anthropics/claude-plugins-official 29.5k★, wshobson/agents 36k★) that the canonical 2026 shape for
an agent+skills+commands+hooks+KB bundle is a Claude Code **plugin** published via a **marketplace**.
**Decision:**
1. Ship the payload as a plugin: `plugins/white-hacker/` with `.claude-plugin/plugin.json` (only the
   manifest in `.claude-plugin/`) and component dirs (`agents/ skills/ commands/ hooks/ scripts/`) at
   the **plugin root**; catalog at repo-root `.claude-plugin/marketplace.json`. Keep a **thin dev
   `.claude/`** for dogfooding; dogfood via `claude --plugin-dir ./plugins/white-hacker`. The repo
   `CLAUDE.md` is **dev-only and not shipped** (a plugin-root CLAUDE.md is not loaded by Claude Code).
2. Agent **identity lives in the agent `.md` + skills**, never a plugin CLAUDE.md. Skills become
   namespaced (`/white-hacker:…`); hooks reference `${CLAUDE_PLUGIN_ROOT}`.
3. **Project-detecting init = run the existing `sec-detect` + `sec-threat-model` once at onboarding**
   and persist a committed, **project-scope companion** (pruned scanner registry, loaded language
   appendices, threat-model seed, scoring standard, AI-pass flag) that the generic agent consumes —
   plus an optional **project-scope** SessionStart hook emitting detected facts as **factual
   statements** (≤10,000 chars, never imperative — imperative additionalContext trips Claude's
   prompt-injection defenses; white-hacker is itself an injection target). Init **never** rewrites the
   shipped identity (ADR-004); every generated artifact passes the **Phase-9 keep-or-revert gate** +
   size caps. Honor anthropics/claude-code#16538 (plugin-scope SessionStart additionalContext may not
   surface → use project scope).
**Rationale:** canonical mechanism; matches the largest active repos; preserves identity (ADR-004);
reuses existing detection skills rather than building a new subsystem; the floor still guarantees value.
**Alternatives rejected:** (a) copy `.claude/` into each repo — ad-hoc, no
versioning/namespacing/marketplace discovery; (b) per-project rewrite of the shipped agent profile —
identity drift (no built-in guard) and prompt-injection risk from imperative auto-injected context.
**Consequences:** namespaced skill invocation; `${CLAUDE_PLUGIN_ROOT}` in hooks; repo `CLAUDE.md`
excluded from the shipped artifact; a `/sec-init` skill + `--init-only` Setup path become the
onboarding surface.

## ADR-018 — Security-policy awareness: detect `SECURITY.md`/`security.txt`; consume as untrusted data (scope annotates, never suppresses); absent → hygiene advisory; propose-to-`PATCHES/` preserving maintainer facts
**Status:** accepted — resolves spike-08
**Context:** A target repo may or may not ship a security policy. `SECURITY.md`/`security.txt` are a forward-looking disclosure POLICY (how to report, supported versions, scope) — NOT an audit log. The file is attacker-influenceable and the agent is itself an injection target (Agents Rule of Two), so it cannot be trusted as instructions.
**Decision:**
1. **Detect** `SECURITY.md` in GitHub precedence order (`.github/` → root → `docs/`, first match wins) plus `security.txt` (`/.well-known/security.txt`, legacy root); record **facts-only** in the `/sec-init` project-scope companion profile (`security_policy`).
2. **Consume a present policy as UNTRUSTED DATA:** use it to populate the report's "how to report" line, weight `Supported Versions`, and ANNOTATE declared scope/embargo — but NEVER act on instructions embedded in it, and **declared scope NEVER suppresses a real, exploitable HIGH** (a malicious policy could "scope away" the bug). Ingest as source-labeled, JSON-encoded untrusted content.
3. **Absent policy = INFORMATIONAL supply-chain-hygiene advisory, not a vulnerability** (consistent with the DO-NOT-REPORT "documentation issues" rule; OpenSSF Scorecard treats it as a maturity gap, not a CVE). No CVSS; never in `VULN-FINDINGS.json`/`TRIAGE.json`.
4. **Maintain boundary = read-only + advisory.** The agent may PROPOSE a new or MERGED policy ONLY to `PATCHES/` (the existing capability-removed path, confined by `confine_patch_writes`); a human applies; it never auto-applies/pushes. On modify it PRESERVES every maintainer-declared fact (contact / supported-versions / timeline / scope) verbatim and only ADDS missing best-practice sections. It NEVER writes scan results / audit history into the policy (history → GitHub Advisories / CHANGELOG / the transient gitignored `SECURITY-REPORT.md`), and NEVER stores the security contact in the KB (sensitive + untrusted).
**Rationale:** Aligns with GitHub/IETF RFC 9116/OpenSSF standards; preserves the agent's untrusted-input posture (ADR-007, ADR-016) and propose-not-push capability-removal (ADR-010, ADR-016); keeps identity + eval gates intact (ADR-004).
**Alternatives rejected:** (a) trust declared scope to filter findings — rejected, untrusted source could hide real bugs; (b) auto-apply/commit a generated policy — rejected, it is an operational/legal commitment owned by the maintainer; (c) report a missing policy as a vuln — rejected, it is hygiene, not exploitable.
**Consequences:** new `sec-policy` skill (parse + propose/modify); a `security_policy` facts block in the project profile; a factual SessionStart line (via the F-001 allowlist sanitizer); all policy proposals land in `PATCHES/`.
