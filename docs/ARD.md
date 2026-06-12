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

### Risk register (2026 container-escape evidence) — added 2026-06-08
*Additive note; the ADR-007 decision above is unchanged.* A container shares the **host
kernel**, so a single kernel CVE can become a **container → host escape** — every tenant on a
shared kernel is exposed by one bug. 2026 evidence sharpens the ceiling for any future
PoC-detonation host: (a) the shared-kernel LPE wave turns "a kernel CVE" into a host-escape
primitive; (b) microVM (Firecracker/Kata) hardware isolation can still be **bypassed via
operation-forwarding**; (c) frontier LLMs show **measurable container-sandbox-escape
capability** (arXiv 2603.02277). Conclusion: **microVM is the ceiling — the strongest practical
boundary — for any future PoC-detonation host** (gVisor/Docker reduce but do not eliminate
host-syscall surface), and **shared-kernel CI runners are the weakest link**. This reinforces
ADR-007's sandboxed-only execution; it does not change what white-hacker reviews (no new
app-repo detector). Ref: spike-10 (`docs/research/spike-10-linux-kernel-security-2026-06.md`,
F4 / Decision §INWARD).

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
**Status:** accepted — the `docs/plan/` plan-doc clause is SUPERSEDED by ADR-030 (planning moved to beads epics/tickets, 2026-06-12); the verification-criteria-per-task + spikes/PoCs + living-docs discipline stands.
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

## ADR-019 — Expand the closed `technique_class` vocabulary 5→6: add AI-native `supply-chain` (slopsquatting / AI-SDK typosquat), ecosystem-agnostic
**Status:** accepted — resolves spike-09 (`docs/research/spike-09-npm-ai-supply-chain-2026-06.md`)
**Context:** ADR-012 fixed the ai-attack-kb `technique_class` as a closed enum of on-disk file stems. Spike-09 surfaced an AI-native supply-chain technique not covered by the original five: **slopsquatting** (an LLM invents a plausible-but-nonexistent package name; an attacker pre-registers it; a developer pastes the AI's install command — ~1-in-5 AI suggestions name a nonexistent package, 43% repeat) plus **AI-SDK typosquatting** (lookalike names of popular AI/LLM SDKs). The name-trust failure is ecosystem-agnostic (npm/PyPI/RubyGems/Go/crates/Maven); npm is just the hottest current example.
**Decision:** Add `supply-chain` as the sixth member of the `technique_class` enum (the closed vocabulary stays closed — it grows by an appended ADR, never silently). The single source of truth is `kb-entry-schema.json`'s enum, which `validate_kb.load_schema()` reads; `SKILL.md`'s vocabulary table mirrors it. The new `reference/supply-chain-1.md` entry (`AISEC-SUPPLY-CHAIN-001`, primary xref `LLM03:2025`) documents the **technique** with cross-ecosystem, technique-level detections; the generic, per-ecosystem detection **mechanics** (registry-record check, distance-to-AI-SDK-allowlist, install-script inspection) live in the deps-scan supply-chain floor (wh-07w), not in the KB. Refreshable by `/sec-kb-refresh` like the other classes.
**Rationale:** Slopsquatting is a genuinely AI-native attack worth tracking in the living KB (ADR-012's Context surface) — it belongs beside prompt-injection/tool-poisoning, not buried as a generic CVE concern. Keeping the technique in the KB while keeping the deterministic detection greps in deps-scan preserves the KB-as-knowledge / detector-as-code split (Rule 5; ADR-015).
**Supersedes:** nothing (ADR-012's structure is preserved; this only widens the enum by one). 
**Alternatives rejected:** (a) treat slopsquatting purely as a deps-scan signal with no KB entry — rejected, it loses the AI-native technique provenance/dating the living KB exists to carry; (b) put per-ecosystem greps in the KB entry — rejected, detection code belongs in the detector (wh-07w), the KB documents the technique.
**References:** spike-09 (F1 slopsquatting row, F5 cross-ecosystem map, Sources/CSA); ADR-012 (KB structure), ADR-015 (capability layer / self-updating registry).

## ADR-020 — Floor-scored supply-chain corpus cases use a per-variant PROJECT-SUBDIR layout (`vulnerable_variant/` and `benign_lookalike/` are directories)
**Status:** accepted — lands the layout introduced by the wh-qyf sc-npm anchor cases (first case at commit `9a4fdf7`: `evals/corpus/cases/sc-npm-install-script-exec/`).
**Context:** The corpus convention to date is FLAT: each case carries `vulnerable_variant.<ext>` and `benign_lookalike.<ext>` as single sibling files (multi-file agent cases add flat `_support_*` siblings, e.g. mf-* cases' `_support_*.py`). Floor-scored supply-chain cases (ADR-019 added the `supply-chain` technique_class; the deps-scan floor implements detection) break that shape: `supply_chain.scan(project_dir, ...)` (`plugins/white-hacker/skills/deps-scan/scripts/supply_chain.py:937`) scans a **directory** — the npm adapter reads `<dir>/package.json` + the lockfile + the referenced install scripts. Two `package.json` (one vulnerable, one benign) cannot coexist flat in one case dir. A directory-per-variant is therefore required to express both variants of a supply-chain case.
**Decision:** For floor-scored supply-chain cases, `vulnerable_variant/` and `benign_lookalike/` are **DIRECTORIES**, each holding a complete per-ecosystem project tree (for npm: `package.json` + lockfile + any `scripts/`), not single files. The locked anchor is `evals/corpus/cases/sc-npm-install-script-exec/{vulnerable_variant/{package.json,package-lock.json,scripts/postinstall.js},benign_lookalike/{package.json,package-lock.json},label.json,target.md}`. The case `label.json` points `vulnerable.file` at the **nested subpath** inside the variant dir (e.g. `vulnerable_variant/scripts/postinstall.js`) and `benign_lookalike.file` at a path inside `benign_lookalike/`; the label sets `multifile:true` and lists the remaining variant files under `support_files`. This subdir layout is the convention ONLY for directory-scanning floors; the FLAT single-file convention is unchanged and remains the default for every agent-scored case.
**Rationale:** (a) The floor scans a directory, so a variant must BE a directory — this is a structural consequence of `supply_chain.scan`, not a stylistic choice. (b) **No `score.py` change is needed:** `_file_match` (`evals/score.py:25-33`) does SUFFIX path matching, so a label whose `vulnerable.file` is a nested subpath (`vulnerable_variant/scripts/postinstall.js`) still matches the floor's project-level finding — the existing scorer absorbs the deeper tree for free. (c) **Leak-neutral:** the floor scores on file CONTENT (manifest + lockfile + install-script signals), not on directory names — benign content placed in a directory literally named `vulnerable_variant/` still yields 0 findings (empirically confirmed during the wh-qyf landing-prep workflow), so the directory names do not leak the answer any more than the flat `vulnerable_variant.<ext>` stem does. (d) The build path is opt-in and bounded: `promote_finding.py promote()` (`evals/scripts/promote_finding.py:59-88`) selects MULTIFILE mode on the presence of a `files:{relpath:content}` map (wh-705), writing the arbitrary subdir tree plus an explicit `vulnerable_file`/`vulnerable_line`/`benign_file`; FLAT mode is unchanged; every relpath is validated by `_check_relpath` (`:29-34`), which rejects absolute paths and any `..` segment BEFORE any mkdir/write so a hostile spec can never escape the case dir. Floor cases stay deterministically scored — the agent is never run on them.
**Supersedes:** nothing (the FLAT single-file convention is preserved as the default; this adds a directory layout for directory-scanning floors only).
**Alternatives rejected:** (a) keep the FLAT layout and concatenate both projects into one file — rejected, `supply_chain.scan` scans a directory and the npm adapter needs a real `<dir>/package.json` tree; two manifests cannot coexist flat. (b) Store one shared project and toggle the install hook via a label flag — rejected, it loses the side-by-side `vulnerable`/`benign` pairing every other case carries and complicates the deterministic floor invocation. (c) Change `score.py` to special-case supply-chain paths — rejected and unnecessary: the existing suffix `_file_match` already matches nested subpaths, so no scorer edit is warranted (Rule 3, surgical).
**References:** wh-705 (`promote_finding.py` MULTIFILE mode — docstring `:7-14`, impl `:59-88`, path guard `:29-34`); wh-qyf (the 3 landed `sc-npm-*` anchor cases — `sc-npm-install-script-exec`, `sc-npm-nonregistry-source`, `sc-npm-typosquat-hook`; baseline 118→121, Youden J=1.0, drift-guard `n_cases==len(cases)` holds at 121); `evals/score.py:25-33` (`_file_match` suffix matching — no change needed); `plugins/white-hacker/skills/deps-scan/scripts/supply_chain.py:937` (`scan(project_dir,...)` scans a directory); `evals/corpus/cases/sc-npm-install-script-exec/label.json` (nested `vulnerable.file`, `multifile:true`, `support_files`); ADR-012 (closed-vocab append-only precedent); ADR-019 (the `supply-chain` technique_class this layout serves).

## ADR-021 — A pinned, verified `install.sh` (run from the target) adds a vendor lane beside the marketplace plugin
**Status:** accepted — implements wh-3jt.
**Context:** ADR-017 made the Claude Code **plugin marketplace** the primary distribution. Two needs it doesn't cover: (a) a one-command, `curl|bash`, run-INSIDE-a-target install; (b) a **self-contained / committed / CI-runnable** install that doesn't require each user to `claude plugin install` (e.g. an early-stage repo that wants the reviewer vendored in). ADR-017's *manual hand-copy* fallback is unpinned + drifts — that is the model it rightly retired.
**Decision:** Ship `install.sh` (repo root) — a `curl|bash`-safe installer with two lanes, **defaulting to the latest RELEASE tag**: (1) **vendor** (default) — git-clone the pinned tag to a `mktemp` dir (trap-cleaned), copy the payload (`agents/white-hacker.md` + `skills/` + `commands/`) into the target's `.claude/`, idempotent (backup, never silent clobber), `.venv` excluded + gitignored; (2) **`--plugin`** — `claude plugin marketplace add` (pinned clone) + install (ADR-017, auto-updates). It **dogfoods ADR-006**: pins a tag, prefers a GPG-signed tag (`git verify-tag`), fetches nothing unpinned, and wraps its whole body in `main()` (run on the last line) so a truncated `curl|bash` executes nothing.
**Rationale:** (a) An **installer-managed vendor is NOT the deprecated manual copy** — it is pinned, verified, idempotent, and refreshable (re-run at a new tag), so the drift that retired the hand-copy is bounded + visible. (b) **The Python toolchain is trivial:** every skill package is **stdlib-only** (`requires-python>=3.10`, zero runtime deps) and runs via `uv run --project` in an **isolated venv** — vendoring installs ZERO Python packages into the target and never touches its environment; the only prereq is `uv` (which also provisions Python; test deps are injected ephemerally via `uv run --with`). (c) Plugin stays recommended for shared/auto-updating use (`--plugin`); vendor wins when the target must be self-contained / CI-runnable.
**Supersedes:** extends ADR-017 (the plugin model is unchanged) and supersedes only ADR-017's *unpinned manual-copy fallback*.
**Alternatives rejected:** (a) plugin-only — no self-contained/CI lane, and marketplace ref-pinning is weaker than git-tag pinning. (b) Vendor the skills' venvs / pip-install deps into the target — unnecessary (stdlib-only; uv isolates per skill). (c) Unpinned `curl|bash` of `main`@HEAD — violates ADR-006 (a security tool must pin + verify its own install).
**References:** wh-3jt; `install.sh`; ADR-017 (plugin distribution), ADR-006 (pin-and-verify), ADR-015 (stdlib floor); `docs/research/spike-07-agent-distribution-and-init-2026-06.md`; the skills' stdlib-only `pyproject.toml` (zero deps) + `uv.lock`.

## ADR-022 — Vendor-lane payload boundary: ship the inner/consumer loop; the outer/producer loop is dev-repo only (fail-closed manifest + deterministic scrub)
**Status:** accepted — implements wh-7gh; amends ADR-021 (which introduced the vendor lane).
**Context:** ADR-021 shipped the vendor lane but copied the WHOLE payload via a fail-OPEN glob (`for s in "$src"/skills/*/`), dragging white-hacker's DEV-repo + OUTER-loop machinery into every target. A 20-agent audit (2026-06-09) confirmed the architecture's two nested loops cross the vendor boundary differently: the INNER loop (the review — threat-model→detect→discovery→triage→report→opt-in-patch, plus secrets/deps/ai-llm scanning, consuming `ai-attack-kb` **read-only**) is what a target USES; the OUTER loop (`sec-learn` reflects on FP/misses and proposes KB/checklist diffs; `sec-kb-refresh` polls threat feeds) runs ONLY in the dev repo — both are gated by the eval keep-or-revert harness (`evals/`) + the KB git history + the confinement hooks, NONE of which exists in a target. A vendored target also lacks `docs/research/*`, `docs/ARD.md`, `docs/ARCHITECTURE.md`, `.beads/`, `bd`, and `${CLAUDE_PLUGIN_ROOT}` (set only for an installed plugin).
**Decision:** The vendor lane ships ONLY consumer/inner-loop units, via two mechanisms. (1) A **fail-CLOSED manifest** — `WH_VENDOR_SKILLS` in `install.sh`, mirrored by `CONSUMER_SKILLS` in `install/scrub_vendored.py` — of 13 skills (`_shared ai-attack-kb ai-llm-review deps-scan sec-detect sec-init sec-patch sec-policy sec-report sec-threat-model sec-triage sec-vuln-scan secrets-scan`); a NEW skill is excluded by default until added. EXCLUDED: `sec-learn`, `sec-kb-refresh` (outer-loop producers; both `disable-model-invocation:true`; the audit's exclude-verdicts returned `refuted:false` — no inner skill imports them, the dependency direction is reversed). (2) A **deterministic vendor-time scrubber** (`install/scrub_vendored.py`, stdlib, TDD) that, ON THE VENDORED COPY ONLY (the source tree is left whole), marker-strips the agent's `## Self-improvement (the outer loop)` section + each skill's `## Verification criteria` definition-of-done block + the `ai-attack-kb` Lifecycle / `MALWARE-DB` pin / `sec-init` Gating / `sec-report` Logged-evidence sections, applies an explicit replacement table for inline dev-pointers (`${CLAUDE_PLUGIN_ROOT}`, `/sec-learn`, `/sec-kb-refresh`, `docs/research/*` links, beads ids), and drops `ai-attack-kb/scripts/precommit_safety.py` — then asserts `find_leaks()` finds ZERO forbidden tokens.
**Scope of the guard:** it scans the AGENT-FACING surface (`.md` — the agent reads `SKILL.md` + `reference/*.md`, never the skills' Python). `.py`/`.json` provenance comments (`# spike-09 §F2`, `"_source":…`) are tolerated code-archaeology — rewriting working comments is brittle and non-surgical (Policy 5, 3). The one runtime hazard, a test driving an absent dev fixture, is handled by skip-guards in the tests themselves (wh-7gh `sec-report`, wh-8lx `deps-scan`), so a vendored `uv run pytest` SKIPS rather than errors. Bare citation provenance (`(ADR-015)`, `(spike-09 §F2)`) is left inert.
**Rationale:** (a) The vendor boundary — not the source files — is where the consumer/producer split belongs: source-editing would gut convention-mandated `## Verification criteria` DoD blocks (Policy 11) and spike-07/08 links that resolve in the dev repo. (b) Fail-closed > blacklist: a blacklist is fail-open (a new producer ships until someone remembers to exclude it). (c) Identity preservation (ADR-004): the agent ships whole MINUS its outer-loop section; the inner-loop reviewer identity + team-workflow awareness are untouched. (d) A tested deterministic transform is NOT the brittle generic prose-regex the audit warned against (Policy 5: code answers; Policy 9: TDD — a real-tree leakage test is the drift guard).
**Supersedes:** amends ADR-021's payload definition — vendor no longer copies `commands/` (plugin-lane-only, `${CLAUDE_PLUGIN_ROOT}`-coupled) nor the outer-loop skills, and scrubs dev/outer-loop content from what it does ship. The `--plugin` lane is unchanged and still delivers the full payload.
**Alternatives rejected:** (a) ship-everything-then-scrub with a generic regex — brittle over untrusted-shaped prose. (b) Edit the source files — guts convention + dev-resolving content (the audit's first instinct; rejected after verifying spike-07/08 exist and VC blocks are convention). (c) Blacklist the 2 producers — fail-open. (d) Maintain a separate consumer-agent file — two identities to keep in sync.
**References:** wh-7gh; `install.sh` (`WH_VENDOR_SKILLS`, the post-copy scrub call, corrected hooks warn); `install/scrub_vendored.py` + `install/tests/test_scrub_vendored.py` (the real-tree leakage guard, 11 tests); the 2026-06-09 vendor-payload audit (20 agents); ADR-021 (vendor lane), ADR-017 (plugin distribution / inner-outer nesting), ADR-004 (identity preservation), ADR-015 (capability layer); `plugins/white-hacker/skills/sec-report/scripts/tests/test_ci_gate.py` (skip-guard).

## ADR-023 — Resource-aware execution: an own stdlib host-probe + concurrency cap (no OOM-freeze); no new dependency
**Status:** accepted — resolves spike wh-bob (`docs/research/20260609_resource_aware_execution.md`); backs PRD §5.7 (FR-22..27) + NFR-11; the implementation is wh-00i.
**Context:** `plugins/white-hacker/agents/white-hacker.md` § "Execution budget" already ships *behavioral* guidance to measure the host and cap concurrency before fanning out (so ~10 concurrent subagents/heavy scanners don't OOM-freeze the host). PRD §5.7/§7 (M8) elevate it to requirements. What was unresolved is the **mechanism**: keep parsing tool text by hand (Policy 5 says a deterministic question should be answered by code), adopt a dependency, or build a small helper. The spike surveyed prior art under a hard **MIT/Apache-2.0-only** licence rule and built a throwaway PoC (`docs/research/poc-resource-probe/`, stdlib-only, 10 tests green).
**Decision:**
1. **Own stdlib helper, no dependency (RQ1).** Build `_shared/scripts/resource_probe.py` (wh-00i) — stdlib-only, zero third-party imports. **Reject `psutil`** (BSD-3 → permissive but outside the MIT/Apache rule, and a dep breaks ADR-021's "vendoring installs ZERO Python packages") and **GNU `parallel`** (GPL-3 → unbundleable; a job-queue, not LLM-subagent orchestration; studied as prior art only). The PoC proves stdlib suffices: cores+load need no shell, only free-mem needs one per-OS read.
2. **Probe commands (RQ2).** cores: Linux `os.sched_getaffinity(0)` (cgroup/affinity-aware → container-correct), else `os.cpu_count()`. load: `os.getloadavg()[0]` (macOS+Linux). free-mem: Linux `/proc/meminfo` **`MemAvailable`** (counts reclaimable cache — NOT `MemFree`); macOS `vm_stat` available proxy `(free+inactive+speculative+purgeable)×page`.
3. **Cap formula + constants (RQ3).** `suggested_max_parallel = clamp≥1( min(cores − HEADROOM, free_mb ÷ SUBAGENT_MB, HARD_CEILING) )`, and **drop to 1 (SEQUENTIAL) when `load1 ≥ cores`**. Env-overridable defaults: `HEADROOM=2`, `HARD_CEILING=8` (conservative for *heavy LLM subagents* — below the `min(16, cores−2)` batch norm), `SUBAGENT_MB=1536` (est. RAM per heavy subagent — the dominant fan-out cost, hence the memory divisor). Validated on-host: `min(12−2, 10434÷1536, 8) = 6`.
4. **Pressure signal (RQ4).** **MemAvailable/vm_stat (memory) + `load1` (saturation backstop)** as the single cross-platform pair. **PSI (`cgroup v2 memory.pressure`) is DEFERRED** (Linux-only → breaks cross-platform symmetry, extra code path; MemAvailable+load is sufficient for the OOM-avoidance goal — Policy 2). `load1` lags, so memory is the primary divisor and load only forces sequential.
5. **Modes (RQ5).** Lock the four already in the agent md — ESSENTIALS/pre-commit · CRITICAL-ONLY · FULL · DEFERRED; the probe **bounds** whichever the user intent selects, default to the lighter mode when unsure, ask on costly/risky scope.
6. **Output contract (RQ6) — REPORT-ONLY (not bound by this ADR).** Do NOT add `mode`/`checks_skipped[]` to `finding-schema.json` now: it is `additionalProperties:false` and the keystone the eval gate (`validate_findings.py`, `evals/score.py`) + the (already-stale) baseline validate against — a breaking bump for human-read metadata. Resource posture goes in `SECURITY-REPORT.md` + the existing `tools_unavailable`-style honesty. A schema bump is a SEPARATE ticket only if the eval gate ever needs to consume `mode`.
**Rationale:** Only the own stdlib helper satisfies all of: MIT/Apache-only bundling, ADR-021 zero-dep vendor, ADR-015 stdlib floor, ADR-003 graceful degradation (unknown OS / unreadable probe → `free_mb=None` → memory divisor skipped, never blocks), ADR-006 (nothing auto-installed), and Policy 5 (code answers the deterministic measurement; the agent keeps the *judgment* — which mode, when to ask). OS-level *enforcement* (cgroups/ulimit/nice) stays out of scope (PRD §8): the cap is planned-and-honored, not kernel-enforced.
**Supersedes:** nothing — extends ADR-003 (graceful degradation) from *tools* to *compute*; the behavioral agent-md section (wh-n4f) stays and gains a deterministic probe behind it.
**Alternatives rejected:** (a) psutil — licence rule + zero-dep vendor invariant; (b) GNU parallel / a shell job-queue — GPL-3 + wrong abstraction + "never block on a missing tool"; (c) PSI now — Linux-only, premature (Policy 2); (d) schema-visible `mode`/`checks_skipped` now — breaking change to the keystone contract for human-read metadata (deferred to its own ticket); (e) status-quo prose only — non-deterministic, Policy 5.
**References:** wh-bob (spike), wh-00i (implementation), wh-n4f (the shipped behavioral section); `docs/research/20260609_resource_aware_execution.md` (survey + decisions) + `docs/research/poc-resource-probe/` (stdlib PoC, 10 tests); PRD §5.7 (FR-22..27), NFR-11, §8; ADR-003 (degradation), ADR-015 (stdlib floor), ADR-021 (zero-dep vendor), ADR-006 (pin-verify); `plugins/white-hacker/agents/white-hacker.md` § "Execution budget".

## ADR-024 — CONTAIN (assume-breach / zero-trust tool execution) is the PRIMARY supply-chain control; the 5-stage lifecycle is defense-in-depth under it
**Status:** accepted — ratifies spike wh-hxt.3 (`docs/research/20260610_contain_primary_control.md`); the strategy ADR for epic wh-hxt; wh-hxt.2 references it (no competing lifecycle ADR); blocks wh-562. Grounds `docs/research/20260609_supply_chain_tooling_strategy.md` (CONTAIN section).
**Context:** The supply-chain lifecycle (ADMIT→PIN/VERIFY→DIVERSIFY→MONITOR→RETIRE) is entirely *selection + verification* — every stage asks "is this tool trustworthy?" But **you cannot verify a tool/dependency is uncompromised**, and 2026 proved verification-by-reputation is defeatable: Mini Shai-Hulud (May 2026; TanStack/Mistral/OpenSearch) victims carried **valid SLSA Build L3 provenance + OIDC trusted-publishing + 2FA** and were still compromised — the worm hijacked the *legitimate* pipeline (stole the ambient OIDC token from `/proc/<pid>/mem`, signed via real Sigstore). StepSecurity: *"provenance confirms WHICH pipeline produced the artifact, not WHETHER the pipeline was behaving as intended."* The only control that stopped it **in flight** was an **egress allowlist**; tool *diversity* is the cited fix in **zero** 2026 postmortems. So swapping a compromised tool for a "trusted" one is not what keeps us safe. white-hacker already holds the SEED — the Agents Rule of Two (`plugins/white-hacker/agents/white-hacker.md:39-41`) + the deps-scan-sandbox LOCKDOWN (`docker/deps-scan-sandbox/run.sh:22-31`: `--network none`, `--read-only`+tmpfs, `--cap-drop ALL`, `no-new-privileges`, `--user 10001`, pid/mem caps, `--rm`) + the fetch/analyze split (`fetch-snapshot.sh:2-6`). This ADR elevates containment from a posture line + one-skill sandbox to the PRIMARY control wrapping the whole lifecycle.
**Decision:**
1. **CONTAIN is PRIMARY; the 5 stages are defense-in-depth UNDER it.** None of ADMIT/PIN-VERIFY/DIVERSIFY/MONITOR/RETIRE survives an *undetected* compromise; CONTAIN does (it does not depend on knowing what is bad). DIVERSIFY is demoted from "the security answer" to **blast-radius reduction** (it also raises the count of supply-chain surfaces).
2. **The CONTAIN invariant = the registry rule.** At **every** tool execution, **≥2 of three** are ABSENT: `{ network/egress · credentials in the tool's env · host write access }`. Pure-offline tools (gitleaks, Checkov-offline, Syft) drop into the lane directly; DB-backed tools (Grype, OSV-Scanner, the OSSF S8 snapshot) use the **fetch/analyze split** (network-on FETCH of the DB, then network-off ANALYZE against it `:ro` — the `fetch-snapshot.sh` pattern); native gates (pip-audit/npm audit/govulncheck) degrade to the floor unless a local advisory DB is pre-seeded — never run with egress to satisfy the invariant.
3. **Lane shape (RQ2): per-skill runners sharing a FROZEN `LOCKDOWN[]` convention NOW; extract a shared `_shared` tool-exec lane at the SECOND real caller.** Today only deps-scan runs inside containment, so a generalized wrapper is abstraction-for-single-use (Policy 2; ADR-015's "add a port when ≥2 tools implement it"). The reusable asset is the **policy** (the flag set + the fetch/analyze split + the Rule-of-Two boundary), captured as a single documented array + a drift-lock test (mirroring `test_registry_lock.py`), not the plumbing. The migration trigger to the shared lane is the first second-capability runner (e.g. Grype).
4. **The S8 auto-route bridge (RQ3): default-when-safe, ARMED by explicit config.** Add `deps_scan.contain.auto_route` (default **false**) + `deps_scan.contain.snapshot_path`. When BOTH `auto_route:true` AND a valid snapshot exist, a **deterministic probe** (docker reachable + snapshot valid, bounded timeout, no LLM — Policy 5) routes the deps-scan stage through `run.sh scan`; any red **falls back to S1–S7** and records `malware-db` in `summary.tools_unavailable` with a reason (ADR-003). This makes containment the steady state for a user who armed it once, without a surprise `docker run` on a fresh checkout (honours ADR-007 + `SKILL.md:81-82`'s explicit-activation contract). The S8 degrade today lives at the `unavailable.add("malware-db")` site in `supply_chain._build_doc` (the `scan()` result builder). **Live build-verify is DEFERRED** (the lane's last verify was 67 passed, predating wave-1a's 102-test layout; docker may be down on a dev host) — `./run.sh build && ./run.sh test` (expect ~102) on a daemon host gates reliance on the lane.
5. **The artifact-provenance admission arm (RQ4).** CONTAIN's *admission* control for the TOOL artifacts the agent executes: pin to an immutable ref (commit-SHA / image-digest / binary-checksum — never a mutable tag; trivy-action 76/77 + tj-actions were force-pushed) + **VERIFY checksum/cosign/SLSA at admission** (not generate-and-trust). Load-bearing nuance: `--skip-db-update` (offline) stops a poisoned DB but NOT a poisoned local binary, so binary-checksum-verify-at-install is the load-bearing control. This is a **DIFFERENT mechanism from two others — three gates, three object kinds, never merged:** eval **Gate-1** (KB review-quality edits, `evals/` keep-or-revert) · **Gate-2** (watchlist/registry DATA entries, per-entry GHSA/OSV provenance + OSV-schema, **owned by wh-562**) · **CONTAIN admission** (TOOL artifacts, this ADR). Reusing Gate-1 to admit a tool, or folding admission into Gate-2's DATA gate, is a category error.
6. **Two delegations (one owner each, as required by the spike).** (a) The ADR-015 *"registry self-updates"* sentence is **design intent until wh-hxt.4 lands** — **carried HERE** (it concerns the tooling registry, this strategy ADR's territory). (b) ADR-021's *"a tag-pin must resolve to a commit SHA"* (the force-push lesson) is **DELEGATED to wh-562's Gate-2 ADR** (same write-lane integrity surface) — this ADR cross-references it so exactly one ADR states it.
7. **CI hardening (RQ5) is a CONTAIN surface; the checklist lives in a `docs/` runbook, not in this ADR.** The runbook (SHA-pin Actions to full commit-SHAs · per-job `GITHUB_TOKEN: contents:read` · OIDC scope-pinned to an immutable workflow + protected branch · **egress allowlist** — the control that stopped Mini Shai-Hulud · `--ignore-scripts` · ephemeral runners · atomic secret rotation; GitHub SHA-pin policy 2025-08-15; EU CRA reporting 2026-09-11) is operational guidance that evolves, so it stays out of append-only ADR prose; this ADR records only the policy + a pointer. `ci/security-review.action.yml` + `.github/workflows/ci.yml` are wired by the impl ticket, not this spike.
8. **Self-edit asymmetry — CONTAIN enforcement code is OUT-OF-LANE for the outer loop.** `confine_self_writes` FROZEN/CONTROL basenames + default-deny put hooks/sandbox/gate beyond self-rewrite. CONTAIN improvements arrive as **human-PR'd, TDD'd, keep-or-revert-gated code diffs**, never KB text — the loop *proposes* sandbox/hook changes through the normal code gate; it cannot self-rewrite the boundary. This is identity preservation (Policy 5), not a defect.
**Rationale:** Security comes from **containment, not selection**: because every tool runs offline + no-creds + sandboxed + provenance-verified, a compromise of *any* tool — Trivy, its replacement, or one not yet picked — is **inert** even in the window before the advisory drops (Mini Shai-Hulud's egress-allowlist proof). The lane decision honours Policy 2 / ADR-015 (no port until ≥2 callers); the bridge honours ADR-003 (degrade to floor) + ADR-007 (no surprise execution); admission honours ADR-006 (pin + verify) and sharpens it from "verify at install" to "the three gates are three object kinds." The out-of-lane asymmetry follows ADR-016's structural-baseline-first confinement.
**Supersedes:** nothing — extends ADR-006 (pin) and ADR-003 (degrade) into a primary execution-containment layer, and elevates the Agents Rule of Two (`white-hacker.md:39-41`) from posture to the load-bearing control. Carries ADR-015's self-updates clarification (intent until wh-hxt.4); delegates ADR-021's tag→SHA supersession to wh-562's Gate-2 ADR (cross-referenced).
**Alternatives rejected:** (a) keep DIVERSIFY/PIN-VERIFY as the primary answer — falsified by Mini Shai-Hulud (valid provenance still passed); diversity cited as the fix in zero 2026 postmortems. (b) A shared `_shared` tool-exec lane NOW — abstraction-for-single-use (only deps-scan runs in containment today); Policy 2 / ADR-015 add the port at ≥2 callers. (c) S8 auto-route default-on unconditionally — a surprise `docker run` on hosts where the daemon is often down (a VM-based docker daemon is often not running); contradicts ADR-007. (d) Fold tool-admission into Gate-1 or Gate-2 — category error (three object kinds). (e) Put the CI checklist in the ADR — append-only ADR prose is the wrong home for evolving operational guidance (Policy 11). (f) Let the outer loop self-edit the sandbox/hooks as KB text — breaks identity preservation (Policy 5; ADR-016).
**References:** wh-hxt.3 (this spike), `docs/research/20260610_contain_primary_control.md` (matrix + RQ decisions + draft impl tickets); `docs/research/20260609_supply_chain_tooling_strategy.md` (CONTAIN section + 2026 primary sources: StepSecurity Mini Shai-Hulud postmortem, SLSA L3 hermetic, NIST SP 800-218/204D, CISA-NSA Defending CI/CD, OpenSSF S2C2F, GitHub SHA-pin policy 2025-08-15, EU CRA) + `docs/research/20260609_supply_chain_loop_leverage.md` (G4, LBC-4/LBC-5, §9) + `docs/research/20260609_trivy_teampcp_supply_chain.md` (offline ≠ binary-verify scorecard); `docker/deps-scan-sandbox/{run.sh,fetch-snapshot.sh,README.md}`; `plugins/white-hacker/skills/deps-scan/SKILL.md:81-82` + `scripts/supply_chain.py` (the `unavailable.add("malware-db")` degrade in `_build_doc`); `plugins/white-hacker/agents/white-hacker.md:39-41`; ADR-001 (two loops), ADR-003 (degrade), ADR-006 (pin+verify), ADR-007 (opt-in sandboxed detonation + microVM-ceiling risk register), ADR-015 (capability-not-brand registry; self-updates), ADR-016 (confinement defense-in-depth), ADR-019 (supply-chain class); siblings wh-562 (Gate-2 DATA gate — blocked by this; owns the ADR-021 tag→SHA supersession), wh-nvk (DIVERSIFY), wh-xn0 (ADMIT), wh-hxt.2 (runbook — references this), wh-hxt.4 (ADMIT-via-loop).

## ADR-025 — Tool admissibility = two deterministic gates (license MIT/Apache-2.0-only + data-egress local/no-default-telemetry); supersedes ADR-011's Opengrep SAST default
**Status:** accepted — resolves spike wh-xn0 (`docs/research/20260609_tool_admissibility_license_gdpr.md`); the ADMIT-policy ADR for epic wh-hxt; every license re-verified from the upstream LICENSE/SPDX 2026-06-10. The registry rewrite is wh-nvk (shared ticket); the deterministic screen is wh-hxt.4.
**Context:** `tool-registry.md` had no license/egress columns and seeded **License-gate violators as defaults** — Opengrep (`:24`), govulncheck (`:29`), trufflehog (`:34`), hadolint (`:38`) — and ADR-011 named **Opengrep (LGPL-2.1)** the cross-language SAST default. ADR-023 already adopted **MIT/Apache-2.0-only bundling** and rejected psutil (BSD-3) for the one bundled helper; nothing generalised that bar to *every capability tool*, so the self-update loop (ADR-015) could keep admitting copyleft/proprietary tools. Distinct from ADR-024's **admission** arm (pin + verify *the artifact*) and from wh-562's **Gate-2** (per-entry provenance for DATA): this is **admissibility** — *is this tool allowed in the registry at all?* — decided *before* a tool is pinned. Four names, four objects, never merged: eval **Gate-1** (KB edits) · **Gate-2** (DATA entries, wh-562) · **CONTAIN admission** (TOOL artifacts, ADR-024) · **admissibility** (license + egress *policy*, this ADR).
**Decision:**
1. **Two deterministic gates, both required (Policy 5 — code answers, no LLM).** **License-gate (license):** `license ∈ {MIT, Apache-2.0}` ONLY — reject BSD (incl. BSD-3), LGPL (any), GPL, AGPL, MPL, any copyleft, proprietary/commercial; a dual offering one of them *at the user's option* passes (elect the permissive arm — e.g. cargo-audit `MIT OR Apache-2.0`). **Egress-gate (data-egress):** the tool's DEFAULT invocation runs **local/offline**, uploads no source, sends no telemetry; a telemetry-on-by-default tool is admissible ONLY with the disable flag pinned. The screen is a pure function (`admit_tool(record) -> (admitted, reason)`); a NEW tool failing either gate is rejected with a stated reason. **SPEC in the spike §8; IMPLEMENTED in wh-hxt.4** (the ADMIT-via-loop row writer — no registry-row writer exists today).
2. **The re-audited admissible set (every SPDX upstream-verified 2026-06-10).** SAST: gosec (Apache-2.0), bandit (Apache-2.0), ruff (MIT), eslint-plugin-security (Apache-2.0). SCA: OSV-Scanner/Grype/Syft/pip-audit (Apache-2.0), cargo-audit (MIT/Apache). secrets: gitleaks (MIT), detect-secrets (Apache-2.0). IaC/CI: Checkov (Apache-2.0), actionlint/zizmor (MIT). AI-redteam: promptfoo (MIT — **admit only with `PROMPTFOO_DISABLE_TELEMETRY=1`**; telemetry on by default, never sends prompts/outputs/configs), garak (Apache-2.0). **Dropped (License-gate):** Opengrep & Semgrep CE (LGPL-2.1), CodeQL (proprietary + private-repo/CI-forbidden), govulncheck (BSD-3; DB data CC-BY-4.0), trufflehog (AGPL-3.0; `--results=verified` = egress), hadolint (GPL-3.0), find-sec-bugs (LGPL-3.0). **Trivy stays OUT regardless of its Apache-2.0 license** (TeamPCP — wh-nvk; license-clean ≠ admissible).
3. **Every capability has ≥1 admissible tool; the floor (ADR-003) is the named backstop, NOT triggered.** Exception to flag: **no admissible Java SAST** remains (find-sec-bugs/SpotBugs are LGPL) → Java taint drops to the floor; cross-language taint drops to the floor + per-language linters.
4. **Supersede ADR-011 explicitly.** The cross-language SAST default is replaced by **floor + per-language MIT/Apache linters**. This is a **precision DOWNGRADE** (linters are mostly intra-procedural; Opengrep gave interprocedural taint). Per Policy 9 the cost is **MEASURED against `evals/score.py`** (Opengrep-on baseline vs linters+floor; neutralized filenames; re-baseline the stale 32→103 corpus first) and gates the KEEP of the SAST change in the impl ticket — **NOT asserted, and NOT run in this spike wave**.
5. **Registry schema (RQ4): add `license` / `data_egress` / `gdpr` columns** to every `tool-registry.md` entry (admissibility evidence inline; violators move to a "Rejected (License-gate)" subsection with SPDX + reason). `detect_tools.py:110` `SCANNER_PREFERENCE` stays in sync — `test_registry_lock.py` enforces doc↔code **at the CAPABILITY level** (GREEN, 4 passed); **per-tool drops are the impl ticket's TDD** (pin violators ABSENT and admitted PRESENT — Policy 9), not the lock. The registry rewrite (columns here + replacement rows from wh-nvk + the lock-regex fix) is **ONE coordinated change** — never two uncoordinated writers.
6. **Pinning is ADR-024's, not re-derived here.** Admissibility (this ADR) decides *whether a tool may enter the registry*; ADR-024's artifact-provenance **admission** arm then pins to an immutable ref + verifies checksum/cosign/SLSA at each execution. They **compose** — a tool passes admissibility once (to be listed) and admission every run (to be executed). The `gdpr` column records ONLY the *tool's* data-flow; the agent's own model-call PII posture is **wh-81y** (Spike B), out of scope here.
**Rationale:** A license + data-egress gate is **registry governance, not a coupling** — the capability interface (ADR-015) is unchanged; only *which* tools sit behind it is constrained. The bar is ADR-023's MIT/Apache-2.0-only rule **generalised** from one bundled helper to every capability tool, keeping the reviewer free of copyleft obligations and SaaS source-upload. The SAST supersession is the honest cost of the license rule (no permissive cross-language taint engine exists in 2026) and is measured not asserted (Policy 9). The deterministic screen keeps tool admission in code (Policy 5); the floor (ADR-003) guarantees no capability is left empty. Naming discipline (four gates, four objects) prevents the category error ADR-024 §5 warned against.
**Supersedes:** **ADR-011** (Opengrep LGPL-2.1 as the cross-language SAST default — replaced by floor + per-language MIT/Apache linters, the cost measured before KEEP). **Generalises** ADR-023 (MIT/Apache-2.0-only bundling; psutil BSD-3 rejection) from the bundled helper to every capability tool — does not supersede it. **Composes with** ADR-024 (admissibility precedes that ADR's artifact admission; pinning lives there, not re-derived here) and is **distinct from** wh-562's Gate-2 DATA gate.
**Alternatives rejected:** (a) keep Opengrep/Semgrep for cross-language taint — LGPL-2.1, fails the License-gate (ADR-023 bar); (b) admit BSD-3 / "permissive-enough" tools (govulncheck) — ADR-023 already rejected BSD-3 (psutil); the bar is MIT/Apache-2.0, not "permissive"; (c) keep Trivy because it is Apache-2.0 — license-clean but TeamPCP-compromised (wh-nvk); admissibility composes with admission/integrity; (d) assert the SAST downgrade is acceptable without measuring — Policy 9 forbids it (eval plan gates KEEP); (e) fold this into ADR-024's admission or wh-562's Gate-2 — category error (admissibility = *may the tool be listed?*, a different object from *is this artifact verified?* and *is this DATA entry sourced?*); (f) an LLM-judged admissibility check — Policy 5 (a deterministic allowlist + egress-default check is a pure function); (g) admit promptfoo as-is — telemetry on by default, so admit only with `PROMPTFOO_DISABLE_TELEMETRY=1` pinned.
**References:** wh-xn0 (this spike), `docs/research/20260609_tool_admissibility_license_gdpr.md` (the admissibility matrix — every SPDX cited to the upstream LICENSE/GitHub License API + promptfoo telemetry doc, verified 2026-06-10; the eval-measurement plan; the deterministic-screen contract; the shared registry-rewrite draft spec); `plugins/white-hacker/skills/_shared/reference/tool-registry.md` (violators at `:24`/`:29`/`:34`/`:38`); `plugins/white-hacker/skills/sec-detect/scripts/detect_tools.py:110` (SCANNER_PREFERENCE); ADR-003 (floor/degrade), ADR-006 (pin+verify), ADR-011 (**superseded**), ADR-015 (capability-not-brand registry; self-updates), ADR-023 (MIT/Apache-2.0-only precedent — **generalised**), ADR-024 (CONTAIN; the artifact-provenance **admission** arm + the gates-are-distinct-objects rule); siblings wh-nvk (Trivy replacement + the SHARED registry rewrite), wh-hxt.4 (the ADMIT-via-loop writer where the §8 screen lands), wh-562 (its Gate-2 is the DATA-edit gate — distinct from this ADR's data-egress gate), wh-81y (Spike B — the agent's own-model-call PII/GDPR posture, NOT covered here).

## ADR-026 — Gate-2: a deterministic DATA gate for watchlist/registry edits, distinct from the eval keep-or-revert gate; the watchlist write-lane; tag-pins resolve to commit SHAs
**Status:** accepted — resolves spike wh-562 (`docs/research/20260609_trivy_teampcp_supply_chain.md`); the
ONE watchlist-mechanism ADR for epic wh-hxt (wh-5es's monitoring design folds in — one watchlist, one ADR);
unblocked by ADR-024 (wh-hxt.3 CLOSED). Consumed by wh-k6l (the watchlist file), wh-5es (the OSSF feeder),
wh-hxt.4 (the registry sidecar + row writer), wh-nvk (the Trivy-replacement rows).
**Context:** ADR-001/004/022 framed the outer loop's self-edits as *"gated by the eval keep-or-revert
harness."* That framing was scoped to **KB / review-quality edits** — a KB entry contributes detections the
labeled corpus can score, so `evals/score.py` (`:64-95`, findings-vs-`label.json`) + `keep_or_revert.py` can
emit KEEP/REVERT on merit, and `gate_kb_edit.py` (`:40-49`) enforces it on `/ai-attack-kb/` + `/_shared/
reference/` writes. A **watchlist or tool-registry DATA edit is a different object**: no corpus case measures
"did adding compromised-package X help," so the eval gate **structurally cannot** score it (loop-leverage
§4.1/LBC-2). Reusing an eval-J KEEP to admit a DATA row would be a **false-merit merge** — an unrelated KB
change's KEEP smuggling a poisoned/wrong-version entry through. Separately, the outer loop cannot even write the
watchlist today: its planned home was outside `confine_self_writes.ALLOW_SEGMENTS` (`:40`). This ADR is an
**append-only clarification** of ADR-001/004/022 (which are never edited): the eval gate governs KB edits;
DATA edits need a second deterministic gate.
**Decision:**
1. **Gate-1 vs Gate-2 split — which gate governs which edit kind.** **Gate-1** (eval keep-or-revert,
   `evals/keep_or_revert.py` → `gate_kb_edit.py`, verdict `evals/gate-verdict.json==KEEP`) governs **KB /
   review-quality edits** (`/ai-attack-kb/` + prose under `/_shared/reference/`). **Gate-2** (this ADR) governs
   **watchlist/registry DATA entries** via a deterministic validator (`_shared/scripts/validate_watchlist.py`,
   no LLM/RNG — Policy 5) checking, per entry: **(a)** a REQUIRED primary-source advisory URL (GHSA/OSV/CVE in
   `references[]`); **(b)** schema validity against the pinned `watchlist-1.0` schema; **(c)** regression-green
   (`malware_db.load_malware_db` + the version-aware `is_known_bad` predicate, plus the deps-scan suite). This
   is the SECOND of the four-objects-never-merged set (ADR-024 §5; ADR-025): Gate-1 (KB) · **Gate-2 (DATA,
   here)** · CONTAIN admission (TOOL artifacts, ADR-024) · admissibility (license+egress policy, ADR-025).
   (The advisory-URL check is **id-bound** — at least one `references[].url` must contain the entry's own
   `id` — so a host-valid but unrelated/forged advisory link fails; SEC-Q4.) This is ADR-024 §5's
   *"per-entry GHSA/OSV provenance + OSV-schema"* made concrete: **`watchlist-1.0` IS the plain-OSV-superset
   that fulfills the "OSV-schema" requirement — not a different schema** (§2).
2. **The schema is `watchlist-1.0`, by reference (never restated here).** The plain-OSV-superset finalized in
   `docs/research/20260609_supply_chain_compromise_monitoring.md` (RQ2 DECISION) — pinned as a Draft-2020-12
   JSON Schema at `plugins/white-hacker/skills/_shared/reference/watchlist-entry-schema.json`, the ONE artifact
   the validator and the OSSF feeder share.
3. **The write-lane.** The watchlist file is **`plugins/white-hacker/skills/_shared/reference/known-compromised.
   osv.json`** — inside the existing `confine_self_writes.ALLOW_SEGMENTS` `/_shared/reference/` lane (`:40`), so
   **the outer loop may write THIS ONE watchlist file, and only under a DATA-verdict KEEP** — with no change to
   the confinement boundary (itself out-of-lane for self-edit, ADR-024 §8). This is **not** a segment-wide
   grant: the `/_shared/reference/` segment's writability does **not** extend to other DATA objects (e.g. the
   wh-hxt.4 registry sidecar) without each being named in `gate_data_edit.DATA_SEGMENTS` and carrying its own
   DATA-verdict KEEP (SEC-Q7). Gate-2 mints a SEPARATE DATA verdict **`evals/data-verdict.json`** (never the
   eval-J `gate-verdict.json`) that is **content-bound (records the sha256 of the validated bytes) and
   one-shot** — `gate_data_edit.py` recomputes the write-target's hash and blocks on mismatch or replay, so a
   KEEP for one candidate cannot admit a different (poisoned) one (SEC-Q2). `gate_data_edit` is scoped to the
   named DATA file paths (initially the watchlist; wh-hxt.4 adds its sidecar path with a test); `gate_kb_edit`
   excludes those paths so a DATA write is not double-gated by the KB verdict. Every entry is a human-gated
   draft-PR, never auto-merged (ADR-012). **Verdict-writer trust (SEC-Q12):** because `validate_watchlist.py`
   mints the DATA verdict and `watchlist-entry-schema.json` defines "valid," both are **gate-grade,
   human-PR'd-only, out-of-lane** — added to `confine_self_writes.FROZEN_BASENAMES` (the same protection
   `evals/keep_or_revert.py` has), so the outer loop cannot weaken the gate that admits its own DATA edits.
   **Hard ordering:** `gate_data_edit` must be registered + the `gate_kb_edit` DATA_PATHS skip merged BEFORE
   the watchlist file is created, else it would block on the absent eval-J verdict or be admitted by an
   unrelated KB KEEP — the false-merit merge (SEC-Q3 / QA-#1).
4. **Tag-pins resolve to commit SHAs (the force-push lesson) — DELEGATED here by ADR-024 §6(b).** The TeamPCP
   compromise force-pushed the `trivy-action` `76`/`77` tags and `setup-trivy` tags (RQ1 above; the same vector
   hit `tj-actions`), so a **version-tag pin is mutable and was defeated**; only an **immutable commit-SHA /
   image-digest / binary-checksum** pin holds. This sharpens ADR-006 for every pinned ref. The DATA side already
   honors it: the OSSF watchlist **snapshot** is pinned to a full 40-hex commit SHA and PIN-verified in code
   (`docker/deps-scan-sandbox/fetch-snapshot.sh:16` enforce → `:37` `git rev-parse HEAD == PIN || exit 1`),
   which is where force-push resistance lives — **not** in a per-entry digest (watchlist entries record an
   identity, not an artifact to verify; that is CONTAIN admission's job, ADR-024 §5).
**Rationale:** The eval gate is the wrong gate for DATA (it has no corpus signal to score), so a deterministic
provenance+schema+regression gate is the honest control — and keeping it a pure function honors Policy 5. Siting
the watchlist inside the existing `/_shared/reference/` lane is simplicity-first (Policy 2): zero change to the
confinement boundary, and it co-locates with the registry sidecar (wh-hxt.4) so ONE DATA-gating mechanism covers
both DATA objects — the ≥2-callers trigger for the shared `_shared/scripts/` validator (ADR-015). A separate
DATA verdict is the only thing that prevents the false-merit merge the single-gate framing would have allowed.
The tag→SHA rule is the structural lesson of TeamPCP/tj-actions, delegated to exactly this ADR by ADR-024 §6(b)
so one ADR states it.
**Supersedes:** **ADR-021's tag-pin wording only** — ADR-021's installer *"pins a tag, prefers a GPG-signed
tag (`git verify-tag`)"* (ADR-021 Decision + Rationale (a)) is sharpened: **a tag-pin MUST resolve to and be
verified against an immutable commit SHA** (a mutable tag was force-pushed in the TeamPCP/tj-actions vector);
the GPG-signed-tag preference and the rest of ADR-021 (the two install lanes, the `mktemp`/trap, idempotent
vendor copy, `main()`-last-line truncation safety) are **unchanged**. This supersession is the one **DELEGATED
by ADR-024 §6(b)** (cross-referenced from ADR-024's Supersedes + References so exactly one ADR states it).
Otherwise extends ADR-001/004/022 (append-only clarification of "gated by the eval keep-or-revert" → KB edits
only) and composes with ADR-024 (CONTAIN admission, a different object) + ADR-025 (admissibility, a different
object). Does not supersede ADR-006 (it sharpens the pin granularity ADR-006 already mandates).
**Alternatives rejected:** (a) reuse Gate-1 (the eval keep-or-revert) for DATA edits — false-merit merge; the
corpus cannot score a watchlist row (loop-leverage §4.1/LBC-2). (b) Site the watchlist in `deps-scan/reference/`
(wh-k6l's draft path) — requires editing the frozen `confine_self_writes.ALLOW_SEGMENTS` + `gate_kb_edit.
GATED_SEGMENTS`, both out-of-lane for the outer loop to self-edit (ADR-024 §8); `_shared/reference/` needs zero
hook edit. (c) Put the validator in `deps-scan/scripts/` — only one caller there; the registry sidecar
(wh-hxt.4) is the second DATA caller, so `_shared/scripts/` is the ADR-015 home (and `validate_findings.py`
already proves the pattern). (d) A per-entry artifact digest on watchlist entries — the force-push lesson
applies to the SHA-pinned snapshot, not the entry; a digest belongs to CONTAIN admission (ADR-024 §5), a
different object. (e) An LLM-judged DATA gate — Policy 5 (provenance + schema + a regression predicate are pure
functions). (f) Fold this into ADR-024's admission or ADR-025's admissibility — category error (four objects:
KB / DATA / TOOL-artifact / license-policy; ADR-024 §5).
**References:** wh-562 (this spike); `docs/research/20260609_trivy_teampcp_supply_chain.md` (RQ1/RQ2 FINAL +
this Gate-2 design); `docs/research/20260609_supply_chain_compromise_monitoring.md` (the `watchlist-1.0` schema
RQ2 DECISION + the OSSF feeder + the ide-hygiene scan — wh-5es, folded in here); `docs/research/20260609_
supply_chain_loop_leverage.md` (§4.1 Gate-2, §5.1/LBC-6 the snapshot-pin correction, Addendum A1 the
DATA-verdict path). Code: `evals/score.py:64-95`, `evals/keep_or_revert.py`, `evals/gate-verdict.json` (absent →
Gate-1 fail-closed); `plugins/white-hacker/hooks/gate_kb_edit.py:18,22-24,40-49`, `confine_self_writes.py:40`
(ALLOW_SEGMENTS); `plugins/white-hacker/skills/deps-scan/scripts/malware_db.py:27,48,62-68` (loader +
`is_known_bad` + OSV read), `supply_chain.py:1015-1050` (version-aware S8); `_shared/scripts/validate_findings.py`
+ `_shared/scripts/conftest.py:10-15` (the shared-validator + cross-skill-import precedent); `_shared/scripts/
tests/test_registry_lock.py`; `docker/deps-scan-sandbox/fetch-snapshot.sh:16,34,36,37,40` (the SHA-pinned
snapshot); `deps-scan/reference/MALWARE-DB.md:39,48`. ADRs: **ADR-021** (its tag-pin wording superseded —
delegated by ADR-024 §6(b)), ADR-001/004/022 (the single-gate framing this clarifies, never edited), ADR-024
(CONTAIN admission + the gates-are-distinct-objects rule + §6(b) delegation), ADR-025 (admissibility — distinct
object), ADR-006 (pin+verify — sharpened), ADR-012 (human-gated draft-PR, never auto-merge), ADR-015
(capability port at ≥2 callers — the shared validator home), ADR-019 (the `supply-chain` class), ADR-027
(wh-nvk's drop-Trivy ADR — the Trivy-replacement rows ride this Gate-2; appended after this one). Siblings:
wh-k6l (the watchlist file — consumes the path + Gate-2), wh-5es (the feeder — schema-first, draft-PR + Gate-2),
wh-hxt.4 (the registry sidecar + row writer — Gate-2 mints its DATA verdict), wh-nvk (DIVERSIFY rows).

## ADR-027 — Trivy permanently removed; a diversified multi-vendor SCA/IaC set (Grype+Syft · Checkov · OSV-Scanner · gitleaks; kube-linter optional) behind the capability layer, each pinned+verified
**Status:** accepted — resolves spike wh-nvk (`docs/research/20260609_trivy_replacement_sca_iac.md`); the
DIVERSIFY-arm ADR for epic wh-hxt. License/egress verdicts cited from ADR-025 (every SPDX upstream-verified
2026-06-10); kube-linter verified upstream by this spike; Action-SHAs + release-artifact facts resolved
2026-06-10. The registry rewrite is the SHARED wh-xn0∪wh-nvk impl ticket (one coordinated writer);
per-tool pin+verify plugs into ADR-024 §5.
**Context:** Trivy (aquasecurity) was a do-everything tool covering SCA · IaC/misconfig
(Dockerfile/k8s/Helm/Terraform/CloudFormation) · container-image CVE · secrets · SBOM behind several
white-hacker capabilities. It was **TeamPCP-compromised** (CVE-2026-33634 / GHSA-69fq-xp46-6x23: the
`trivy-action`/`setup-trivy` tags were force-pushed, malicious binary v0.69.4 + images v0.69.5–.6
published — verification + our LOW–MEDIUM partial exposure are FINAL in
`docs/research/20260609_trivy_teampcp_supply_chain.md`), and the `trivy-mcp` wrapper was unmaintained +
pinned a stale binary (the "MCP trap"). The user DECIDED to drop Trivy; wh-d5b quarantined it as the
interim stopgap (demoted below Checkov for IaC, `detect_tools.py:116`; "permanent removal wh-nvk" caveat
in `tool-registry.md:54-57`). **Trivy stays OUT regardless of its Apache-2.0 license** (ADR-025 §2:
license-clean ≠ admissible — admissibility composes with admission/integrity).
**Decision:**
1. **Permanently remove Trivy** from `SCANNER_PREFERENCE` (`detect_tools.py:114` sca; `:116` iac) and the
   `tool-registry.md` SCA/IaC lines + the safe-version pin block (`:50-57`); record it in the
   "Rejected (integrity/TeamPCP)" subsection — a category DISTINCT from ADR-025's License-gate rejections
   (Trivy is license-clean but integrity-compromised). **It does not return.**
2. **Adopt the diversified split behind the capability layer (ADR-015), each a CLI (no MCP, ADR-002):**
   **SCA** → OSV-Scanner (cross-language) + Grype (image/dir) + native gates per-language; **container
   image + SBOM** → Grype + Syft; **IaC/misconfig** → Checkov (incl. Dockerfile, filling hadolint's
   GPL-rejected slot); **secrets** → gitleaks; **k8s second-source** → kube-linter (optional EXTEND);
   **GH-Actions** → actionlint/zizmor (kept). KICS is **excluded** (same TeamPCP campaign); trufflehog is
   removed by ADR-025 (AGPL License-gate fail) — not a swap.
3. **DIVERSIFY is blast-radius reduction, NOT the security control (subordinate to ADR-024 §1).** Security
   comes from CONTAIN (every tool offline + no-creds + sandboxed + provenance-verified), so a compromise
   of any tool — Trivy, its replacement, or one not yet picked — is inert. Multi-vendor split additionally
   limits blast radius (no single-vendor compromise removes the whole pipeline) at the **cost of more
   supply-chain surfaces** — every replacement therefore passes the SAME ADR-025 admissibility +
   ADR-024 admission gates. Diversity is defense-in-depth under containment; it is never re-elevated to
   "the answer."
4. **Per-tool pin+verify is ADR-024 §5's admission arm — not a new mechanism.** Pin every official Action
   to a **full commit-SHA** (a version tag is a mutable ref — the `trivy-action` 76/77 force-push proves
   only a SHA is immutable) and **verify the binary at admission**: Grype/Syft = cosign keyless
   (`checksums.txt`+`.pem`+`.sig`); OSV-Scanner = SLSA provenance (`multiple.intoto.jsonl`) + SHA256SUMS;
   kube-linter = Sigstore bundle (`.sigstore.json`); **gitleaks = checksum-only with NO upstream signature,
   so the expected checksum VALUE is pinned in OUR registry row / a committed pin file (reviewed once at
   admission via human PR) — the upstream `checksums.txt` ships from the same release as the binary and so
   does not defeat a publisher/release compromise (the TeamPCP vector: re-published binary + metadata);
   pinning the value in our git history makes the trust root our reviewed commit (the recorded gap is the
   missing upstream signature, the compensating control is the in-repo pin)**; Checkov = pip hash-pin
   (`pip install checkov==<ver> --require-hashes`) or a **digest**-pinned image — its Docker Action pins a
   *mutable* `:3.3.0` image tag, so the binary/pip path is preferred. The resolved SHAs are point-in-time
   (2026-06-10) — re-resolve + re-verify at the actual pin commit (ADR-006).
5. **The registry rewrite is ONE coordinated change shared with wh-xn0** (admissibility columns + these
   replacement rows + the `test_registry_lock.py:51` `r"0\.7[01]"` lock-regex retirement + the
   SCANNER_PREFERENCE edits) — never two uncoordinated writers to `tool-registry.md` + `detect_tools.py`.
6. **GATING (lens-5):** the impl must NOT flip the SAST default live until `evals/score.py` measures the
   downgrade (ADR-025 §4) GREEN on a **re-baselined, Java-inclusive** corpus (the stale 32-vs-103 baseline
   re-baselined first) — because Java taint is floor-only after find-sec-bugs (LGPL) drops, the measurement
   is blind where the loss is worst without Java cases. This gates the SAST arm of the shared rewrite; the
   Trivy/SCA/IaC row changes are not blocked by it.
**Rationale:** Removing a compromised tool is necessary but not sufficient (ADR-024: selection-by-trust was
defeated by Mini Shai-Hulud's valid SLSA provenance); the replacement set is safe **because it runs under
CONTAIN**, and diversified **so one vendor compromise degrades at most one capability** while the ADR-003
floor guarantees no capability is left empty. CLI-first (ADR-002) avoids recreating the trivy-mcp trap (a
3rd-party MCP layer obscuring the pinned artifact). Pin-to-SHA + verify-at-admission (ADR-024 §5 / ADR-006)
defeats the tag-force-push and substituted-binary vectors. The honest costs are recorded, not hidden:
gitleaks' single-maintainer/feature-complete posture + checksum-only releases (tracked via the staleness
arm), the checkov-action mutable image-tag, and the SAST precision downgrade (measured, not asserted —
Policy 9).
**Supersedes:** **nothing formally superseded in the ARD.** This ADR **RATIFIES** the `tool-registry.md`
COMPROMISED-block's "permanent removal wh-nvk" caveat (`:54-57`) and **supersedes wh-d5b's *temporary*
framing** ("Quarantined … returns when a safe pinned+verified version is cleared") — the removal is
**permanent; Trivy does not return**. **Extends** ADR-024 (uses its §5 admission arm + its CONTAIN-primary
demotion of DIVERSIFY — does not re-derive either) and **consumes** ADR-025 (cites its admissibility
verdicts + registry-schema columns + the SAST eval-measurement gate — does not restate them).
**Alternatives rejected:** (a) keep Trivy because it is Apache-2.0 — license-clean ≠ admissible; TeamPCP
integrity compromise (ADR-025 §2; wh-nvk). (b) Replace Trivy with one other do-everything tool — re-creates
the single-vendor blast radius the diversified set reduces. (c) Adopt KICS — same TeamPCP campaign
(`20260609_trivy_teampcp_supply_chain.md:44`); re-introduces a compromised-vendor surface. (d) Keep
trufflehog as the secrets tool — AGPL-3.0 License-gate fail + `--results=verified` egress (ADR-025 §2).
(e) Wrap any replacement in a 3rd-party MCP — the trivy-mcp trap (unmaintained indirection over a stale
binary); CLI-first (ADR-002). (f) Pin Actions to version tags — defeated by the `trivy-action` force-push;
only a full commit-SHA is immutable (ADR-024 §5). (g) Treat diversity as the security control — falsified
by Mini Shai-Hulud (ADR-024 §1); CONTAIN is primary, diversity is blast-radius reduction under it. (h) Use
the checkov Docker Action as-is — it pins a mutable `:3.3.0` image tag (the trivy-action trap class);
prefer the pip/digest-pinned binary path. (i) Flip the SAST default before measuring — Policy 9 /
ADR-025 §4 (the Java-inclusive eval gate must run GREEN first).
**References:** wh-nvk (this spike), `docs/research/20260609_trivy_replacement_sca_iac.md` (the scorecard +
coverage-parity matrix + the resolved Action-SHAs + per-tool verify primitives + the diversity-thesis
verdict subordinated to CONTAIN); `docs/research/20260609_trivy_teampcp_supply_chain.md` (TeamPCP
verification + exposure FINAL); `docs/research/20260609_tool_admissibility_license_gdpr.md` (ADR-025's
admissibility matrix — cited, not re-derived); `docs/research/20260610_contain_primary_control.md` +
`docs/research/20260609_supply_chain_tooling_strategy.md` (CONTAIN-primary framing). Code/registry anchors:
`plugins/white-hacker/skills/sec-detect/scripts/detect_tools.py:110-119` (SCANNER_PREFERENCE),
`plugins/white-hacker/skills/_shared/reference/tool-registry.md:30,38,50-57` (SCA/IaC + Trivy block),
`plugins/white-hacker/skills/_shared/scripts/tests/test_registry_lock.py:51` (the `r"0\.7[01]"` lock).
ADRs: ADR-002 (CLI-first/MCP-optional), ADR-003 (floor/degrade), ADR-006 (pin+verify), ADR-015
(capability-not-brand registry; self-updates), ADR-024 (CONTAIN primary; the artifact-provenance admission
arm §5; DIVERSIFY=blast-radius reduction §1), ADR-025 (admissibility two gates; the re-audited admissible
set; the SAST supersession + eval gate; the registry-schema columns); siblings wh-d5b (interim quarantine —
its temporary framing **superseded** here), wh-562 (the Gate-2 DATA gate validates the shared Trivy
watchlist entry — wh-k6l's instantiation; the sibling Gate-2 ADR is ADR-026), wh-xn0
(the SHARED registry rewrite), wh-hxt.4 (the ADMIT-via-loop screen), wh-hxt.1 (the staleness arm tracking
Betterleaks), wh-hxt.2 (the retire→replace runbook).

## ADR-028 — Distribution posture: manual install from the repo (vendor lane or local plugin registration); marketplace publication deferred
**Status:** accepted — operator decision 2026-06-10. Amends ADR-017's *primacy* claim only; the plugin mechanism is unchanged.
**Context:** ADR-017 made the Claude Code plugin **marketplace** the primary distribution and ADR-021 added the pinned `install.sh` vendor lane beside it. No marketplace listing has been published, and the operator has decided not to publish one for now — yet README/ARCHITECTURE presented "installed from a marketplace" as the path, claiming a distribution that is not offered (Rule 12: fail loud, never imply an unshipped path).
**Decision:** (1) **Manual install is the documented path** until a listing ships: clone/fetch this repo and either run the **`install.sh` vendor lane** (default + recommended — pinned tag, `git verify-tag` preferred, idempotent; ADR-021, tag→SHA per ADR-026) or **register the clone locally** (`claude --plugin-dir ./plugins/white-hacker`, or `claude plugin marketplace add <local clone>` against the in-repo catalog `.claude-plugin/marketplace.json`, then `claude plugin install white-hacker@white-hacker-marketplace`). (2) User-facing docs (README § Install & onboarding, ARCHITECTURE §8, release-checklist §4) present manual install as primary and drop "published via a marketplace" wording. (3) The payload remains a **valid plugin**: the dev-vs-payload split (ADR-017), the vendor payload boundary (ADR-022), `packaging/validate_manifest.py`, and `claude plugin validate` still gate releases — flipping to a published marketplace later is a docs-only change.
**Rationale:** Honest docs over aspirational ones; zero mechanism change (the same validated payload serves both paths); the strongest pin/verify posture (ADR-006/021) is the vendor lane, which is already built and tested; the in-repo catalog keeps local registration working without any publication step.
**Supersedes:** nothing structurally — **amends ADR-017's "primary distribution" to "intended end-state; publication deferred."** ADR-017's manifest/namespacing/dev-vs-payload decisions and ADR-021's two lanes stand unchanged.
**Alternatives rejected:** (a) publish the marketplace listing now — deferred by the operator. (b) Drop the plugin shape and ship copy-only — loses manifest validation, namespacing, and the cheap future flip. (c) Leave the docs claiming marketplace distribution — asserts a path that is not offered (Rule 12).
**References:** operator instruction 2026-06-10; ADR-017 (mechanism — primacy amended), ADR-021 (`install.sh` vendor lane), ADR-022 (payload boundary), ADR-026 (tag→SHA); `README.md` § Install & onboarding; `docs/ARCHITECTURE.md` §8; `docs/release-checklist.md` §4; `.claude-plugin/marketplace.json` (in-repo catalog — local registration only).


## ADR-029 — One white-hacker agent: the shipped product reviews our own code (consolidate; delete the project self-audit shadow)
**Status:** accepted — operator decision 2026-06-11. Reverses wh-g2v's 2026-06-09 "keep both" groom; clarifies ADR-009 + ADR-017.
**Context:** Two files declared `name: white-hacker`: the SHIPPED generic reviewer (`plugins/white-hacker/agents/white-hacker.md`, ADR-017 payload) and a PROJECT-LOCAL self-audit teammate (`.claude/agents/white-hacker.md`). Verified against the official Claude Code subagent docs (`sub-agents.md`): scope precedence is managed(1) > `--agents`(2) > project `.claude/agents/`(3) > user `~/.claude/agents/`(4) > **plugin agents (5, lowest)**; "when multiple subagents share the same name, the higher-priority location wins." So the project profile **permanently shadows** the plugin product — the shipped white-hacker has NEVER run as `white-hacker` in our own sessions. Maintaining a second, hand-written reviewer is (a) the opposite of dogfooding (we reviewed our own code with a *different* agent, not the product) and (b) drift-prone.
**Decision:** ONE white-hacker = the shipped product. (1) DELETE `.claude/agents/white-hacker.md` (removes the shadow). (2) The self-audit *methodology* — reviewing an AI agent's own confinement / injection / self-improvement surfaces + Rule-of-Two + the confinement-bypass red-team classes — is migrated INTO the product, **generalized and machine-agnostic**, as `_shared/reference/agent-self-review.md` + an "Agent-as-target" category in the product agent's "what to check"; this is a capability GAIN (the product can now review ANY AI agent's own surfaces, not just ours). (3) DOGFOOD = run dev/team sessions with the plugin loaded (`claude --plugin-dir ./plugins/white-hacker`, ADR-028) so `subagent_type: white-hacker` resolves to the product. (4) GUARDRAIL (operator-mandated): the migrated content is METHODOLOGY only — NO local-system info, NO PII, and **NO security-CHECK RESULTS** (audit/scan results are LOCAL EVIDENCE → `.notes/security_audit/`, gitignored, never in git).
**Rationale:** Real dogfooding = use the product on ourselves; if the product can't review our own confinement, that is a PRODUCT gap to fix IN the product, not to fork into a twin. One source of truth; resolves the name collision; the self-audit knowledge becomes a generic, reusable capability.
**Supersedes:** wh-g2v's 2026-06-09 "intentionally distinct, do NOT merge" design. **Clarifies ADR-009** ("define the identity once at `.claude/agents/white-hacker.md`") — the shipped identity was relocated to `plugins/` by ADR-017; with the self-audit profile removed there is exactly one identity (the plugin product). ADR-017's dev-vs-payload split and ADR-028's manual-install / plugin-loaded dogfood stand unchanged.
**Alternatives rejected:** (a) keep both, rename the project profile to de-collide (the original wh-g2v plan) — preserves a profile that shadows the product forever = never dogfooding the shipped agent. (b) symlink/regenerate one from the other — couples two different-purpose files. (c) leave the self-audit knowledge only in the deleted profile — loses a generic capability.
**References:** wh-g2v (re-scoped 2026-06-11); official Claude Code subagent docs https://code.claude.com/docs/en/sub-agents (scope-precedence table); ADR-009 (identity-once), ADR-017 (dev-vs-payload), ADR-028 (manual-install / `--plugin-dir` dogfood), ADR-001 §6 (Agents Rule of Two); `plugins/white-hacker/skills/_shared/reference/agent-self-review.md` (migrated methodology); `.claude/CLAUDE.md` § Architecture at a glance + § Security posture.


## ADR-030 — Process: planning lives in beads epics/tickets, not `docs/plan/`
**Status:** accepted — operator decision 2026-06-12. Supersedes ADR-013's `docs/plan/` "approved plan" clause.
**Context:** ADR-013 mandated "no build before an approved plan (`docs/plan/`)" plus a maintained `docs/plan/PLAN.md` + `phase-*` build docs. The project has since moved all planning to **beads** (`bd`): an epic's mandatory "Execution Waves" table is the build order, each ticket is designed via `/design-ticket` + its type template and carries Goal/Steps/AC/Verification, and `.notes/order.md` (gitignored) is the live wave pointer. `docs/plan/PLAN.md` (a 2026-06-06 DRAFT) and `phase-0..13` became a stale parallel plan — two sources of truth that drift.
**Decision:** (1) **DELETE `docs/plan/`** (PLAN.md, README.md, `phase-0..13` — 17 files; recoverable from git history). (2) Planning IS beads: the epic Execution-Waves table is the build order; every ticket is `/design-ticket`-designed and carries Verification criteria; `.notes/order.md` is the local wave pointer. (3) Re-point the live references — the 12-policy bindings (`.claude/CLAUDE.md` P1/P3/P10), the agent profiles (developer/tech-lead/project-manager/researcher), and the companion docs (README/ARCHITECTURE/DDD/PRD/release-checklist) — from `docs/plan/` to beads. (4) The `## Verification criteria`/`## Acceptance Criteria` definition-of-done discipline from ADR-013 is UNCHANGED — it lives in the beads ticket now, not a `docs/plan/` task.
**Rationale:** One source of truth for the plan (beads is already where waves launch — `/launch-team` reads the epic + `.notes/order.md`); removes the drifting parallel plan docs; the plan-first + verification-per-task discipline ADR-013 mandated is preserved, just relocated to where work is tracked.
**Supersedes:** ADR-013's `docs/plan/` "approved plan" clause + its "`plan/*` maintained" living-docs item. ADR-013's other clauses (verification-criteria-per-task, spikes/PoCs for uncertain assumptions, `README`/`PRD`/`DDD`/`ARCHITECTURE`/`ARD` maintained, ARD append-only) stand unchanged.
**Alternatives rejected:** (a) keep `docs/plan/` in sync with beads — the drift this removes (two plans, one a stale DRAFT) is exactly the problem. (b) archive `docs/plan/` elsewhere under `docs/` instead of deleting — leaves dangling cross-refs + a second plan surface; git history already preserves it. (c) leave ADR-013 unannotated — a settled ADR mandating a now-deleted path with no supersession trail (Policy 7: superseded ones say so).
**References:** operator decision 2026-06-12; ADR-013 (process — plan-doc clause superseded); root `CLAUDE.md` § Ticket creation & grooming (beads ticket templates); `.claude/commands/launch-team.md` (reads the epic Execution-Waves table + `.notes/order.md`); `docs/beads_templates/` (ticket type templates).


## ADR-031 — Proportionality & blast-radius doctrine for security-research actions (the anti-DN42 criteria); resource caps move from Context-advisory to Harness-enforced
**Status:** accepted — operator decision 2026-06-12. Prompted by the DN42 AI-agent bankruptcy incident; names existing posture as criteria and ratifies one enforcement-surface upgrade (C5 → Harness).
**Context:** A public write-up documented an AI agent that provisioned 5× `m8g.12xlarge` + load balancers + Lambda ("100 Gbps", "index the network") to scan **DN42** — a hobby network a single small VPS would serve — running up a US$6,531 AWS bill (later reduced to ~$1,894). The failure was a *pattern*, not a one-off: (F1) disproportionate scope; (F2) hollow approval — the agent asked for confirmation repeatedly and the operator just said "complete this right away without delay" without inspecting the plan or costs; (F3) irreversible, per-hour accumulating cost (CloudFormation re-run redundantly); (F4) no hard cap — discovered only via a credit-card charge ~24h later; (F5) the agent manufacturing its own deadline urgency ("my user's deadline is approaching, I must complete this promptly"); (F6) the operator's takeaway being "next time a better agent is needed" — a process/oversight failure misread as a model-capability failure. white-hacker is a different shape (a read-only *reviewer*, not an infra agent), so the literal cloud-spend path is absent — but the pattern must be checked. An audit (2026-06-12) mapped each mode to our artifacts: the bankruptcy-class is **structurally precluded** (no spend channel + no reachable credentials + reversible-text-artifact outputs), yet our proportionality/resource caps live in the **Context surface (advisory prose), which ADR-004 holds the model may ignore**, not the Harness.
**Decision:** Adopt the **C1–C8 proportionality & blast-radius criteria** as standing doctrine for any action whose cost or impact *scales*. Each names the surface that must enforce it (Harness binds; Context only advises — ADR-004):
- **C1 Authorized scope only** — own working tree/diff; no external-host / "the internet" scanning; no fetch-then-scan of arbitrary branches. *(Harness partial: egress allow-list for `curl/wget/nc/…` — `confine_self_writes.py:122`; Context posture — `white-hacker.md:35`.)*
- **C2 Static/read-only by default** — active/live actions (PoC, network probes, builds, installs) are opt-in **and** contained. *(`white-hacker.md:79`; CONTAIN lane — ADR-024.)*
- **C3 No spend channel / no reachable credentials.** *(Harness — secret-file block `guard_bash.py:84`; Rule of Two — ADR-001.)* **Load-bearing — the anti-bankruptcy control.**
- **C4 Reversible effects only, via capability-removal** — no push/apply/money/external mutation; durable outputs are text artifacts. *(Harness — no `Write`/`Edit` tool `white-hacker.md:16`; git-mutation block `guard_bash.py:79`; ADR-010/016.)* **Load-bearing.**
- **C5 Proportionate resources** — concurrency & scan-breadth capped to the engagement; measure the host (ADR-023); default to the lighter mode. **Currently Context-advisory only (`white-hacker.md:150-188`) — to be Harness-enforced (action 1).**
- **C6 Substantive, not hollow, approval** — gates are *structural*, so they hold even when the operator rubber-stamps; where human review is required the shown surface suffices to decide and the change is reversible.
- **C7 Never manufacture urgency** to bypass inspection; caution over speed (Policy 1).
- **C8 Incidents drive gated guardrail/process edits, not model swaps** — the outer loop (ADR-001/004) is the institutional answer to F6.

Ratified actions: **(1)** a PreToolUse tripwire **Harness-enforces C5/C1** — bound unbounded subagent fan-out and flag active-scan/cloud verbs (`nmap`/`masscan`/`aws`/`terraform`/`gcloud`) that the egress allow-list (verb-scoped to `NET_VERBS`) does not cover — designed via `/design-ticket` (task). **(2)** A spike verifies whether the confine/egress hooks fire for **subagent/teammate** writes (white-hacker's primary modes) or only the top-level session; if top-level-only, capability-removal (C3/C4) is the sole Harness layer in those modes and that limit is documented.
**Rationale:** Naming the criteria makes the audit repeatable and hands `sec-learn`/reviews a checklist. The bankruptcy-class is already precluded by C3+C4 (both structural), so the only ratified *change* is the smallest one that closes the live gap (C5 advisory → enforced). Enforcement-surface honesty (ADR-004) is the through-line: a cap the model may ignore is not a cap.
**Supersedes:** nothing — augments ADR-001 (Rule of Two), ADR-004 (Harness-not-Context guardrails), ADR-007 (static-only default), ADR-010/016 (capability-removal / PreToolUse confinement), ADR-023 (resource probe), ADR-024 (CONTAIN).
**Alternatives rejected:** (a) "get a better agent" — the F6 misattribution the incident itself warns against; our answer is gated guardrails, not a model swap. (b) Leave C5 as advisory prose — ADR-004 holds Context guardrails are ignorable; the over-provisioning analog deserves a Harness tripwire. (c) A hard kill-switch on all fan-out — over-correction; the floor must keep working (ADR-003), so a *bounded* cap + active-verb flag, not a block.
**References:** DN42 incident write-up (lantian.pub, "AI Agent Bankrupted Their Operator While Trying to Scan DN42", retrieved 2026-06-12); audit 2026-06-12; ADR-001/004/007/010/016/023/024; `plugins/white-hacker/agents/white-hacker.md` (:16 no Write/Edit, :35 scope, :79 static-only default, :150-188 execution budget); `plugins/white-hacker/hooks/guard_bash.py` (:79 git-mutation block, :84 secret-file refs); `plugins/white-hacker/hooks/confine_self_writes.py` (:122 egress allow-list); `plugins/white-hacker/hooks/confine_patch_writes.py` (:3-10 "tripwire, not the boundary"). NOTE (Policy 7): two hook docstrings claim a `permissions.deny` pairing that is **absent** from `.claude/settings.local.json` — reconcile separately (offered as action C, deferred by the operator 2026-06-12).
