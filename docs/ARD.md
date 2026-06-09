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

## ADR-019 — Expand the closed `technique_class` vocabulary 5→6: add AI-native `supply-chain` (slopsquatting / AI-SDK typosquat), ecosystem-agnostic
**Status:** accepted — resolves spike-09 (`docs/research/spike-09-npm-ai-supply-chain-2026-06.md`)
**Context:** ADR-012 fixed the ai-attack-kb `technique_class` as a closed enum of on-disk file stems. Spike-09 surfaced an AI-native supply-chain technique not covered by the original five: **slopsquatting** (an LLM invents a plausible-but-nonexistent package name; an attacker pre-registers it; a developer pastes the AI's install command — ~1-in-5 AI suggestions name a nonexistent package, 43% repeat) plus **AI-SDK typosquatting** (lookalike names of popular AI/LLM SDKs). The name-trust failure is ecosystem-agnostic (npm/PyPI/RubyGems/Go/crates/Maven); npm is just the hottest current example.
**Decision:** Add `supply-chain` as the sixth member of the `technique_class` enum (the closed vocabulary stays closed — it grows by an appended ADR, never silently). The single source of truth is `kb-entry-schema.json`'s enum, which `validate_kb.load_schema()` reads; `SKILL.md`'s vocabulary table mirrors it. The new `reference/supply-chain.md` entry (`AISEC-SUPPLY-CHAIN-001`, primary xref `LLM03:2025`) documents the **technique** with cross-ecosystem, technique-level detections; the generic, per-ecosystem detection **mechanics** (registry-record check, distance-to-AI-SDK-allowlist, install-script inspection) live in the deps-scan supply-chain floor (wh-07w), not in the KB. Refreshable by `/sec-kb-refresh` like the other classes.
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
