# Phase 10 — Distribution & Onboarding (plugin packaging + project-detecting init)

> **Status:** DONE (2026-06-07) — built by the TL/QA/Dev/white-hacker team flow; 502 tests green
> across 14 packages; dogfood security review found+fixed one MEDIUM (F-001, below). Date: 2026-06-06.
> Owner: ping@jaigouk.kim.
> Source spike: [`docs/research/spike-07-agent-distribution-and-init-2026-06.md`](../research/spike-07-agent-distribution-and-init-2026-06.md)
> (RESOLVED, HIGH). Governs/extends **ADR-014**; introduces **ADR-017** (T-10.1).
> **Plan-first:** these are proposals — nothing is built until the plan is approved.

## Why this phase
Today the shipped payload (agent + skills + commands + hooks + KB) lives in **this repo's dev
`.claude/`**, conflating "dev/dogfood config" with "the artifact a user installs." Spike-07
established the canonical 2026 shape: **a Claude Code plugin published via a marketplace**, with
`.claude/` (dev) and `plugins/<name>/` (payload) as siblings, and a **project-detecting init**
that emits a *gated, project-scope companion* the generic agent consumes — **never** a rewrite of
the shipped identity (ADR-004). This phase makes that real.

## Target layout (from spike-07 Decision)
```
white-hacker/                          # repo root == the marketplace
├── .claude-plugin/marketplace.json    # catalog (lists the white-hacker plugin)
├── plugins/white-hacker/              # the shipped plugin payload
│   ├── .claude-plugin/plugin.json     # ONLY the manifest lives here
│   ├── agents/   skills/   commands/  # component dirs at PLUGIN ROOT (never under .claude-plugin/)
│   ├── hooks/hooks.json   scripts/    # confinement + capture + SessionStart-detect
│   └── (no CLAUDE.md — plugin-root CLAUDE.md is not loaded)
├── .claude/                           # THIS repo's own dev/dogfood config (thin)
├── docs/  config/  evals/  ci/        # unchanged
└── CLAUDE.md                          # dev conventions (not shipped)
```
Dogfood during dev via `claude --plugin-dir ./plugins/white-hacker` (or self-registered marketplace).

## Conventions (inherit from `docs/plan/README.md`)
Same task-block shape, status lifecycle, and "what makes a VC valid" rules. Python via
`uv run pytest`; new `scripts/` packages get a colocated `pyproject.toml`. **Do not** start a task
before the plan is approved. IDs are typed and never renumbered.

---

### T-10.1 · ADR-017 + ARCHITECTURE §8 refresh (distribution & init architecture)
- **Goal:** record the accepted decision — distribute as a plugin via marketplace; `.claude/` (dev)
  vs `plugins/<name>/` (payload); project-detecting init emits a gated project-scope companion,
  never a profile rewrite — superseding the thin ADR-014.
- **Artifact:** `docs/ARD.md` (append `## ADR-017 …`, mark ADR-014 superseded-by-017), `docs/ARCHITECTURE.md` §8.
- **Depends on:** — (consumes spike-07).
- **Verification criteria:**
  - [x] ADR-017 present and accepted — `grep -nE "^## ADR-017" docs/ARD.md`
  - [x] ADR-014 marked superseded — `grep -n "superseded by ADR-017" docs/ARD.md`
  - [x] ARCHITECTURE §8 names plugin+marketplace and the dev/payload split — `grep -niE "marketplace|plugins/white-hacker" docs/ARCHITECTURE.md`
  - [x] ARD cross-ref table has an ADR-017 row — `grep -n "ADR-017" docs/ARCHITECTURE.md`
- **Status:** done

### T-10.2 · Plugin manifest + marketplace catalog (+ schema tests, TDD)
- **Goal:** author a valid `plugin.json` and `marketplace.json` and a test that enforces the
  canonical layout rules (required fields; relative `./plugins/white-hacker` source; no component
  dirs under `.claude-plugin/`).
- **Artifact:** `plugins/white-hacker/.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`,
  stdlib validator package `packaging/{validate_manifest.py,pyproject.toml,conftest.py,tests/test_validate_manifest.py}`.
- **Depends on:** T-10.1.
- **Verification criteria:**
  - [x] failing-test-first then green, >1 test (29), edge cases — `uv run --with pytest pytest packaging/tests/ -q`
  - [x] manifest has required `name` (kebab-case) — asserted by the test
  - [x] catalog lists `white-hacker` with `source` `./plugins/white-hacker` and a verified-present path — asserted by the test
  - [x] validator fails if any of `commands/ agents/ skills/ hooks/` is placed inside `.claude-plugin/` — negative-case test
  - [x] stdlib floor validator passes on the real repo — `uv run python packaging/validate_manifest.py .` exit 0 (`claude plugin validate` optional, CLI not required)
- **Status:** done

### T-10.3 · Migrate payload `.claude/` → `plugins/white-hacker/` (preserve dogfooding + eval green)
- **Goal:** move agent/skills/commands/hooks/KB into the plugin-root layout; keep this repo working
  by dogfooding the plugin (`--plugin-dir` or self-marketplace); leave a thin dev `.claude/`.
- **Artifact:** `plugins/white-hacker/{agents,skills,commands,hooks,scripts}/…` (git-moved), thin
  `.claude/`, updated hook paths (use `${CLAUDE_PLUGIN_ROOT}` not repo-relative paths).
- **Depends on:** T-10.2.
- **Verification criteria:**
  - [x] layout: every component dir at plugin root, `.claude-plugin/` holds only `plugin.json` — `uv run python packaging/validate_manifest.py .` exit 0
  - [x] no component dir under any `.claude-plugin/` — `find plugins -path '*/.claude-plugin/*' -type d` prints no component dirs
  - [x] full test suite green at parity from new locations (12/12 packages, 400 tests) — per-package `uv run --project <pkg> --with pytest pytest <pkg>/tests`
  - [x] repo-root fixture paths made location-independent (`.git`-walk, not hardcoded `parents[N]`) — sec-report + deps-scan tests green
  - [x] hooks register the PreToolUse confinement chain via `plugins/white-hacker/hooks/hooks.json` using `${CLAUDE_PLUGIN_ROOT}` (resolves to executables) — `test_hooks_json.py`
  - [x] plugin-prefix robustness tests + self-disablement guard generalized (control files / `.claude-plugin/` denied) — hooks pkg 87 tests green
- **Status:** done

### T-10.4 · Reconcile identity vs plugin context limits (no shipped CLAUDE.md; identity in agent+skills)
- **Goal:** guarantee the agent's identity/posture is fully carried by `agents/white-hacker.md` +
  skills (since a plugin-root CLAUDE.md is not loaded), and that the repo `CLAUDE.md` stays dev-only.
- **Artifact:** audited `plugins/white-hacker/agents/white-hacker.md`, `tests/test_identity_carriage.py`.
- **Depends on:** T-10.3.
- **Verification criteria:**
  - [x] no CLAUDE.md ships inside the plugin — `find plugins/white-hacker -name CLAUDE.md` prints nothing
  - [x] all 6 posture/identity clauses present in `agents/white-hacker.md` (no edit needed) — `missing_posture_clauses()` == []
  - [x] 4 tests incl. a negative case (checker flags a stripped sample) — `uv run --with pytest pytest packaging/tests/test_identity_carriage.py -q`
- **Status:** done

### T-10.5 · Project-detecting init → committed project-scope companion (reuse sec-detect/sec-threat-model)
- **Goal:** an onboarding step (`/sec-init` skill and/or a `Setup`-hook script) that runs detection +
  threat-model-seed once and persists a **gated, project-scope** profile the generic agent consumes —
  pruned scanner registry, loaded language appendices, threat-model seed, scoring standard, AI-pass
  flag — **without** mutating the shipped identity.
- **Artifact:** `plugins/white-hacker/skills/sec-init/{SKILL.md, scripts/{init_profile.py,
  project_profile_schema.json,pyproject.toml,conftest.py,tests/test_init_profile.py}}`; reuses
  `sec-detect`; writes `<repo>/.white-hacker/project-profile.json` (project-scope companion).
- **Depends on:** T-10.3.
- **Verification criteria:**
  - [x] failing-test-first then green, 32 tests (sec-detect fixture + tmp manifests) — `uv run --project plugins/white-hacker/skills/sec-init/scripts --with pytest pytest .../tests -q`
  - [x] generated profile validates against `project_profile_schema.json` — asserted by the test
  - [x] no shipped-identity keys possible (`additionalProperties:false`; `posture`/`tools` rejected) — negative-case test
  - [x] factual-not-imperative guard (write refuses imperative strings) + size cap `json.dumps < 8000B` (fits 10k SessionStart cap) — asserted by the test
- **Status:** done

### T-10.6 · SessionStart factual-context injection (project scope, injection-safe)
- **Goal:** an optional **project-scope** SessionStart hook that emits the detected profile as
  **factual statements** (≤10,000 chars), honoring bug #16538 (project, not plugin, scope); the agent
  continues to treat injected content as untrusted.
- **Artifact:** `.claude/hooks/sessionstart_project_facts.py` (+ test), settings registration.
- **Depends on:** T-10.5.
- **Verification criteria:**
  - [x] hook emits valid `SessionStart` JSON with `additionalContext`, ≤10k, factual — `uv run --project plugins/white-hacker/hooks --with pytest pytest .../tests/test_sessionstart_facts.py`
  - [x] **allowlist** sanitizer (closed-vocab token shape + word cap), not a denylist — neutralizes attacker-committed profile prose/markdown (F-001 fix); 13 hook tests cover the bypass classes
  - [x] no-op on absent/invalid profile; empty-repo edge case covered — asserted by the test (107 hook tests green)
  - [x] registered in plugin `hooks/hooks.json` under `SessionStart`; **project-scope** registration documented for target repos (honors bug #16538) — `test_hooks_json.py`
- **Status:** done

### T-10.7 · Onboarding + dev-vs-ship docs (README, install commands, dev loop)
- **Goal:** document install (`/plugin marketplace add` + `/plugin install`), the `--plugin-dir`
  dev/dogfood loop, the `/sec-init` onboarding, and the `.claude/`-vs-`plugins/` split.
- **Artifact:** `README.md` (Install/Onboarding section), `docs/release-checklist.md` update,
  `docs/plan/README.md` Phase-10 row.
- **Depends on:** T-10.2, T-10.5.
- **Verification criteria:**
  - [x] README documents install + dev-loop commands — `grep -niE "plugin marketplace add|plugin install|plugin-dir" README.md` (5 hits)
  - [x] README documents `/sec-init` onboarding + dev-vs-payload split — `grep -n "sec-init" README.md` (5 hits)
  - [x] plan index lists Phase 10 — `grep -n "phase-10-distribution-init" docs/plan/README.md`
  - [x] release-checklist has plugin-release steps; links resolve — `grep -niE "validate_manifest|plugin validate" docs/release-checklist.md`
- **Status:** done

---

## Decisions made during the phase (TL)
- **One plugin** `white-hacker` in marketplace `white-hacker-marketplace` (single-plugin for now;
  revisit a split if KB-refresh cadence diverges from the reviewer).
- **Migration strategy** (user-chosen): plugin-root-relative, then move. The confinement hooks turned
  out to be **segment-relative already** (`/ai-attack-kb/`, `/_shared/reference/`), so the move was
  behavior-preserving (400→502 tests still green); the only guard change was *hardening* the
  self-disablement denylist (control files / `.claude-plugin/`).
- **Dogfood mechanism:** `claude --plugin-dir ./plugins/white-hacker` (documented in README).
- **Init carrier:** ship `/sec-init` skill (discoverable) + document the `claude --init-only` Setup path.

## Phase-10 security review (white-hacker dogfood, 2026-06-07)
The white-hacker agent reviewed the Phase-10 diff (static-analysis-only) with focus on the new
untrusted-input surfaces.
- **F-001 (MEDIUM, FIXED):** `sessionstart_project_facts.py` rendered attacker-committable profile
  fields into auto-injected `additionalContext` behind a **denylist** sanitizer, bypassable with
  out-of-vocab imperative prose / markdown-role framing. Fixed by switching to an **allowlist**
  (closed-vocab token shape + word cap), keeping the denylist + fail-closed `is_factual` as
  secondary layers. Re-verified: attacker strings no longer reach the context; legit tokens still
  render; +6 bypass-class tests (hook pkg 107 green).
- **Confirmed NOT regressions:** the `confine_self_writes` generalization is a hardening (control
  files denied even inside the allow lane); `init_profile.py` detection is read-only with no
  target-code execution and a fixed output path; validator/manifests clean.

## Result
All 7 tickets `done`. 14 test packages green (**502 tests**); plugin/marketplace validator exit 0;
hooks.json wires PreToolUse confinement + SessionStart facts. Repo is now a Claude Code marketplace
(`.claude-plugin/marketplace.json`) shipping `plugins/white-hacker/`, with a thin dev `.claude/`.
**Not yet done (deliberately, separate concerns):** git commit (awaiting user), real-world
`/plugin install` smoke test against a published GitHub remote, and CI wiring of `validate_manifest`.
