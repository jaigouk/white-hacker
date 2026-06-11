# Spike: ratify CONTAIN (assume-breach / zero-trust tool execution) as the PRIMARY supply-chain control

**Date:** 2026-06-10 · **Author:** researcher (seat-wh-hxt.3) · **Ticket:** wh-hxt.3 (epic wh-hxt, wave 1b-keystone)
**Status:** spike COMPLETE — decisions made; ADR-024 appended to `docs/ARD.md`; impl follow-ups drafted below
**Grounding (no new web research — the 2026 evidence is already cited here):**
`docs/research/20260609_supply_chain_tooling_strategy.md` (the CONTAIN section + 2026 primary sources) ·
`docs/research/20260609_supply_chain_loop_leverage.md` (G4 + LBC-4/LBC-5 + §9 decisions) ·
`docs/research/20260609_trivy_teampcp_supply_chain.md` (the per-tool offline/verify scorecard).

---

## 0. Goal & scope

Ratify **CONTAIN** — *assume any tool is backdoored; make the backdoor inert by denying network/egress +
creds + host write* — as the **PRIMARY** supply-chain control, with the existing 5-stage lifecycle
(ADMIT→PIN/VERIFY→DIVERSIFY→MONITOR→RETIRE) demoted to **defense-in-depth under it**. The driving fact
(strategy doc:29-35): Mini Shai-Hulud (May 2026; TanStack/Mistral/OpenSearch) victims carried **valid
SLSA Build L3 provenance + OIDC trusted-publishing + 2FA** and were still compromised — the worm hijacked
the *legitimate* pipeline; the only control that stopped it **in flight** was an **egress allowlist**.
Verification-by-reputation is defeatable; containment does not depend on knowing what is bad.

Six research questions, each → a DECISION. This is research + ADR + ticket-carving — **no package code**
this wave (CONTAIN enforcement code is out-of-lane for the spike; see §6.7 and ADR-024).

**Out of scope (cite, do not re-debate):** ADR-001 (the two loops), ADR-003 (degrade-to-floor),
ADR-006 (pin+verify), ADR-007 (opt-in sandboxed detonation), ADR-015 (capability-not-brand registry),
ADR-016 (confinement = defense-in-depth, structural-baseline-first). wh-562 owns the Gate-2 DATA-gate
mechanism; wh-nvk owns DIVERSIFY; wh-xn0 owns ADMIT gates — cross-reference, never fold.

---

## RQ1 — The per-tool containment matrix

**The CONTAIN invariant (the registry rule):** at **every** tool execution, **at least two of three**
must be ABSENT — `{ network/egress · credentials in the tool's env · host write access }`
(strategy doc:44-48). The matrix below classifies the diversified set (the wh-nvk replacement set +
the native gates) on the four axes that decide whether a tool runs *inside the lane today* or needs the
**fetch/analyze split** the repo already uses (`fetch-snapshot.sh:2-6` — network-on FETCH, then
network-off ANALYZE; the Agents Rule of Two, `white-hacker.md:39-41`).

Tool licenses + telemetry are upstream-verified 2026-06-09 (GitHub LICENSE files + release infra, per the
trivy-replacement scorecard / agent memory) — they are reproduced as the ADMIT context, not re-derived here.

| Tool (capability) | Offline-capable today | Needs fetch/analyze split | Creds needed | Sandbox-ready (today) |
|---|---|---|---|---|
| **gitleaks** (secrets) | **YES** — regex/entropy rules, no external DB; MIT, no telemetry | **No** | No | **YES** — pure read of the worktree |
| **Checkov** (IaC/misconfig) | **YES** when run offline w/o `--bc-api-key` (policies bundled; the Prisma enrich API is a suppressible network *enrichment*, not required) | **No** (optional enrich only) | No (a `--bc-api-key` is opt-in push — keep it OUT of the lane env) | **YES** offline |
| **Syft** (SBOM) | **YES** — reads packages from the filesystem/image; Apache-2.0, local | **No** | No | **YES** |
| **Grype** (SCA / image-CVE) | **YES against a pre-fetched DB** — the vuln DB wants a periodic network refresh (same shape as Trivy's `--skip-db-update` offline cache, scorecard:32,54, and the OSSF snapshot) | **YES** — DB refresh is the FETCH step; matching is the network-off ANALYZE step | No | **YES** once the DB is mounted `:ro` |
| **OSV-Scanner** (SCA, second source) | **YES against a pre-fetched OSV DB** (offline mode consumes a local OSV database; cross-checks Grype) | **YES** — same DB-refresh split as Grype | No | **YES** once the DB is mounted `:ro` |
| **OSSF snapshot** (the deps-scan S8 known-bad DB) | **YES** — already split + SHA-verified | **YES — already implemented** (`fetch-snapshot.sh`) | No | **YES** (the existing lane) |
| **pip-audit / npm audit / govulncheck** (native gates) | **partial** — these query a remote advisory service by default; offline needs a pre-seeded local advisory DB / `--no-deps`-style local mode per tool | **YES** (the remote advisory query is the FETCH step) | No (read-only advisory queries; no auth) | **YES** once seeded offline; else degrade |

**RQ1 DECISION.** Three classes:
1. **Pure-offline today** — gitleaks, Checkov (offline, no `--bc-api-key`), Syft. Drop straight into the
   lane: `--network none` + `:ro` worktree mount. Two-of-three trivially satisfied (no egress, no creds).
2. **Offline-with-a-pre-fetched-DB (fetch/analyze split)** — Grype, OSV-Scanner, and the OSSF snapshot.
   The vuln/OSV DB is fetched in a separate **network-on, no-untrusted-analysis** step (exactly
   `fetch-snapshot.sh`'s pattern), then ANALYZE runs `--network none` against the DB mounted `:ro`.
   This is the canonical CONTAIN shape — it is what makes a backdoored scanner inert (it has the DB but no
   way to phone home).
3. **Native gates (pip-audit/npm audit/govulncheck)** — remote-advisory-by-default; offline requires a
   per-tool pre-seeded local advisory DB. Where that is not configured, they **degrade to the floor**
   (`tool_assisted:false`, listed in `tools_unavailable`) rather than being run with egress — never weaken
   the invariant to "let this one tool reach the network."

**Honest limit (carry to the impl ticket):** the *exact* offline-DB CLI flag per tool (Grype
`GRYPE_DB_*` / `db import`, OSV-Scanner offline-DB flag, the native-gate local-DB modes) is **not pinned
from local evidence** — only the architectural shape is (the Trivy `--skip-db-update` cache + the OSSF
split are the local proof points). Resolving the precise flags is part of impl ticket (a) — the one-tool
live-verify (Grype) build-verifies the offline-DB path on a daemon host.

---

## RQ2 — The lane shape: shared `_shared` tool-exec lane vs per-skill LOCKDOWN[]

**Options.**
- **(A) A single shared `_shared` tool-exec lane** — generalize `docker/deps-scan-sandbox/run.sh` into a
  capability-agnostic wrapper any skill calls (`run.sh <capability> <tool> <args> [--mount db:ro] …`).
- **(B) Keep per-skill sandboxes that share a `LOCKDOWN[]` convention** — the LOCKDOWN flag array
  (`run.sh:22-31`: `--rm --network none --read-only --tmpfs … --cap-drop ALL --security-opt
  no-new-privileges --user 10001 --pids-limit --memory`) becomes a documented, copy-pasted *convention*;
  each skill keeps its own thin runner that applies it with its own mounts/DB/entrypoint.

**Weighing (the decision drivers).**

| Driver | (A) Shared lane | (B) Per-skill + shared LOCKDOWN[] |
|---|---|---|
| ADR-003 degrade (no docker → floor, `tool_assisted:false`) | identical — both detect docker and fall to the Read/Grep/Glob floor | identical |
| The ≥2-of-3 CONTAIN invariant | one place to get the invariant right → strongest single guarantee | invariant duplicated → drift risk (one skill weakens a flag) |
| "every tool has different mounts/DBs/entrypoints" | a shared wrapper must grow a parameter surface for each tool's mounts/entrypoint/DB | each runner is naturally shaped to its tool — no shared parameter bloat |
| Maintenance cost | one file to harden + audit; but a fatter, more abstract interface | N small files; but N places to re-verify when the lockdown bar moves (e.g. gVisor escalation, ADR-007 risk register) |
| Simplicity-first (Policy 2: no abstraction for single use; a port only when ≥2 tools implement it) | premature today — only deps-scan exists; abstracting for tools we have not wired is speculative | matches "stdlib-first floor + add the port when ≥2 callers exist" |
| Out-of-lane for self-edit (the LOCKDOWN is CONTROL/FROZEN, loop-leverage:140-147) | one frozen surface | the *convention* (a documented flag array) is the single source of truth even across N runners |

**RQ2 DECISION → (B) now, with a defined migration trigger to (A).** Keep containment **per-skill**, but
make the **`LOCKDOWN[]` flag array the single, named, FROZEN convention** every tool-exec runner MUST
apply verbatim. Reasons: (1) **Policy 2 / ADR-015** — a shared `_shared` *port* is justified only when
**≥2 tools** are actually wired through it; today only deps-scan runs inside the lane, so a generalized
wrapper is abstraction-for-single-use. (2) Every tool genuinely differs in mounts/DB/entrypoint, so the
real reuse is the **policy** (the flag set + the fetch/analyze split + the Rule-of-Two boundary), not the
plumbing — and a convention captures the policy without a fat parameter surface. (3) Drift is the only
real risk of (B), and it is mitigated by making LOCKDOWN[] a single documented array + a lint/test that
asserts each runner applies it (the impl ticket adds that drift-lock, mirroring `test_registry_lock.py`).

**Migration trigger to (A):** the moment a **second** capability (e.g. an SCA Grype runner) is wired to
run inside containment, extract the shared lane — at ≥2 real callers the port earns its keep (ADR-015's
"add a port when ≥2 tools implement it"). Impl ticket (a) is that second caller, so the lane extraction
is folded into it as the deliverable.

---

## RQ3 — The S8 auto-route bridge

**The gap (loop-leverage LBC-4, file-grounded).** The sandbox is **opt-in**, invoked by no inner-loop
skill or the agent; at a default review the deps-scan S8 signal **degrades to `[]`** and records
`malware-db` in `summary.tools_unavailable` (the `unavailable.add("malware-db")` site in
`supply_chain._build_doc`, the `scan()` result builder; moved by wave-1a/0871c4f). Activation today needs a
hand-passed `malware_db=load_malware_db(<osv>)`
into `scan()` (`SKILL.md:81-82`). So containment exists but is never *reached* in a normal run.

**Options.**
- **(A) default-when-safe** — when a pinned snapshot path is configured **AND** docker is reachable, the
  deps-scan stage **auto-routes** through `run.sh scan <target> <snapshot>` (S8 active, sealed); else fall
  back to S1–S7 + `tools_unavailable`.
- **(B) louder-opt-in** — stay opt-in, but surface the degrade **prominently** in the report (e.g.
  `tools_unavailable: ["malware-db"]` escalated to a visible "containment available but not engaged —
  run `./run.sh scan …`" advisory) so the user consciously opts in.

**Weighing.** Containment-by-default (A) is the strategy's whole thesis (security comes from containment,
not selection — strategy doc:190-197). But (A) **surprises the user with a `docker run`** they did not ask
for, and dev hosts often run a VM-based docker runtime that is **frequently not running**
(when the VM is down, only a dead `default` docker context is registered; the runtime context is
unregistered). A default that silently shells out to docker would either fail confusingly or run a
container the user did not expect. SKILL.md:81-82 frames S8 as an **explicit activation contract**, not an
ambient default — flipping that silently also contradicts ADR-007's "execution is opt-in, never default."

**RQ3 DECISION → (A) default-when-safe, GATED behind an explicit opt-in config key (so it is "default-on
*once the user has armed it*", never a surprise).** Concretely:

- **Config key:** `deps_scan.contain.auto_route` (default **`false`**) **+** `deps_scan.contain.snapshot_path`
  (the pinned OSSF `osv/` dir). Auto-route fires **only when BOTH**: `auto_route:true` AND a valid
  `snapshot_path` exists. This makes containment the default *behaviour* for any user who has armed it once,
  while a fresh/un-armed checkout never gets a surprise `docker run` (honours ADR-007 + SKILL.md:81-82).
- **Detection probe (deterministic, Policy 5 — code answers, no LLM):** `auto_route` true → probe docker
  reachability (`docker info` / context check, bounded timeout) AND `snapshot_path` validity (dir exists,
  contains `osv/`, optionally the `PINNED_SHA` matches the configured pin). **All green → route through
  `run.sh scan`**; any red → **fall back to S1–S7** and record `malware-db` in `tools_unavailable` with a
  reason (`docker-unreachable` / `snapshot-missing`) so the degrade is honest (ADR-003).
- **Fallback = the floor.** Never block, never reach the network outside the FETCH step. A degrade is a
  fully-valid result with `tool_assisted:false` for S8.

This is the smallest change that makes containment the steady state without violating "no surprising
execution": the user arms it once (config), and from then on every review runs S8 sealed when docker is
up, and degrades cleanly when it is not.

> **DEFERRED — start the docker runtime, then `./run.sh build && ./run.sh test` (expect ~102).**
> The lane's last build-verify was **67 passed / 1 deselected** on a VM-based docker runtime (README:85-88), which
> **predates wave-1a** — the deps-scan package is now **102 tests**, so the image must be REBUILT + re-run
> before the auto-route can be relied on. Docker may be **down on a dev host** (the VM runtime not
> running; only the `default` context exists). RQ3's **design** does not block on this; only the **live
> verification** does. This probe is impl ticket (a)'s gating prerequisite.

---

## RQ4 — The artifact-provenance admission arm (CONTAIN's admission control for TOOLS)

CONTAIN has two arms: **runtime confinement** (the lane, RQ1–RQ3) and **admission** — *which tool binary
is even allowed to enter the lane*. The admission arm operates on **artifacts the agent executes**:

- **Pin to an immutable ref, never a mutable tag.** Full **commit-SHA** (source Actions/repos),
  **image-digest** (`@sha256:…`), or **binary checksum** (released binaries). The strategy doc's force-push
  lesson (strategy doc:36 — trivy-action tags 76/77; tj-actions Mar-2025) proves a tag pin is defeated;
  only a SHA/digest holds (ADR-006).
- **VERIFY at admission, not generate-and-trust.** Check the **checksum/cosign/SLSA** signature *before
  first use*. This is the load-bearing correction from the Trivy scorecard (`…trivy_teampcp…:24-25,51`):
  `--skip-db-update` (offline) stops a **poisoned DB** but does **NOT** stop a **poisoned local binary** —
  so **binary checksum/signature-verify-at-install is the load-bearing control**. Generating provenance
  without verifying it is "security theater" (the Mini Shai-Hulud lesson: valid provenance still passed —
  so admission must verify *and* runtime must contain; neither alone suffices).

**This is a DIFFERENT mechanism from two others — three gates, three object kinds, NEVER merged:**

| Gate | Object kind | Mechanism | Owner |
|---|---|---|---|
| **Eval Gate-1** (keep-or-revert) | **KB / review-quality edits** | `score.py` metrics over the labeled corpus → KEEP/REVERT (deterministic, no LLM/RNG) | `evals/` (existing) |
| **Gate-2** (DATA gate) | **watchlist / registry DATA entries** | per-entry GHSA/OSV provenance URL + OSV-schema validity + regression-green (deterministic) | **wh-562** (its ADR) |
| **CONTAIN admission** (this RQ) | **TOOL artifacts the agent executes** | SHA/digest/binary-checksum pin + cosign/SLSA **verify at admission** | **wh-hxt.3 / ADR-024** |

Reusing Gate-1 to admit a tool, or folding tool-admission into Gate-2's DATA gate, would be a category
error (loop-leverage:117-135; the 2026-06-09 audit corrected the earlier "one mechanism" framing —
two object kinds, then this third). Cross-reference wh-562; do not merge.

**RQ4 DECISION — the two delegations (pick an owner for each, state it in the ADR):**
- **The ADR-015 "registry self-updates = design intent until wh-hxt.4 lands" clarification → CARRIED BY
  ADR-024.** Rationale: it is a statement about the *tooling* registry (ADR-015's surface), which is the
  CONTAIN/lifecycle strategy ADR's territory; wh-562 is about DATA-entry provenance, a different surface.
- **The ADR-021 "a tag-pin must resolve to a commit SHA" clarification → DELEGATED TO wh-562's Gate-2 ADR.**
  Rationale: ADR-021's pin lane and wh-562's per-entry provenance gate are the *same write-lane integrity
  surface*; keeping the tag→SHA supersession with the gate that enforces per-entry integrity is the more
  cohesive home. ADR-024 **cross-references** it (so exactly one ADR states it; the other points).

This split satisfies the contract's "exactly one of the two states it; cross-reference from the other"
(launch contract / ticket body).

---

## RQ5 — The hardened-CI checklist (and where it lives)

CONTAIN applied to the **CI surface** (distinct from the tool-exec lane). The checklist (all items grounded
in the strategy doc's CI-hardening section, strategy doc:71-75, + the 2026 primary sources cited there):

- [ ] **SHA-pin every GitHub Action to a full commit-SHA** (never a tag — trivy-action 76/77 + tj-actions
      were force-pushed; only a SHA holds; GitHub's SHA-pin allowed-actions policy 2025-08-15 backs this).
- [ ] **Minimal `GITHUB_TOKEN`** — `permissions: { contents: read }`, set **per-job**, least-privilege.
- [ ] **OIDC scope-pinned** — short-lived creds trusted only for an **immutable workflow file + a protected
      branch** (not just "this repo"), so a hijacked branch/workflow cannot mint a token.
- [ ] **Egress allowlist** (Harden-Runner **block mode**) — *the control that stopped Mini Shai-Hulud in
      flight* (strategy doc:34); deny-by-default network egress on the runner.
- [ ] **`--ignore-scripts`** on npm/pip install steps (`npm ci --ignore-scripts` / `.npmrc
      ignore-scripts=true` / pip `--no-build-isolation` care) — kills the preinstall/prepare delivery vector.
- [ ] **Ephemeral runners** — torn down per job; no implant persistence.
- [ ] **Atomic secret rotation** — rotate-then-revoke so a leaked secret has a bounded lifetime.
- [ ] *(EU CRA context — strategy doc:75)* reporting obligations land **2026-09-11**; SBOM mandatory
      (Syft/VEX feeds it). A compliance driver, not a control, but it dates the checklist's urgency.

**RQ5 DECISION → the checklist lives as a `docs/` reference file (a CI-hardening runbook), with ADR-024
carrying only the *policy statement* + a pointer; `ci/` files get the wiring later (NOT this wave).**
Rationale: (1) the checklist is **operational guidance that evolves** (new Actions, new advisories) — that
belongs in a living `docs/` runbook, not in append-only ADR prose (Policy 11 / ADR house style: the ADR
records the *decision*, the runbook records the *procedure*). (2) ADR-024 must stay tight (ADR-022/023
length budget) — embedding a maintained checklist would bloat it. (3) `ci/security-review.action.yml` +
`.github/workflows/ci.yml` are **read-only this wave** (file-ownership) — the actual wiring is impl ticket
(c). So: ADR-024 states "CI is a CONTAIN surface; hardening per the checklist runbook"; the runbook file is
created by impl ticket (c) alongside the wiring (this spike does not create `ci/` content or edit CI files).

---

## RQ6 — The reframe (→ ADR-024)

ADR-024 (appended to `docs/ARD.md`, the next-free number at write time — last written was ADR-023) states,
matching the house style of ADR-022/023:

1. **CONTAIN is the PRIMARY supply-chain control** (assume-breach / zero-trust tool execution).
2. **The 5-stage lifecycle is defense-in-depth UNDER it** — none survives an *undetected* compromise;
   CONTAIN does not depend on knowing what is bad (strategy doc:60-69).
3. **The ≥2-of-3 invariant is the registry rule** (`{network/egress · creds-in-env · host-write}`, ≥2
   absent at every tool exec).
4. **The lane decision (RQ2):** per-skill runners sharing a FROZEN `LOCKDOWN[]` convention now; extract a
   shared `_shared` lane at the second real caller.
5. **The bridge decision (RQ3):** S8 default-when-safe, armed by an explicit `auto_route` config key
   (default-on once armed; never a surprise docker run); deterministic probe; degrade to floor.
6. **The artifact-provenance admission arm (RQ4)** + the two delegations (ADR-015 self-updates clarification
   carried here; ADR-021 tag→SHA delegated to wh-562's Gate-2 ADR).
7. **The self-edit asymmetry:** CONTAIN enforcement code (hooks/sandbox/gate) is **out-of-lane** for the
   outer loop — `confine_self_writes` FROZEN/CONTROL basenames + default-deny put it beyond self-rewrite
   (loop-leverage:140-147). Improvements arrive as **human-PR'd, TDD'd, keep-or-revert-gated code diffs**,
   never KB text. Cite ADR-007 (opt-in sandboxed execution precedent) + ADR-016 (confinement =
   defense-in-depth, structural-baseline-first) as precedent; ADR-003 (degrade) + ADR-006 (pin) as the
   bindings. This asymmetry is identity preservation (Policy 5), not a defect.

**Status: accepted.**

---

## Decisions at a glance

| RQ | Decision (one line) |
|---|---|
| RQ1 | Three classes: pure-offline (gitleaks/Checkov-offline/Syft) drop into the lane; DB-backed (Grype/OSV-Scanner/OSSF) use the fetch/analyze split; native gates degrade to floor unless pre-seeded offline. |
| RQ2 | **(B) now → (A) at ≥2 callers:** per-skill runners sharing a FROZEN `LOCKDOWN[]` convention + a drift-lock test; extract the shared `_shared` lane when a second capability is wired (impl ticket a). |
| RQ3 | **Default-when-safe, armed by `deps_scan.contain.auto_route` (default false) + `snapshot_path`:** both-green deterministic probe (docker reachable + valid snapshot) → route through `run.sh scan`; any red → fall back to S1–S7 + `tools_unavailable`. Live verify DEFERRED. |
| RQ4 | CONTAIN admission = SHA/digest/binary-checksum pin + cosign/SLSA **verify-at-admission**; DISTINCT from Gate-1 (KB) and Gate-2 (DATA) — three gates, three object kinds. Delegations: ADR-015 self-updates → ADR-024; ADR-021 tag→SHA → wh-562. |
| RQ5 | Checklist lives in a **`docs/` CI-hardening runbook**; ADR-024 carries the policy + a pointer; `ci/` wiring is impl ticket (c) (CI files read-only this wave). |
| RQ6 | ADR-024 (accepted): CONTAIN primary; lifecycle = defense-in-depth; ≥2-of-3 invariant; the lane/bridge/admission decisions; the self-edit asymmetry (cite ADR-007/016 precedent, ADR-003/006 bindings). |

---

## Risk & open questions

- **R1 — Offline-DB flags unpinned (RQ1 honest limit).** The exact per-tool offline-DB CLI surface (Grype
  `db import`/`GRYPE_DB_*`, OSV-Scanner offline flag, native-gate local-DB modes) is not pinned from local
  evidence — only the architectural shape is. **Resolved by** impl ticket (a)'s one-tool live-verify on a
  daemon host. Until then, the matrix is correct in *shape* but a tool may need a config tweak to reach
  true offline.
- **R2 — Live build-verify is DEFERRED (RQ3).** The lane is not currently build-verified at the wave-1a
  102-test layout (image predates it; docker down on this host). The auto-route MUST NOT be relied upon in
  production until `./run.sh build && ./run.sh test` is green at ~102. Tracked as impl ticket (a)'s gate.
- **R3 — Convention drift (RQ2-B).** Per-skill runners can drift from the LOCKDOWN[] bar. **Mitigation:** a
  drift-lock test (mirroring `test_registry_lock.py`) asserting each runner applies the frozen flag set —
  part of impl ticket (a).
- **R4 — Auto-route surprise (RQ3).** Even gated behind a config key, a user who armed `auto_route` long
  ago might be surprised by a `docker run`. **Mitigation:** the report states clearly when S8 ran sealed
  vs degraded (the `tools_unavailable` reason string); the config defaults to false.
- **R5 — microVM ceiling (cite ADR-007 risk register).** The lane uses Docker (`--network none` + caps
  dropped); a kernel CVE remains a container→host escape vector (ADR-007 risk register, 2026 LPE wave). For
  *untrusted-code detonation* the ceiling is microVM — but the deps-scan floor is **inert by construction**
  (stdlib JSON+regex, no exec/network/subprocess — README:9-12), so Docker confinement is proportionate
  here. A future tool that *executes* untrusted code (not just parses it) must escalate toward gVisor/microVM
  per ADR-007 — flagged for whoever wires the first such tool.

---

## Draft impl tickets (for `/design-ticket`)

> Drafts only — **not** `bd create`d this wave (launch override #3). Each is self-contained for grooming.

### (a) Shared tool-exec lane + ONE-tool live-verify (Grype, offline + no-creds + sandboxed)
- **Type:** task (impl) · **Epic:** wh-hxt · **Blocks:** the auto-route bridge (b) relies on this lane.
- **Goal:** make the LOCKDOWN[] a single FROZEN convention with a drift-lock test; **build-verify the lane
  at the wave-1a layout** (`./run.sh build && ./run.sh test`, expect ~102); **live-verify Grype** running
  fully offline (pre-fetched DB via the fetch/analyze split), no creds in env, sealed (`--network none`,
  `:ro` DB mount). When a *second* runner (Grype) lands, **extract the shared `_shared` lane** (RQ2's
  migration trigger).
- **Files:** `docker/deps-scan-sandbox/run.sh` (the LOCKDOWN source-of-truth); a NEW Grype runner +
  fetch step under `docker/` (or the extracted `_shared` lane); a drift-lock test mirroring
  `_shared/scripts/tests/test_registry_lock.py`; `docs/research/poc-*` if the offline-DB path needs a PoC.
- **ACs:** `./run.sh build && ./run.sh test` green at ~102 on a daemon host (closes the DEFERRED probe) ·
  Grype runs offline against a pre-fetched DB with `--network none` + `:ro` mount, no creds, produces SCA
  output · the drift-lock test fails if any runner omits a LOCKDOWN flag · the exact Grype offline-DB flags
  are pinned (closes R1) · gate green.

### (b) The S8 auto-route bridge (default-when-safe, armed by config)
- **Type:** task (impl) · **Epic:** wh-hxt · **Blocked-by:** (a) (needs the verified lane).
- **Goal:** wire RQ3 — `deps_scan.contain.auto_route` (default false) + `snapshot_path`; a deterministic
  probe (docker reachable + valid snapshot, bounded timeout, no LLM — Policy 5); both-green → route the
  deps-scan stage through `run.sh scan <target> <snapshot>`; any red → fall back to S1–S7 + record
  `malware-db` in `tools_unavailable` with a reason. Preserve `SKILL.md:81-82`'s activation semantics as
  the un-armed default.
- **Files:** the deps-scan activation path (`supply_chain.py` around the `unavailable.add("malware-db")`
  degrade in `_build_doc`; the `scan()` entrypoint); `SKILL.md` (document the config key); tests under
  `deps-scan/scripts/tests/` (probe-green routes; probe-red degrades with the right reason; never raises).
- **ACs:** armed + docker-up + valid snapshot → S8 runs sealed (active) · armed + docker-down → degrades to
  S1–S7 with `tools_unavailable:["malware-db"]` + reason `docker-unreachable` · un-armed → unchanged
  opt-in behaviour (no surprise docker run) · probe is deterministic, never an LLM · gate green.

### (c) CI-hardening runbook + wire it into the CI surface
- **Type:** task (impl) · **Epic:** wh-hxt.
- **Goal:** create the **`docs/` CI-hardening runbook** (the RQ5 checklist) and **wire** the controls into
  `ci/security-review.action.yml` + `.github/workflows/ci.yml`: SHA-pin all Actions to full commit-SHAs,
  set per-job `permissions: contents: read`, scope-pin OIDC to an immutable workflow + protected branch,
  add a Harden-Runner egress allowlist (block mode), `--ignore-scripts` on install steps, ephemeral runners.
- **Files:** NEW `docs/<ci-hardening-runbook>.md`; `ci/security-review.action.yml`;
  `.github/workflows/ci.yml` (both edited HERE, not in the spike wave).
- **ACs:** every Action is SHA-pinned (no floating tags) · `GITHUB_TOKEN` is `contents:read` per-job ·
  OIDC trust is workflow+branch-scoped · egress is deny-by-default (allowlist) · install steps use
  `--ignore-scripts` · the runbook enumerates each control with its rationale + 2026 source · CI green.

### (d) *(optional)* Drift-lock the LOCKDOWN[] convention as a standalone guard
- **Type:** task (impl) · **Epic:** wh-hxt · *(fold into (a) unless it grows large)*.
- **Goal:** a dedicated test that enumerates every tool-exec runner and asserts it applies the full frozen
  LOCKDOWN[] flag set (no runner silently drops `--network none` / `--cap-drop ALL` / a `:ro` mount),
  mirroring `test_registry_lock.py`'s doc↔code drift-lock.
- **Files:** a test under `_shared/scripts/tests/` or `docker/`; reads the LOCKDOWN source-of-truth.
- **ACs:** the test fails if any runner omits a LOCKDOWN flag or adds egress/creds · runs in the per-PR
  CI tiers · gate green.
