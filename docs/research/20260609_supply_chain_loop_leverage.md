# Research + Handoff: can the self-improvement loops carry the supply-chain CONTAIN strategy?

**Date:** 2026-06-09 · **Author:** white-hacker · **Type:** research record + handoff
**Method:** background workflow `wst324yuh` — 6 read-only readers → synthesis → adversarial verification
(5/6 load-bearing claims CONFIRMED, 1 REFUTED + corrected).
**Status:** Research FINAL · Handoff LIVE (the work it points to is open).
**Companion docs:** `20260609_supply_chain_tooling_strategy.md` (the strategy this rides),
`20260609_trivy_teampcp_supply_chain.md`, `20260609_supply_chain_compromise_monitoring.md`.

---

## 0. What this document is, and how to use it

Two things in one file:

- **A research record** — a reproducible account of one question (*can white-hacker's existing inner/outer
  self-improvement loops carry the supply-chain CONTAIN strategy, or do we need new machinery?*): how we
  investigated it, what we found, the evidence, and what changed in our understanding. Read **Part I**.
- **A handoff** — enough live state and concrete next-actions to pick the work up cold: what's decided and
  committed, the ticket inventory and status, what's ready vs blocked, the open decisions that are *yours*,
  and where to start. Read **Part II**.

**Reading paths.** *"Give me the research"* → §1→§6. *"I'm continuing the work"* → §7 (state of play) →
§8 (work queue) → §9 (decisions) → §10 (resume here). The `file:line` index is the Appendix.

---
---

# PART I — RESEARCH

## 1. Research question + verdict

**Question.** The repo is built on two nested loops (ADR-001): an INNER review loop that *consumes* the
knowledge base, and an OUTER self-improvement loop (`/sec-learn` reflect + `/sec-kb-refresh` poll → propose
text diffs → eval keep/revert gate → human PR) that *edits* it. The diagram asserts *"tools are knowledge
too — the registry self-updates."* So: **does the supply-chain CONTAIN strategy already ride these loops,
or are we about to build parallel machinery?**

**Verdict: YES — leverage them, with wiring.** The loop *machinery* exists and is well-built (confined
write-lanes, a fail-closed eval gate, the Docker sandbox with a SHA-verified snapshot pin, deterministic
libs, the inner-loop SCAN-PLAN consumption chain). But **the supply-chain strategy is wired to the KB
only.** The work ahead is *wiring* — parsers, a second gate, a sandbox auto-route, a version-aware match —
and almost all of it **extends tickets that already exist**. We do not need to rebuild the loops.

## 2. Method, coverage & reproducibility

**Method.** A background workflow fanned out **6 read-only readers**, one per loop surface; a synthesis
agent produced the leverage map + gaps + load-bearing claims; then a parallel **adversarial-verify** pass
re-checked each load-bearing claim against `file:line`, defaulting to REFUTED on weak evidence.

**Reader coverage.**

| Reader | Surface | Outcome |
|---|---|---|
| outer-input | `sec-kb-refresh/` (poll → propose) | ✅ returned |
| outer-reflect | `sec-learn/` (reflect → propose) | ⚠️ **FAILED to return structured output** — see limit below |
| gate | `evals/keep_or_revert.py`, `score.py`, hooks, `lint_skill.py` | ✅ returned |
| data | KB + `tool-registry.md` + `malware_db.py` | ✅ returned |
| inner+contain | `detect_tools.py`, `supply_chain.py`, the sandbox | ✅ returned |
| design-intent | `ARCHITECTURE.md`, ADR-001/015/019, `CLAUDE.md` | ✅ returned |

**Known limit (carry forward).** The **`sec-learn` reader failed**; this doc's account of `/sec-learn`'s
scope is *inferred* (chiefly from `patch_merge.py:40` having no non-test caller), not directly audited.
**Verify `/sec-learn` first-hand before grooming the ADMIT-via-loop work (wh-hxt.4).**

**Reproducibility.** Re-run the audit with `Workflow({scriptPath:
".../workflows/scripts/leverage-self-improvement-loops-wf_2d830cb8-164.js", resumeFromRunId:
"wf_2d830cb8-164"})` (unchanged readers return cached; edited/new readers re-run). Every claim below is
checkable by reading the cited `file:line` (Appendix). No metric depends on an LLM or RNG.

## 3. Findings — the leverage map (per stage)

| Stage | Loop arm it rides | State | One-line gap |
|---|---|---|---|
| **CONTAIN** (primary) | INNER: egress hooks + deps-scan sandbox | **PARTIAL** | sandbox opt-in, not auto-routed; S8 degrades to `[]` at default review |
| **ADMIT** | OUTER reflect → tool-registry rows | **ASPIRATIONAL** | registry is prose; no registry-row writer; `patch_merge` wired to nothing |
| **PIN+VERIFY** | OUTER input → watchlist + ADR-006 pin | **PARTIAL** | snapshot pin *is* SHA-verified; per-entry GHSA/OSV verify + schema gate missing |
| **DIVERSIFY** | INNER: `SCANNER_PREFERENCE` + floor | **PARTIAL** (by design) | capability-not-brand built; defense-in-depth, not the answer |
| **MONITOR** | INNER `signal_s8` ← OUTER `/sec-kb-refresh` | **PARTIAL** | `/sec-kb-refresh` doesn't feed it; match is name-only; degraded-by-default |
| **RETIRE** | OUTER `staleness_check --archive` | **PARTIAL** | only ages out KB entries; no tool/watchlist retire path |
| **INNER consumption** | the SCAN-PLAN chain | **BUILT** | none — the gap is on PRODUCING + ACTIVATING, not consuming |

**CONTAIN** — built agent-level (`hooks.json` registers `guard_bash`+`confine_self_writes`;
`_egress_violation` blocks non-`FEED_HOSTS` egress while untrusted code is held; agent static-only
`white-hacker.md:79`). The real tool-exec boundary is the sandbox (`run.sh`: `--network none`, `--read-only`
+tmpfs, `--cap-drop ALL`, `--user 10001`, `no-new-privileges`, `--pids-limit 256`, `--memory 512m`,
`--rm`) — the lane wh-hxt.3 generalizes. **Gap:** opt-in (`README.md:3,8,19`); nothing auto-invokes it, so
S8 returns `[]` + records `malware-db` in `tools_unavailable` (`supply_chain.py:1122-1124`).

**ADMIT** — write-lane real + gated (`confine` ALLOW_SEGMENTS has `/_shared/reference/`; `gate_kb_edit`
needs `gate-verdict.json==KEEP`; `test_registry_lock` drift-locks doc↔`SCANNER_PREFERENCE`), but the
*proposal* is missing: `poll_feeds.py` renders KB markdown only; `patch_merge.py:40` is a generic `str→str`
merge with no registry caller; `tool-registry.md` is prose, not machine-readable fields.

**PIN+VERIFY** — see §5.1 (LBC-6): the snapshot pin **is** verified in code (`fetch-snapshot.sh:37`). The
real gap is **per-entry** provenance: `load_malware_db` (`malware_db.py:26-44`) never checks a GHSA/OSV
source, there's no watchlist-entry validator (cf. `validate_kb.py` for the KB), and the watchlist isn't in
the writable lane.

**DIVERSIFY** — `SCANNER_PREFERENCE` ordered per capability + degrade-to-floor (ADR-003/015) is BUILT.
Honest limit: it answers "pick another tool when one is pulled," **not** "is the replacement also
compromised" — that's CONTAIN's job. No code reorders preference on an advisory (that's ADMIT, aspirational).

**MONITOR** — watchlist is the highest-confidence signal (S8-ACTIVE verified 2026-06-09, wh-8qw) but
degraded-by-default and **name-only** (`supply_chain.py:754`) while version-aware `is_known_bad`
(`malware_db.py:47-52`) is dead code; and `/sec-kb-refresh` doesn't feed it (no OSSF parser/re-pin).

**RETIRE** — `staleness_check --archive` (`:26-30,50-52`) ages out **KB** entries only; no tool/watchlist
retire/supersede path.

**INNER consumption** — the most-built arm: registry as code (`SCANNER_PREFERENCE`), KB as
progressive-disclosure text the agent Reads, watchlist by code (`signal_s8`). The gap is on producing +
activating, not consuming.

## 4. Findings — the two architectural decisions

### 4.1 Supply-chain DATA needs a SECOND gate (Gate-2)

Two structurally different gates; the strategy needs the second, which doesn't exist.

- **Gate-1 — EVAL KEEP/REVERT (KB / review-quality edits).** `keep_or_revert.py` emits KEEP/REVERT/
  INCONCLUSIVE from `score.py` metrics over the labeled corpus (no LLM/RNG); `gate_kb_edit.py` blocks
  writes to `/ai-attack-kb/` + `/_shared/reference/` unless `gate-verdict.json==KEEP` — and that file is
  **absent on disk**, so the gate is **fail-closed** today. Works because a KB entry *contributes
  detections the corpus can score*.
- **Gate-2 — PRIMARY-SOURCE + SCHEMA + REGRESSION (watchlist/registry DATA — MISSING).** The eval gate
  **structurally cannot** score a DATA edit: `score.py:64-95` consumes only findings-vs-`label.json`; no
  corpus case measures "did adding compromised-package X help." So a poisoned/wrong-version entry can't be
  REVERTed on merit. The right gate is deterministic: **(a)** every entry cites a GHSA/OSV URL (+ the
  snapshot SHA already checks out via `fetch-snapshot.sh:37`); **(b)** OSV-JSON schema validity (mirroring
  `validate_kb.py`'s jsonschema gate); **(c)** `malware_db` unit tests green + version-aware predicate
  exercised.

> Same draft-PR + confinement + human-review wrapper for BOTH; only the inner verdict differs. **Reusing
> Gate-1 for a watchlist edit would be a false-merit merge.** Wiring the strategy onto the loop *requires*
> building Gate-2.

### 4.2 CONTAIN rides the loop differently — by design

The KB self-edits (text behind an interface). CONTAIN enforcement is CODE (hooks/sandbox/gate), and
`confine_self_writes` puts it **out-of-lane** for self-editing: FROZEN_BASENAMES (`:29`) + CONTROL_BASENAMES
(`:33-35`) get an early deny (`:69-76`); the hook bodies + `docker/` are caught by default-deny (`:77`)
because they're in no ALLOW_SEGMENT (`:40` = `/ai-attack-kb/`, `/_shared/reference/`, `/PATCHES/`,
`/evals/traces/`). So the agent **cannot self-rewrite its hooks/gate/sandbox**; CONTAIN improvements arrive
as **human-PR'd, TDD'd, keep-or-revert-gated code diffs**, never KB text. This asymmetry is identity
preservation (Rule 5), not a defect — "leverage the loop for CONTAIN" means the loop *proposes* sandbox/hook
changes through the normal code gate.

### 4.3 Rule-of-Two is preserved — and must stay so

Honored today and must remain when the watchlist arm is built: **(1)** no secrets co-located
(`sec-kb-refresh` has egress, holds no secrets; `guard_bash` blocks secret-reads/exfil); **(2)** advisories
parsed as *values* not structure (`safe_dump`; poisoned-feed-can't-inject test `test_poll_feeds.py:66-95`;
confidence 0.6, AUTO-EXTRACTED); **(3)** egress host-allow-listed (`FEED_HOSTS :41-46`, host-only check
`:119`); **(4)** the proposer emits only `{source-url, package, version, ecosystem, retrieved}` — never
advisory prose into the KB; **(5)** human reviews, never auto-merge; **(6)** keep the fetch(network-on) /
analyze(network-none) split (`fetch-snapshot.sh:2-6`). Residual: the hooks are heuristic Bash parsers ("a
tripwire, not the boundary", `:16-17`) — the real boundary is the sandbox.

## 5. Evidence — verified load-bearing claims

| ID | Claim | Verdict |
|---|---|---|
| LBC-1 | `signal_s8` matches **name-only**; `is_known_bad` is **dead code** → FPs on patched versions | **CONFIRMED** |
| LBC-2 | The eval gate **cannot** score a watchlist/registry edit; DATA needs a different gate; KB gate fail-closed (`gate-verdict.json` absent) | **CONFIRMED** |
| LBC-3 | `sec-kb-refresh` mints KB entries **only** — no OSSF parser, no watchlist re-pin, no registry writer; `supply-chain` isn't a valid KB class | **CONFIRMED** |
| LBC-4 | The Docker sandbox is **opt-in**, invoked by no inner-loop skill/agent; S8 degraded at default review | **CONFIRMED** |
| LBC-5 | CONTAIN code is **out-of-lane** for self-edit (FROZEN/CONTROL + default-deny) | **CONFIRMED** |
| LBC-6 | OSSF host not in allow-list **and** snapshot pin prose-only/unverified | **REFUTED — see §5.1** |

### 5.1 LBC-6 REFUTED — the correction to carry forward

The earlier claim is **false** on its operative points: **(1)** OSSF is served from `github.com`, which IS
in `FEED_HOSTS (:43)`, and the egress check is host-only (`:119`) — nothing missing. **(2)** The pin **is**
programmatically verified: `fetch-snapshot.sh:16` (40-hex SHA) → `:34` clone → `:36` checkout → `:37`
`git rev-parse HEAD == PIN || exit 1`; `MALWARE-DB.md:48` is the operator *record*. **(3)** Egress safety =
a deliberate fetch/analyze split, not "no pull wired"; `git` isn't a NET_VERB (`:51`), so the shell egress
gate is orthogonal to the clone. The one accurate sub-claim — `load_malware_db` doesn't verify a source —
is true but is a *pure offline loader by design*; per-entry verification is the **Gate-2** gap, and the
snapshot pin is already verified.

> **Carry-forward:** do **not** scope wh-562 as "add a snapshot checksum" (exists). Scope it as
> **per-entry GHSA/OSV provenance + OSV-schema validator + put the watchlist in the writable lane.**

## 6. Conclusions — what changed in our understanding

1. **The supply-chain lifecycle is not bespoke work — it's the outer loop applied to tooling.** Treat every
   gap as "wire the existing loop," not "build a system."
2. **"Self-updating registry" is currently aspirational, but the *gated write-lane* is real.** The missing
   piece is a deterministic *proposer* + a *DATA gate*, not new trust infrastructure.
3. **The eval gate is the wrong gate for DATA.** This was the non-obvious finding: a watchlist edit has no
   measurable corpus contribution, so it needs source-verification, not keep/revert. (Gate-2.)
4. **CONTAIN is leveraged differently from the KB** — through gated *code* PRs, by design.
5. **One earlier assumption was wrong** (LBC-6): the snapshot pin is already verified; refocus integrity
   work on *per-entry* provenance.

---
---

# PART II — HANDOFF

## 7. State of play (as of 2026-06-09)

**Decided + committed** (don't re-litigate):

- **CONTAIN (assume-breach / zero-trust tool execution) is the PRIMARY control**; the 5-stage lifecycle is
  defense-in-depth; DIVERSIFY is blast-radius, not prevention. (Strategy doc + epic body; commit `a28ba7d`.)
- **Swapping tools ≠ security** — research-backed (2026 sources in the strategy doc).
- **The loops CAN carry the strategy** — YES, with wiring (this doc).
- **Gate-2 is required**; **CONTAIN code is out-of-lane** for self-edit; **snapshot pin already verified**.

**Committed artifacts:**

| Commit | What |
|---|---|
| `a28ba7d` | CONTAIN made primary (strategy doc CONTAIN section + epic reframed to P1 + wh-hxt.3 created) |
| `d2d6e85` | "Riding the self-improvement loops" section in the strategy doc + notes on wh-5es/wh-562/wh-hxt.3 |
| `8de5a2e` → *(this rewrite)* | this research + handoff doc |

`main` is up to date with origin; bd dolt synced.

**Ticket inventory** (epic **wh-hxt** = P1, OPEN, 8 children, 0% complete):

| Ticket | Pri | Status | Role | This audit's input |
|---|---|---|---|---|
| **wh-4k9** | P1 | **READY** (groomed) | version-aware S8 (the FP-bomb fix) | G3 — confirmed; smallest win |
| wh-hxt.3 | P1 | open · *note added* | CONTAIN spike (ADR + sandbox lane + CI checklist) | G4 — add the sandbox auto-route bridge |
| wh-562 | P1 | **blocked by wh-hxt.3** · *note added* | integrity gate / PIN+VERIFY | G2 — re-scope to **Gate-2** (per §5.1) |
| wh-5es | P2 | open · *note added* | continuous MONITOR | G1 — the `/sec-kb-refresh`→watchlist feeder |
| wh-k6l | P1 | **blocked by wh-4k9** | extensible OSV watchlist (the DATA) | G2 — the DATA Gate-2 validates |
| wh-hxt.1 | P3 | open | maintenance/staleness | G6 — extend RETIRE to tools/watchlist |
| wh-hxt.2 | P3 | open | lifecycle ADR + retire/replace runbook + diversity policy | ⚠ ADR overlap with wh-hxt.3 — see §9 |
| wh-d5b | P1 | open | interim Trivy quarantine | (tactical, not a loop-wiring gap) |
| wh-nvk | P2 | open | Trivy-replacement set | (DIVERSIFY instantiation) |
| wh-xn0 | P2 | open | tool admissibility (license/egress gates) | (ADMIT gates) |
| wh-q86 | P2 | open | KB entry AISEC-SUPPLY-CHAIN-002 | (KB, not loop-wiring) |
| **wh-hxt.4** | P2 | **NOT CREATED** (proposed) | ADMIT-via-loop (registry-row writer) | G5 — create it (§8) |

> wh-4k9 / wh-k6l / wh-q86 are the tactical supply-chain hot-path (Wave 1a in `.notes/order.md`), *related*
> to but **not children of** the epic. The epic holds the strategic lifecycle children.

## 8. Work queue — the gaps as ticket actions

The six gaps (G1–G6, full table in §3 of the strategy doc / restated here) map to ticket actions. **Reuse >
create:** five extend existing tickets, one is new.

| Gap | Sev | Action | Ticket |
|---|---|---|---|
| **G3** name-only S8 / dead `is_known_bad` | P1 | `signal_s8` calls `is_known_bad(name, version, db)`; extract lockfile-resolved version first (adapters emit `spec`, not `version`); update the 2 tests pinning old behavior | **wh-4k9** (ready) |
| **G2** no Gate-2 for DATA | P0 | deterministic validator: OSV-schema + required GHSA/OSV URL per entry; put watchlist in the write-lane under a `gate_kb_edit`-analogue | **wh-562** (re-scope) + **wh-k6l** (the DATA) |
| **G1** `sec-kb-refresh` doesn't feed watchlist | P0 | OSSF parser in `poll_feeds.py` PARSERS + a `{source-url,package,version,ecosystem,retrieved}` candidate writer (draft PR, `safe_dump`) | **wh-5es** |
| **G4** sandbox opt-in, not auto-routed | P1 | capability-gated bridge: snapshot+docker present → route deps-scan through `run.sh`; else S1–S7 + `tools_unavailable`. PREREQ: build-verify `run.sh` | **wh-hxt.3** |
| **G5** ADMIT-via-loop aspirational | P2 | machine-readable registry sidecar (pin/digest/compromise-status) + registry-row writer via `patch_merge` behind `confine`+`gate_kb_edit`; add `supply-chain` to VALID_CLASSES | **wh-hxt.4** (CREATE) |
| **G6** RETIRE KB-only | P3 | staleness signal → MONITOR for tools + a watchlist-supersede path | **wh-hxt.1** |

**Suggested sequence** (rationale: clear the FP-bomb first so the watchlist is usable; do the schema before
the feeder; turn CONTAIN on by default; then the aspirational arm):

1. **wh-4k9** — small, ready, confirmed; removes the FP bomb that makes the watchlist unusable.
2. **wh-hxt.3** — ratify the CONTAIN ADR + the sandbox auto-route design; **unblocks wh-562**.
3. **wh-562 (Gate-2)** + **wh-5es (feeder)** — the P0 pair; do Gate-2's schema first so the feeder writes
   valid entries. Coordinate the ONE watchlist schema across wh-562 / wh-5es / wh-k6l.
4. **wh-k6l** — seed the watchlist DATA (unblocked once wh-4k9 lands).
5. **wh-hxt.4** — ADMIT-via-loop (after verifying `/sec-learn` first-hand, §2 limit).
6. **wh-hxt.1** — RETIRE-for-tools.

## 9. Open decisions (yours to make before/at grooming)

1. **Gate-2's home** — in `deps-scan/scripts/` (next to `malware_db.py`) or in `_shared/` as a reusable
   DATA-gate? Ties to the "one watchlist" reconciliation across wh-562 / wh-5es / wh-k6l.
2. **Sandbox auto-route default** — S8 "default-when-safe" (snapshot+docker present) vs. stay opt-in with a
   louder `tools_unavailable`. Containment-by-default vs. surprising the user with a Docker run. (wh-hxt.3.)
3. **One ADR or two?** — wh-hxt.3 ratifies *CONTAIN-as-primary*; wh-hxt.2 codifies *the lifecycle +
   retire/replace runbook + diversity policy*. Decide if these are one strategy ADR or two; avoid two
   tickets each "appending an ADR" colliding on the next-free number.
3b. **`/sec-learn` scope is UNAUDITED** (§2 limit) — confirm what traces it reflects on and whether it can
   target `tool-registry.md` **before** committing wh-hxt.4's design.
4. **CI-hardening checklist home** — the wh-hxt.3 CI guidance (SHA-pin Actions, minimal token, OIDC scope,
   egress allowlist, `--ignore-scripts`) lives in `ci/` docs or as ADR content? It's the CONTAIN layer for
   the *CI* surface, distinct from the tool-exec sandbox.

## 10. Resume here (next session, cold-start)

1. **Load context:** this doc (§7→§8→§9), then `20260609_supply_chain_tooling_strategy.md` (the "Riding the
   self-improvement loops" section), then `bd show wh-hxt` + the notes on wh-5es / wh-562 / wh-hxt.3.
2. **First concrete action — pick one:**
   - *Ship a quick win:* `/groom wh-4k9` → implement the version-aware S8 fix (smallest, confirmed, ready).
   - *Set the foundation:* `/groom wh-hxt.3` → ratify the CONTAIN ADR + design the sandbox auto-route
     (unblocks wh-562 and the whole P0 pair).
   - *Create the missing ticket:* `/design-ticket --epic=wh-hxt --type=spike` for **wh-hxt.4** (ADMIT-via-loop)
     using §8/G5 as the scope — but resolve decision §9.3b (`/sec-learn` audit) first.
3. **Before any DATA-gate work:** re-read §5.1 so the integrity scope is *per-entry provenance*, not a
   snapshot checksum.

---

## Appendix — file:line index

- **Outer-input:** `sec-kb-refresh/scripts/poll_feeds.py` (`:23` VALID_CLASSES, `:69` PARSERS, `:82-107`
  render, `:84` class-assert); `sec-kb-refresh/SKILL.md:34-37`; `test_poll_feeds.py:66-95`.
- **Outer-reflect:** `sec-learn/scripts/patch_merge.py:40`; `staleness_check.py:26-30,50-52`. *(scope
  otherwise unaudited — §2.)*
- **The gate:** `evals/score.py:64-95`; `evals/keep_or_revert.py:14-15,33-50`;
  `plugins/white-hacker/hooks/gate_kb_edit.py:18,40-49,58-61`; `evals/gate-verdict.json` (absent → fail
  closed); `ai-attack-kb/scripts/validate_kb.py` (provenance gate).
- **Confinement:** `plugins/white-hacker/hooks/confine_self_writes.py` (`:16-17` tripwire, `:29` FROZEN,
  `:33-35` CONTROL, `:40` ALLOW_SEGMENTS, `:41-46` FEED_HOSTS, `:51` NET_VERBS, `:69-77` deny, `:111-122`
  egress, `:119` host-only); `test_confine_self_writes.py`.
- **Data:** `_shared/reference/tool-registry.md:1,7,50-55`; `deps-scan/scripts/malware_db.py:26-44`
  (loader), `:47-52` (`is_known_bad`, dead), `:78-84` (DB shape); `deps-scan/reference/MALWARE-DB.md:48,79`.
- **Inner + CONTAIN:** `sec-detect/scripts/detect_tools.py` (`SCANNER_PREFERENCE`, `build_scan_plan`);
  `deps-scan/scripts/supply_chain.py:744-756,975,995-996,1122-1124`; `deps-scan/SKILL.md:80-82,110`;
  `docker/deps-scan-sandbox/run.sh`, `fetch-snapshot.sh:2-6,16,34,36,37`, `README.md:3,8,19,49-50,87-88`.
- **Design intent:** ADR-001 / ADR-015 / ADR-019 (`docs/ARD.md`); `docs/ARCHITECTURE.md:318-322`;
  `.claude/CLAUDE.md`.
- **Workflow run:** `wst324yuh` / `wf_2d830cb8-164` (this audit).
