# Research: Riding the self-improvement loops for the supply-chain CONTAIN strategy

**Date:** 2026-06-09
**Author:** white-hacker (loop-leverage audit)
**Method:** background workflow `wst324yuh` — 6 read-only readers → synthesis → adversarial verification
(5/6 load-bearing claims CONFIRMED, 1 REFUTED + corrected).
**Related:** epic **wh-hxt** (supply-chain lifecycle); children wh-hxt.3 (CONTAIN), wh-562 (PIN+VERIFY),
wh-5es (MONITOR), wh-nvk (DIVERSIFY), wh-xn0 (ADMIT), wh-d5b (RETIRE), wh-hxt.1 (staleness), wh-4k9 +
wh-k6l (watchlist machinery). Strategy: `docs/research/20260609_supply_chain_tooling_strategy.md`.
**Status:** FINAL (audit). The ticket-action section below is the input for a grooming/creation pass.

---

## 0. How to use this doc

This is a **handoff map**, not a plan to execute as-is. It answers one question — *can white-hacker's
existing inner/outer self-improvement loops carry the supply-chain CONTAIN strategy, or do we need new
machinery?* — with file-grounded evidence, so you can step back and (a) refine the existing tickets with
accurate scope, (b) create the few genuinely-new tickets, and (c) sequence them.

Read §1 (verdict) → §2 (leverage map) → §3 (the two architectural decisions) → §5 (gaps) → **§6 (ticket
actions — the part you act on)**. §4 (verified claims) and §7 (file:line index) are the evidence appendix.

---

## 1. Verdict — YES, with wiring

The loop **machinery all exists and is well-built**; the supply-chain strategy is wired to the **KB only**.

- **Outer loop** (`/sec-kb-refresh` poll → `/sec-learn` reflect → propose text diffs → eval keep/revert
  gate → human PR) is real and mints **KB technique entries**. It does **not** feed the watchlist, the
  tool-registry, or the snapshot re-pin — even though the deps-scan docs *name* `/sec-kb-refresh` as the
  re-pin cadence.
- **Inner loop** consumption (a review reads KB + registry + watchlist) is the **most-built** arm.
- **CONTAIN** (PreToolUse egress hooks + the deps-scan Docker sandbox) is **built but opt-in** — not
  auto-routed into a default review, so the strongest tool-exec containment is silently off by default.

So we **leverage the loops, we don't rebuild them**. The work is *wiring* (parsers, a second gate, a
sandbox auto-route, a version-aware match), almost all of which **extends tickets that already exist**.

---

## 2. The leverage map (per stage)

| Stage | Loop arm it rides | State | One-line gap |
|---|---|---|---|
| **CONTAIN** (primary) | INNER: egress hooks + deps-scan sandbox | **PARTIAL** | sandbox is opt-in, not auto-routed; S8 degrades to `[]` at default review |
| **ADMIT** | OUTER reflect → tool-registry rows | **ASPIRATIONAL** | registry is prose; no registry-row writer; `patch_merge` wired to nothing |
| **PIN+VERIFY** | OUTER input → watchlist + ADR-006 pin | **PARTIAL** | snapshot pin *is* SHA-verified; per-entry GHSA/OSV verify + schema gate missing |
| **DIVERSIFY** | INNER: `SCANNER_PREFERENCE` + floor | **PARTIAL** (by design) | capability-not-brand built; it's defense-in-depth, not the answer |
| **MONITOR** | INNER `signal_s8` ← OUTER `/sec-kb-refresh` | **PARTIAL** | `/sec-kb-refresh` doesn't feed it; match is name-only; degraded-by-default |
| **RETIRE** | OUTER `staleness_check --archive` | **PARTIAL** | only ages out KB entries; no tool/watchlist retire path |
| **INNER consumption** | the SCAN-PLAN chain | **BUILT** | none — the gap is on PRODUCING + ACTIVATING, not consuming |

### 2.1 CONTAIN — built agent-level, opt-in at tool-exec
- **Built + wired every review:** `hooks.json` registers `guard_bash` + `confine_self_writes`;
  `_egress_violation` blocks egress to any non-`FEED_HOSTS` host while untrusted code is held; the agent
  is static-only (`white-hacker.md:79`).
- **The real tool-exec boundary** is the Docker sandbox (`docker/deps-scan-sandbox/run.sh`: `--network
  none`, `--read-only` + tmpfs, `--cap-drop ALL`, `--user 10001`, `no-new-privileges`, `--pids-limit 256`,
  `--memory 512m`, `--rm`). This **is** the lane wh-hxt.3 wants to generalize.
- **Gap:** the sandbox is **opt-in** (`README.md:3,8,19`). No inner-loop skill and not the agent invokes
  `run.sh`, so at default review time the strongest containment is off; `signal_s8` returns `[]` and
  `supply_chain.py:1122-1124` records `malware-db` in `tools_unavailable`.

### 2.2 ADMIT — aspirational in code
- **Design intent** (ADR-015; `tool-registry.md:1,7`; `ARCHITECTURE.md:318-322`): new tools self-admit as
  dated, gated diffs the same way KB techniques do.
- **The write-lane is real + gated:** `confine_self_writes` ALLOW_SEGMENTS includes `/_shared/reference/`;
  `gate_kb_edit` blocks the registry write unless `gate-verdict.json == KEEP`; `test_registry_lock`
  drift-locks the doc against `SCANNER_PREFERENCE`.
- **The automated proposal is missing:** `poll_feeds.py` renders KB markdown only (no tool-extraction /
  registry-row writer); `sec-learn`'s `patch_merge.py:40` is a generic `str→str` section-merge with no
  caller pointed at `tool-registry.md`. So ADMIT-via-loop today is the LLM step (harness+context) with no
  deterministic script behind it. **`tool-registry.md` is also prose**, not machine-readable fields.

### 2.3 PIN+VERIFY — snapshot verified; per-entry verify missing
- **Corrected finding (see §4, LBC-6):** the OSSF snapshot pin **is** verified in code —
  `fetch-snapshot.sh:16` enforces a 40-hex SHA, `:34` clones, `:36` checks out the pin, `:37` runs
  `git rev-parse HEAD == PIN || exit 1`. `MALWARE-DB.md:48` (SHA `174a862b…`) is the operator *record* of
  that pin, not the verification itself.
- **What's actually missing:** (a) **per-entry** primary-source verification — `malware_db.py:26-44`
  `load_malware_db` is a pure offline disk loader and never checks an entry against a GHSA/OSV source;
  (b) `validate_kb.py` enforces provenance for KB entries but there is **no equivalent validator for a
  watchlist entry**; (c) the deps-scan watchlist path is **not** in `confine_self_writes` ALLOW_SEGMENTS,
  so the outer loop cannot even write it.

### 2.4 DIVERSIFY — built, but it is defense-in-depth
- **Built:** `detect_tools.py` `SCANNER_PREFERENCE` is an ordered per-capability list; `build_scan_plan`
  picks the first installed + language-serving tool and records `degraded[]` + `tools_unavailable`; the
  Read/Grep/Glob floor always works with zero tools (ADR-003/015).
- **Honest limit:** the epic itself notes tool diversity is cited as the fix in *zero* 2026 postmortems —
  it rides the loop as "pick a different tool when one is pulled" but does **not** answer "is the
  replacement also compromised." That is CONTAIN's job. **No code reorders preference in response to a
  compromise advisory** (that would be an ADMIT/registry self-update, still aspirational).

### 2.5 MONITOR — real but manual, name-only
- The watchlist is the highest-confidence supply-chain signal and was verified S8-ACTIVE against a real
  malicious package on 2026-06-09 (wh-8qw).
- **Degraded-by-default:** with no snapshot passed, `signal_s8` returns `[]` and records `malware-db` in
  `tools_unavailable`; activation requires an operator to hand-pass `malware_db=load_malware_db(...)` or
  run the sandbox (`deps-scan SKILL.md:80-82`).
- **Two concrete defects:** (a) `signal_s8` matches **name-only** (`supply_chain.py:754`
  `if d["name"] in malware_db`) while the version-aware `is_known_bad` (`malware_db.py:47-52`) is **dead
  code** (zero production callers) — a known-bad package at a patched version still fires S8 (the FP bomb,
  wh-4k9); (b) the outer input arm doesn't feed it (`sec-kb-refresh` has no OSSF parser / re-pin).

### 2.6 RETIRE — KB only
- `staleness_check.py:26-30,50-52` `--archive` `shutil.move`s a stale **KB** entry to `archive/` — opt-in,
  operator-run, ages-out only; never adds/edits/reclassifies, and operates on the KB, **not** the
  tool-registry or watchlist. No codepath retires a compromised tool from `SCANNER_PREFERENCE`, nor
  removes/supersedes a watchlist entry. Lowest-leverage, least-wired stage.

### 2.7 INNER consumption — the most-built arm
- Registry consumed **as code** (`SCANNER_PREFERENCE` drives tool selection); KB consumed **as
  progressive-disclosure text** (no script parses `ai-attack-kb/*`; the agent Reads it); S4/S5 AI-SDK
  allowlist consumed by code; watchlist consumed by code (`signal_s8`, but name-only/degraded). The
  leverage gap is entirely on the **producing** (outer) and **activating** (sandbox auto-route +
  version-aware match) sides, not on consumption.

---

## 3. The two architectural decisions (the load-bearing insights)

### 3.1 Supply-chain DATA needs a SECOND gate (Gate-2)

There are **two structurally different gates**, and the strategy needs the second one, which doesn't exist.

- **Gate-1 — EVAL KEEP/REVERT (governs KB / review-quality edits).** `evals/keep_or_revert.py` emits an
  asymmetric KEEP/REVERT/INCONCLUSIVE verdict from `score.py` metrics (Youden's J, recall, FPR,
  sev-weighted recall, precision) over the labeled corpus, no LLM / no RNG (FROZEN). `gate_kb_edit.py`
  then blocks any in-session write to `/ai-attack-kb/` or `/_shared/reference/` unless
  `evals/gate-verdict.json == KEEP` — and that file is **absent on disk**, so the hook is **fail-closed**
  (all such edits blocked by default). This gate works because a KB technique entry *contributes
  detections the corpus can score*: "did adding it raise recall without raising FPR?" is measurable.
- **Gate-2 — PRIMARY-SOURCE + SCHEMA + REGRESSION (governs watchlist / registry DATA — MISSING).** The
  eval gate **structurally cannot** score a watchlist/registry edit: `score.py:64-95` consumes only
  findings-vs-`label.json`, and **no corpus case** measures "did adding compromised-package X help." So a
  poisoned or wrong-version entry cannot be REVERTed on merit. The correct gate for DATA is deterministic
  and source-based: **(a)** every entry cites a GHSA/OSV advisory URL (+ the snapshot SHA passes its
  checksum — already enforced by `fetch-snapshot.sh:37`); **(b)** the entry validates as **OSV JSON**
  against a pinned schema (mirroring `validate_kb.py`'s jsonschema gate); **(c)** the existing
  `malware_db` unit tests stay green and the version-aware predicate is exercised.

> **The same draft-PR + confinement + human-review wrapper applies to BOTH gates; only the inner verdict
> differs.** Gate-1 = "did review quality measurably improve" (eval). Gate-2 = "is this datum
> provenance-verified, schema-valid, regression-clean" (deterministic source check). **Reusing Gate-1 for
> a watchlist edit would be a false-merit merge.** Wiring the strategy onto the loop *requires* building
> Gate-2.

### 3.2 CONTAIN rides the loop differently — by design

The KB self-edits (text behind an interface). **CONTAIN enforcement is CODE** (hooks / sandbox / gate),
and `confine_self_writes` puts it **out-of-lane** for self-editing:

- `confine_self_writes.py:29` FROZEN_BASENAMES = `{keep_or_revert.py, baseline.json, score.py,
  label-schema.json}`; `:33-35` CONTROL_BASENAMES = `{settings.json, settings.local.json, hooks.json,
  plugin.json, marketplace.json}` → explicit early deny at `:69-76`.
- The hook bodies themselves (`confine_self_writes.py`, `guard_bash.py`, `gate_kb_edit.py`) and `docker/`
  are caught by the **default-deny** at `:77` (they're not in any ALLOW_SEGMENT — `:40` =
  `/ai-attack-kb/`, `/_shared/reference/`, `/PATCHES/`, `/evals/traces/`).

So the agent **cannot self-rewrite its own hooks / gate / sandbox**. CONTAIN improvements arrive as
**human-PR'd, TDD'd, keep-or-revert-gated code diffs**, never as KB text. The outer loop *proposes*; it
cannot self-edit the boundary. **This asymmetry is identity preservation (Rule 5), not a defect** — and it
means "leverage the loop for CONTAIN" = "the loop *proposes* sandbox/hook improvements through the normal
code-change gate," not "the loop edits CONTAIN like it edits the KB."

### 3.3 Rule-of-Two is preserved — and must stay so when the watchlist arm is added

The Agents Rule of Two (never simultaneously hold untrusted input + secrets + egress) is honored today and
must be preserved verbatim when the watchlist/registry output lanes are built:

1. **No secrets co-located** — `sec-kb-refresh` has egress to feeds but holds no working-tree secrets;
   `guard_bash` blocks secret-file reads + exfil egress.
2. **Advisories are untrusted / injection-carrying** — feed text is parsed as a *value*, never structure:
   `safe_dump` + a test that a poisoned feed cannot inject a top-level YAML key
   (`test_poll_feeds.py:66-95`); confidence starts low (0.6); items flagged AUTO-EXTRACTED.
3. **Egress is host-allow-listed** — `confine_self_writes` FEED_HOSTS (`:41-46`) + `_egress_violation`
   (`:111-122`, host-only at `:119`) deny any non-feed host. **The OSSF host is reachable today** because
   `ossf/malicious-packages` is served from `github.com`, which is in FEED_HOSTS, and `git` is **not** in
   NET_VERBS (`:51`), so a `git clone` isn't gated as egress.
4. **The proposer must emit only minimal structured data** — for a watchlist/registry candidate, emit
   ONLY `{source-url (GHSA/OSV), package, version, ecosystem, retrieved}`, never free-form advisory prose
   that could carry instructions into the agent's own KB.
5. **Human reviews** — never auto-merge; every candidate is a dated draft PR (Apply / Edit / Skip).
6. **Keep fetch/analyze split** — `fetch-snapshot.sh:2-6` fetch is network-ON with no untrusted analysis,
   in a throwaway hardened container; analyze (`run.sh scan`) runs `--network none`. Never analyze
   untrusted snapshot content with egress live.

**Residual:** the PreToolUse hooks are heuristic Bash parsers ("a tripwire, not the boundary",
`confine_self_writes.py:16-17`) — the real boundary for execution is the Docker sandbox.

---

## 4. Verified load-bearing claims (evidence appendix)

Six claims the analysis depends on, each adversarially re-checked against `file:line`.

| ID | Claim | Verdict |
|---|---|---|
| LBC-1 | `signal_s8` matches **name-only**; `is_known_bad` is **dead code** → FPs on patched versions | **CONFIRMED** |
| LBC-2 | The eval gate **cannot** score a watchlist/registry edit; DATA needs a different gate; KB gate is fail-closed (`gate-verdict.json` absent) | **CONFIRMED** |
| LBC-3 | `sec-kb-refresh` mints KB entries **only** — no OSSF parser, no watchlist re-pin, no registry writer; `supply-chain` isn't a valid KB class | **CONFIRMED** |
| LBC-4 | The Docker CONTAIN sandbox is **opt-in**, invoked by no inner-loop skill/agent; S8 degraded at default review | **CONFIRMED** |
| LBC-5 | CONTAIN code is **out-of-lane** for self-edit (FROZEN/CONTROL + default-deny); improvements via human-PR'd TDD diffs | **CONFIRMED** |
| LBC-6 | OSSF host not in egress allow-list **and** snapshot pin is prose-only / unverified | **REFUTED** — see below |

### 4.1 LBC-6 — REFUTED (the correction to carry forward)

The earlier claim "the OSSF host is missing from the allow-list and the pin is prose-only with no
checksum" is **false on its operative assertions**:

1. **OSSF host is reachable.** `ossf/malicious-packages` is hosted at `github.com`, which IS in FEED_HOSTS
   (`confine_self_writes.py:43`); the egress check extracts host-only (`:119`), never the path. There is
   no separate "OSSF host" to be missing.
2. **The pin IS programmatically verified.** `fetch-snapshot.sh:16` (40-hex SHA), `:34` (`git clone`),
   `:36` (`git checkout PIN`), `:37` (`git rev-parse HEAD == PIN || exit 1`). The `MALWARE-DB.md:48` SHA
   is the operator record of a pin the script enforces.
3. **Egress safety = deliberate split, not "no pull wired."** Fetch is network-ON with no analysis in a
   hardened throwaway container; analyze runs `--network none`. `git` is not a NET_VERB, so the agent-shell
   egress gate is orthogonal to the clone.

The **one accurate sub-claim**: `load_malware_db` (`malware_db.py:26-44`) never verifies an entry against a
primary source — true, but it's a *pure offline disk loader by design*; per-entry/source verification is
the **Gate-2** gap (§3.1), and snapshot-pin verification already lives in `fetch-snapshot.sh:37`.

> **Carry-forward correction:** do **not** scope wh-562 as "add a snapshot checksum" — that exists. Scope
> it as "add **per-entry** GHSA/OSV provenance verification + an OSV-schema validator + bring the watchlist
> into the writable lane."

### 4.2 LBC-5 precision note

Two deny paths, same net effect: FROZEN/CONTROL basenames get an *explicit early deny* (`:69-76`); the
hook `.py` bodies + `docker/` are denied by the *default-deny* (`:77`) because they're in no ALLOW_SEGMENT.
File is `plugins/white-hacker/hooks/confine_self_writes.py` (not `_shared/hooks/`).

---

## 5. Gaps (ranked, file-grounded)

| # | Gap | Sev | Fix | Evidence |
|---|---|---|---|---|
| G1 | `sec-kb-refresh` doesn't feed the MONITOR watchlist (no OSSF parser / re-pin), yet docs name it as the cadence | **P0** | Add an OSSF-malicious-packages parser to `poll_feeds.py` PARSERS + a `{source-url,package,version,ecosystem}` candidate writer (draft PR, `safe_dump`) | `poll_feeds.py:69,23,82-107`; `MALWARE-DB.md:48,79`; `deps-scan SKILL.md:110` |
| G2 | No Gate-2 for watchlist/registry DATA (eval can't score it; no per-entry provenance validator; watchlist not in write-lane) | **P0** | Deterministic validator mirroring `validate_kb.py`: OSV-schema + required GHSA/OSV URL per entry; add watchlist to ALLOW_SEGMENTS under a `gate_kb_edit`-analogue | `score.py:64-95`; `malware_db.py:26-44`; `confine_self_writes.py:40`; `gate-verdict.json` absent |
| G3 | `signal_s8` name-only; `is_known_bad` dead code → FP bomb | **P1** | `signal_s8` calls `is_known_bad(name, version, db)`; extract lockfile-resolved version first (adapters emit `spec`, not `version`) | `supply_chain.py:754`; `malware_db.py:47-52` |
| G4 | Docker sandbox opt-in, not auto-routed → S8 off by default | **P1** | Capability-gated bridge: snapshot path configured + docker available → route deps-scan through `run.sh`; else S1–S7 + `tools_unavailable` | `README.md:8,19`; `supply_chain.py:1122-1124`; `SKILL.md:82` |
| G5 | ADMIT-via-loop aspirational: registry is prose; no registry-row writer; `patch_merge` wired to nothing | **P2** | Machine-readable registry sidecar (pin/digest/compromise-status) + a registry-row writer driven by `patch_merge`, behind `confine`+`gate_kb_edit`; add `supply-chain` to VALID_CLASSES | `poll_feeds.py:82-107`; `SKILL.md:34-37`; `patch_merge.py:40`; `tool-registry.md:50-55` |
| G6 | RETIRE has no tool/watchlist codepath (`--archive` is KB-only) | **P3** | Staleness signal into MONITOR for tools (cadence/EOL on ADMIT) + a watchlist-supersede path | `staleness_check.py:26-30,50-52` |

---

## 6. Ticket actions (the part to act on)

### 6.1 Extend existing tickets (reuse > create)

> Notes already appended to wh-5es / wh-562 / wh-hxt.3 on 2026-06-09 (`bd show <id>` → NOTES). Refine the
> descriptions/ACs from those + this doc.

- **wh-5es (MONITOR spike)** ← **G1.** Make its continuous-watchlist-refresh codepath concrete: the OSSF
  parser + the minimal-field candidate writer + the draft-PR gate. AC should pin: emits only
  `{source-url,package,version,ecosystem,retrieved}`; no free-form advisory prose; `safe_dump`; OSSF pull
  keeps the fetch/analyze split. Reconcile the ONE watchlist/format with wh-562 + wh-k6l.
- **wh-562 (integrity gate spike)** ← **G2.** Re-scope per §4.1: **not** a snapshot checksum (exists) but
  **per-entry GHSA/OSV provenance verify + OSV-schema validator + put the watchlist in the writable lane**
  under a Gate-2 (`gate_kb_edit`-analogue). This is the executable half of "Gate-2."
- **wh-k6l (extensible watchlist)** ← **G2.** The curated/extensible OSV watchlist file is the DATA that
  Gate-2 validates; keep schema-aligned with wh-5es's writer. (Already re-scoped to an extensible
  mechanism per the earlier session.)
- **wh-4k9 (version-aware S8)** ← **G3.** Already groomed with the right fix **and** a hard prereq the
  audit confirms: adapters emit `spec` (manifest range), no `version` key → extract the lockfile-resolved
  version FIRST; two existing tests pin the old name-only behavior and must be updated (TDD). **Ready to
  implement** — smallest, highest-confidence win.
- **wh-hxt.3 (CONTAIN primary spike)** ← **G4.** Add the concrete inner-loop bridge (auto-route the
  sealed sandbox when snapshot + docker present; S8 default-when-safe) as a deliverable. PREREQ:
  `./run.sh build && ./run.sh test` on a daemon host (`README.md:87-88` says authored-not-build-verified;
  bd memory records 67 passed on Rancher Desktop — re-confirm before relying on it).
- **wh-hxt.1 (staleness)** ← **G6.** Extend to cover **tools/watchlist** retire/supersede, not just KB
  `--archive`. P3.

### 6.2 Create one new ticket

- **wh-hxt.4 — Spike: ADMIT-via-loop (machine-readable registry + registry-row writer)** ← **G5.** P2.
  Design a parseable `tool-registry` sidecar (pin + digest + compromise-status fields) and wire
  `patch_merge` to write registry rows behind `confine_self_writes` + `gate_kb_edit`, so a new/retired
  tool self-admits as a gated diff the way KB techniques do. Add `supply-chain` to `poll_feeds`
  VALID_CLASSES. Reuses existing confine/gate/lock machinery — implementation, not new infrastructure.
  Likely outcome: keep the lock test field-based (not prose-diff). Nest under wh-hxt.

### 6.3 Suggested sequence

1. **wh-4k9** (G3) — small, ready, removes the FP bomb that makes the watchlist unusable in practice.
2. **wh-562 Gate-2** (G2) + **wh-5es feeder** (G1) — the P0 pair; do Gate-2's schema first so the feeder
   writes valid entries. Coordinate the ONE watchlist schema across wh-562/wh-5es/wh-k6l.
3. **wh-hxt.3 sandbox auto-route** (G4) — after build-verifying `run.sh`; turns CONTAIN on by default.
4. **wh-hxt.4 ADMIT-via-loop** (G5) — the aspirational arm; lowest urgency, highest design content.
5. **wh-hxt.1 RETIRE-for-tools** (G6) — last.

---

## 7. Open decisions for the refinement pass

1. **Gate-2 home** — does the watchlist validator live in `deps-scan/scripts/` (next to `malware_db.py`)
   or in `_shared/` as a reusable DATA-gate? (Mirrors the wh-562 ↔ wh-5es ↔ wh-k6l "one watchlist"
   reconciliation.)
2. **Sandbox auto-route default** — S8 "default-when-safe" (snapshot + docker present) vs. stay opt-in
   with a louder `tools_unavailable` surfacing. Trade-off: containment-by-default vs. surprising the user
   with a Docker run. (Decide in wh-hxt.3.)
3. **`sec-learn` scope** — **not fully audited** (the sec-learn reader failed to return structured output;
   coverage here is inferred from `patch_merge.py:40` having no non-test caller). Before grooming wh-hxt.4,
   verify directly what traces `/sec-learn` reflects on and whether it can target `tool-registry.md`.
4. **CI hardening checklist** (from wh-hxt.3) — where does the hardened-CI guidance (SHA-pin Actions,
   minimal token, OIDC scope, egress allowlist, `--ignore-scripts`) live — in `ci/` docs, or as ADR
   content? It's the CONTAIN layer for the *CI* surface, distinct from the tool-exec sandbox.

---

## 8. References (file:line index)

- **Outer-input:** `sec-kb-refresh/scripts/poll_feeds.py` (`:23` VALID_CLASSES, `:69` PARSERS, `:82-107`
  render, `:84` class assert); `sec-kb-refresh/SKILL.md:34-37`; `test_poll_feeds.py:66-95`.
- **Outer-reflect:** `sec-learn/scripts/patch_merge.py:40`; `staleness_check.py:26-30,50-52`.
- **The gate:** `evals/score.py:64-95`; `evals/keep_or_revert.py:14-15,33-50`;
  `plugins/white-hacker/hooks/gate_kb_edit.py:18,40-49,58-61`; `evals/gate-verdict.json` (absent → fail
  closed); `ai-attack-kb/scripts/validate_kb.py` (provenance gate).
- **Confinement:** `plugins/white-hacker/hooks/confine_self_writes.py` (`:16-17` tripwire, `:29` FROZEN,
  `:33-35` CONTROL, `:40` ALLOW_SEGMENTS, `:41-46` FEED_HOSTS, `:51` NET_VERBS, `:69-77` deny, `:111-122`
  egress, `:119` host-only); `test_confine_self_writes.py`.
- **Data:** `_shared/reference/tool-registry.md:1,7,50-55`; `deps-scan/scripts/malware_db.py:26-44`
  (loader), `:47-52` (`is_known_bad`, dead), `:78-84` (DB shape); `deps-scan/reference/MALWARE-DB.md:48,79`.
- **Inner + CONTAIN:** `sec-detect/scripts/detect_tools.py` (`SCANNER_PREFERENCE`, `build_scan_plan`);
  `deps-scan/scripts/supply_chain.py:744-756` (`signal_s8`), `:975`, `:995-996`, `:1122-1124`;
  `deps-scan/SKILL.md:80-82,110`; `docker/deps-scan-sandbox/run.sh`, `fetch-snapshot.sh:2-6,16,34,36,37`,
  `README.md:3,8,19,49-50,87-88`.
- **Design intent:** ADR-001 / ADR-015 / ADR-019 (`docs/ARD.md`); `docs/ARCHITECTURE.md:318-322`;
  `.claude/CLAUDE.md` ("KB-refresh is the input arm" / "tools are knowledge too").
- **Workflow run:** `wst324yuh` (this audit). Strategy doc: `20260609_supply_chain_tooling_strategy.md`.
