# Spike-12: ADMIT-via-loop — the machine-readable tool-registry sidecar + the deterministic registry-row writer (2026-06)

> **Self-improvement / supply-chain context.** This spike DESIGNS the missing *proposer* that
> makes ADR-015's *"the registry self-updates"* real in code: a machine-readable mirror of
> `tool-registry.md` (so the outer loop can read/propose rows deterministically) + a pure-function
> row writer (`admit_tool`, the screen ADR-025 §1 delegated here) that emits a draft registry-row
> PR gated by Gate-2's DATA verdict (ADR-026), never by the eval keep-or-revert gate. The arm that
> proposes is **`sec-kb-refresh`** (primary); `sec-learn` is structurally dry (deferred). No
> production code here — decisions + a draft impl-ticket spec section. The impl consumes
> wh-hxt.5 (the Gate-2 validator), wh-hxt.6 (`gate_data_edit`), and wh-hxt.7 (the rewritten registry).

**Status:** RESOLVED (RQ1–RQ4) · no new ADR (consumes ADR-024 §6(a) / ADR-025 §1 / ADR-026 §3)
**Date:** 2026-06-11
**Confidence:** HIGH — every decision is grounded in a ratified ADR (ADR-024/025/026, all `accepted`
in `docs/ARD.md`) and a re-verified `file:line` in the live repo (read 2026-06-11). No external/web
claims; this spike cites only ratified ADRs + repo state, as scoped.
**Author:** researcher (seat-hxt4, Wave-A1)
**Ticket:** wh-hxt.4 (epic wh-hxt — the supply-chain capability lifecycle: admit→pin/verify→diversify→monitor→retire).
Siblings (this wave + consumed): wh-hxt.5 (Gate-2 validator `_shared/scripts/validate_watchlist.py`),
wh-hxt.6 (`gate_data_edit` hook + `DATA_SEGMENTS`), wh-hxt.7 (the human-facing registry rewrite — single writer),
wh-562 (the Gate-2 design — ADR-026, this spike's input), wh-nvk (ADR-027 — the rows that first exercise the writer),
wh-xn0 (ADR-025 — the admissibility screen spec), wh-hxt.1 (the staleness/health signal feeding RETIRE rows),
wh-5es (the watchlist feeder — the sibling DATA writer that shares the validator).
**Related ADRs:** ADR-001 (two loops), ADR-002 (CLI-first/no-MCP), ADR-003 (floor/degrade),
ADR-005 (size caps), ADR-006 (pin+verify), ADR-010/012 (proposes, never auto-merges; human draft-PR),
ADR-015 (capability-not-brand registry; **self-updates** — the design intent this spike lands),
ADR-016 (confinement defense-in-depth; the row writer is out-of-lane self-edit),
ADR-024 (CONTAIN; §5 the four-objects-never-merged rule; §6(a) carries the self-updates clarification until this lands),
ADR-025 (admissibility = two deterministic gates; §1 delegates `admit_tool` IMPL to this ticket),
ADR-026 (Gate-2 DATA gate — content-bound one-shot DATA verdict; the mechanism this spike's row PR rides),
ADR-027 (Trivy removal / diversified set — the first rows the writer will carry).

---

## Goal

ADR-015 says the tool registry is *part of the self-improving loop* — `sec-kb-refresh`/`sec-learn`
"can add tools the agent didn't know." That sentence is **aspirational in code today**, confirmed by
three live facts (read 2026-06-11):

1. **No registry writer exists.** `poll_feeds.py` renders only ai-attack-KB technique entries:
   `to_candidate_entry` (`poll_feeds.py:84`) **hard-asserts** `technique_class in VALID_CLASSES`
   (`:23` = the five attack classes), so a tool/registry row (no `technique_class`, not KB markdown)
   structurally cannot ride it. `sec-kb-refresh/SKILL.md:34-37` *claims* tool proposals — **prose-only**.
2. **No machine-readable substrate.** `tool-registry.md` is prose (entry-field conventions + a
   change-log format); there is no JSON/YAML mirror and no validator analogous to `validate_findings.py`.
   The only executable twin is `detect_tools.py::SCANNER_PREFERENCE` (`:110-119`) — capability→ordered
   `(tool, langs)` tuples with **no** license / egress / pin / verify data.
3. **No row-writer screen.** ADR-025 §1 defines `admit_tool(record) -> (admitted, reason)` but
   explicitly marks it *"SPEC in the spike §8; **IMPLEMENTED in wh-hxt.4**"* — i.e., this ticket.

Decide, before any "wire it" task is filed: (RQ1) the sidecar shape + path + single-source-of-truth
rule; (RQ2) the deterministic row writer (`admit_tool` + the row-proposal format, no LLM); (RQ3) the
write-lane (the sidecar is a DATA object → it must be added to `gate_data_edit.DATA_SEGMENTS` with a
test); (RQ4) which arm drives it.

## Background & constraints (the decision context)

These are **settled by ratified ADRs — cite, do not re-debate** (Policy 1):

- **The four gates / four objects, never merged** (ADR-024 §5; ADR-025; ADR-026 §1): eval **Gate-1**
  (KB review-quality edits, scored by `evals/score.py`) · **Gate-2** (watchlist/registry **DATA**
  entries, deterministic provenance+schema+regression, ADR-026) · **CONTAIN admission** (TOOL
  *artifacts* — pin + verify the binary at execution, ADR-024 §5) · **admissibility** (license+egress
  *policy* — may the tool be listed at all?, ADR-025). A registry **row** is a **DATA** object → it
  rides **Gate-2** (ADR-026 §3 names "the wh-hxt.4 registry sidecar" as Gate-2's second DATA object).
  A registry row is **NOT** scored by the eval corpus (no corpus case measures "did adding tool X
  help") → reusing an eval-J KEEP for a row is the **false-merit merge** ADR-026 forbids.
- **`admit_tool` is admissibility, not admission** (ADR-025 §1 vs §6): the writer's screen decides
  *whether a tool may enter the registry* (license ∈ {MIT, Apache-2.0} AND egress local/telemetry-off).
  It does **not** pin or verify the binary — that is ADR-024 §5's admission arm, run per-execution, a
  different object. The writer records the pin+verify *fields* in the row; it does not perform them.
- **The DATA-verdict mechanism is decided** (ADR-026 §3, RATIFIED): the Gate-2 validator
  (`_shared/scripts/validate_watchlist.py`, wh-hxt.5) mints a **content-bound** (sha256 of the
  validated bytes) **one-shot** `evals/data-verdict.json`; `gate_data_edit.py` (wh-hxt.6) recomputes
  the write-target hash and blocks on mismatch/replay; the verdict is **never** the eval-J
  `gate-verdict.json`. The sidecar gets the **same** mechanism — the validator was sited in
  `_shared/scripts/` *precisely because this ticket is its second caller* (ADR-026 alternatives (c);
  ADR-015's ≥2-callers port trigger).
- **The registry-row schema is settled by ADR-025 §5** (don't wait on wh-hxt.7): every registry entry
  carries `license` / `data_egress` / `gdpr` columns + per-tool `pin` + `verify` rows. The sidecar
  **mirrors** that column set machine-readably.
- **`sec-kb-refresh` is the primary arm; `sec-learn` is dry** (ADR-026 / the spike body's verified
  facts): the capture hooks exist as tested scripts but are registered in **no** `hooks.json`/
  `settings.json` (pending human-auth — `docs/plan/phase-8-self-improvement.md:107`), and
  `evals/traces/` does not exist on disk → a `/sec-learn` run harvests 0 rows today; its `>=3-sessions`
  pre-gate is prose AND unsatisfiable. Design the writer **arm-agnostic**; wire it to `sec-kb-refresh`.
- **The row writer is out-of-lane self-edit** (ADR-016; ADR-024 §8): the writer *proposes* a row diff;
  it never auto-applies. `confine_self_writes.ALLOW_SEGMENTS` (`:40`) already includes
  `/_shared/reference/`, so the sidecar path is *in the self-improvement write lane* — but a write is
  admitted **only** under a Gate-2 DATA-verdict KEEP, never auto-merged (ADR-012).

### What does NOT exist yet (verified 2026-06-11 — this spike's hard dependencies)

`gate_data_edit.py`, `validate_watchlist.py`, `watchlist-entry-schema.json`, and
`known-compromised.osv.json` are **absent on disk** (`find plugins -name … ` → empty). They are the
wh-hxt.5/.6 deliverables. The sidecar + writer impl **lands after** wh-hxt.5/.6/.7 (a bd ordering dep
already exists on the epic). This spike is parallel-safe: its only deliverable is this research doc.

---

## RQ1 — The machine-readable substrate: a JSON sidecar beside `tool-registry.md`

**DECISION: a JSON sidecar `tool-registry.json` at the same path as the prose registry**
(`plugins/white-hacker/skills/_shared/reference/tool-registry.json`), with the **prose `.md` leading**
as the human source of truth and the **sidecar a derived, lock-tested mirror** of the rows the loop
reads/proposes. JSON, not YAML — the codebase's machine artifacts are JSON (`finding-schema.json`,
`watchlist-entry-schema.json`, `*-verdict.json`); `validate_findings.py` already uses
`Draft202012Validator` over JSON; `poll_feeds` parses with stdlib `json`. YAML would add a non-stdlib
read dependency for no gain here (Policy 2).

**Why a sidecar, not structured front-matter in the `.md`:**

- The `.md` is **prose with multiple free-text sections** (capability descriptions, the pinning
  narrative, the change-log). Front-matter would force a machine-parseable block to coexist with
  prose the lock test reads case-insensitively (`test_registry_lock.py:30` lowercases the whole file).
  A separate file keeps the machine contract clean and independently schema-validatable.
- `detect_tools.py::SCANNER_PREFERENCE` is **already** a machine twin, but a *thin* one (capability→
  `(tool, langs)`; no license/egress/pin/verify). The sidecar is the **richer** machine mirror that
  carries the ADR-025 §5 columns the writer must read and propose. SCANNER_PREFERENCE stays the
  runtime *selection order*; the sidecar is the *governance record*.

**Sidecar shape (`tool-registry-1.0`).** One object per `(capability, tool)`, mirroring the ADR-025 §5
columns + ADR-024 §5 pin/verify + ADR-027's per-tool verify primitive. Illustrative (NOT exhaustive
data — the rows are wh-hxt.7's to write; this is the *schema*):

```jsonc
{
  "schema": "tool-registry-1.0",
  "generated_from": "tool-registry.md",        // provenance: the .md leads
  "tools": [
    {
      "capability": "sca",                       // ∈ {sast, sca, secrets, iac, ai-redteam}
      "tool": "osv-scanner",
      "license": "Apache-2.0",                   // SPDX id — gate input
      "license_source": "https://github.com/google/osv-scanner/blob/main/LICENSE",
      "data_egress": "local",                    // ∈ {local, telemetry-off-by-flag, network-required}
      "egress_flag": null,                       // e.g. "PROMPTFOO_DISABLE_TELEMETRY=1" when telemetry-off-by-flag
      "gdpr": "n/a",                             // the TOOL's data-flow only (ADR-025 §6); agent PII = wh-81y
      "pin": {"kind": "action-sha|image-digest|binary-checksum|pip-hash", "ref": "<immutable>"},
      "verify": "slsa|cosign-keyless|sigstore-bundle|checksum-only|pip-require-hashes",
      "status": "active",                        // ∈ {active, rejected-license, rejected-integrity, retired, stale}
      "reason": null,                            // REQUIRED when status startswith "rejected"/"retired"/"stale"
      "source_url": "https://github.com/google/osv-scanner",
      "added": "2026-06-10",
      "modified": "2026-06-10"
    }
  ]
}
```

**Single-source-of-truth + sync rule.** The **`.md` is authoritative for humans; the sidecar is the
machine projection.** They stay in sync via a **drift-lock test** that EXTENDS, not replaces, the
existing capability-level lock:

- Keep `test_registry_lock.py` GREEN as-is (it locks `SCANNER_PREFERENCE` ↔ `.md` at the **capability**
  level — heading-token presence, `test_registry_lock.py:33-44`). The sidecar adds a **second** lock
  assertion in the same module (or a sibling `test_registry_sidecar_lock.py`):
  1. **Capability closure:** every `capability` in the sidecar is a heading token in the `.md` AND a key
     in `SCANNER_PREFERENCE` (the sidecar cannot name a capability the other two don't).
  2. **Tool coverage:** every `(capability, tool)` listed as *active* in the `.md`'s capability sections
     appears in the sidecar with the same `status`, and vice-versa (no silent divergence between the
     human row and the machine row).
  3. **Schema-valid:** the sidecar validates against a pinned `tool-registry-schema.json`
     (Draft-2020-12, mirroring `finding-schema.json` + `validate_findings.py`).
- **Why .md-leads (not sidecar-leads):** ADR-015 + the registry header (`tool-registry.md:3-7`) make the
  prose registry the *named* artifact humans and the SKILLs reference ("the concept owns this file");
  `test_registry_lock.py` already treats the `.md` as the lock anchor. Inverting that to make a JSON
  file the source of truth would be a larger change to a settled convention (Policy 11) for no benefit —
  the writer proposes BOTH the `.md` change-log line AND the sidecar row in one PR (RQ2), so they are
  authored together and the lock test fails CI if a PR touches one without the other.

**Coordination with wh-hxt.7 (the registry rewrite this wave).** wh-hxt.7 is the **single writer** of
the rewritten `.md` (ADR-025 §5 columns + ADR-027 rows + the `r"0\.7[01]"` lock-regex retirement). The
sidecar's initial rows are **generated from that post-rewrite `.md`** — so the sidecar impl is ordered
**after** wh-hxt.7 (already a bd dep). This spike runs parallel to wh-hxt.7 (disjoint files: research
doc vs registry/code); the sidecar schema is fixed *here* against the ADR-025 §5 column set (settled —
cite, don't wait).

---

## RQ2 — The deterministic row writer (`admit_tool` + the row-proposal format)

**DECISION: a pure-function module `admit_tool.py` in `sec-kb-refresh/scripts/` (the primary arm),
emitting a `(capability, tool)` row candidate via a parallel emit path — NOT through
`poll_feeds.to_candidate_entry` (which hard-asserts the KB taxonomy).** No LLM (Policy 5 — a license
allowlist + egress-default check + a schema render are pure functions).

**The screen (ADR-025 §1, made concrete — the `admit_tool` contract this ticket implements):**

```python
# admit_tool.py  (sec-kb-refresh/scripts/) — pure function, no LLM, no network, no RNG (Policy 5)
PERMISSIVE = {"MIT", "Apache-2.0"}              # ADR-025 §1 — the ONLY admissible licenses

def admit_tool(record: dict) -> tuple[bool, str]:
    """ADR-025 §1: License-gate AND Egress-gate, both required. Returns (admitted, reason)."""
    lic = _elect_permissive_arm(record.get("license", ""))   # "MIT OR Apache-2.0" -> elect MIT (dual at user option passes)
    if lic not in PERMISSIVE:
        return False, f"License-gate: {record.get('license')!r} not in {{MIT, Apache-2.0}} (ADR-025 §1)"
    egress = record.get("data_egress")
    if egress == "network-required":
        return False, "Egress-gate: default invocation requires network/uploads source (ADR-025 §1)"
    if egress == "telemetry-off-by-flag" and not record.get("egress_flag"):
        return False, "Egress-gate: telemetry on by default and no disable-flag pinned (ADR-025 §1, promptfoo case)"
    return True, "admitted: License-gate + Egress-gate pass"
```

- **License-gate:** `license ∈ {MIT, Apache-2.0}` ONLY — reject BSD/LGPL/GPL/AGPL/MPL/any copyleft/
  proprietary; a dual offering one of them *at the user's option* passes (elect the permissive arm —
  ADR-025 §1's cargo-audit `MIT OR Apache-2.0` example). `_elect_permissive_arm` parses an SPDX
  expression and returns the permissive operand if present.
- **Egress-gate:** the tool's DEFAULT invocation is local/offline, uploads no source, sends no
  telemetry; a telemetry-on-by-default tool is admissible **only** with the disable flag pinned
  (ADR-025 §1's promptfoo `PROMPTFOO_DISABLE_TELEMETRY=1` case → `data_egress:"telemetry-off-by-flag"`
  REQUIRES a non-null `egress_flag`).
- **Note — integrity is NOT this screen's job.** ADR-025 §2 / ADR-027: Trivy is license-clean
  (Apache-2.0) but TeamPCP-compromised, so it is rejected on **integrity**, a different object. The
  writer's `admit_tool` passes Trivy on license+egress; the **`status:"rejected-integrity"`** label and
  the integrity decision come from the human reviewer / the watchlist (Gate-2 cross-check), not from
  this pure function. The writer never *admits* a tool that is on the watchlist — see the regression
  check in RQ3.

**The row-proposal format (what the writer emits — two coupled artifacts in one PR):**

1. **A sidecar row** — the `tool-registry-1.0` object (RQ1 shape) for the new/changed `(capability,
   tool)`, with `status` set by `admit_tool` (`active` on pass; `rejected-license` on License-gate
   fail, recorded with the SPDX reason — ADR-025 §5's "Rejected (License-gate)" subsection is mirrored
   as sidecar rows, not dropped).
2. **A `.md` change-log line** — rendered via **`merge_markdown_patch`** (`patch_merge.py:40`), which
   gets its **first real caller** here. The registry change-log format
   (`tool-registry.md:63` = `YYYY-MM-DD · +/- · capability · tool · source · rationale`) is a
   section-keyed append under the `## Change log` heading — exactly the section-keyed `##` merge that
   function was built for (`patch_merge.py:1-12`). The writer builds the new change-log section text and
   merges it into the existing `.md`, append-only.

**Taxonomy decision (the `poll_feeds` `:84` hard-assert):** do **NOT** add a `tool`/`supply-chain`
class to `VALID_CLASSES`. A new class would make `to_candidate_entry` render an `AISEC-…` KB markdown
entry into `ai-attack-kb/` — the wrong lane (a tool row is a registry DATA object, not an attack
technique). Instead, the writer uses a **parallel emit path** (`emit_registry_row` /
`to_registry_candidate`), exactly mirroring the sibling decision in wh-5es (the watchlist feeder uses a
parallel `to_watchlist_candidate`, not a new VALID_CLASS, for the same structural reason — see
`docs/research/20260609_supply_chain_compromise_monitoring.md`). The two writers (registry + watchlist)
are siblings: each parses a source → renders a DATA candidate → Gate-2 validates → draft PR.

**The full proposer pipeline (arm-agnostic; wired to `sec-kb-refresh`):**

```
feed/discovery signal (a new or relicensed or compromised scanner)
  -> build a tool record {capability, tool, license, license_source, data_egress, egress_flag,
                          pin, verify, source_url, gdpr}                       # discovery (recall)
  -> admit_tool(record) -> (admitted, reason)                                  # the ADR-025 §1 screen (pure)
  -> emit_registry_row(record, admitted, reason) -> sidecar row + .md change-log line via merge_markdown_patch
  -> validate (wh-hxt.5 validator, registry profile: schema-valid + admit_tool re-checked + lock-green)
  -> Gate-2 mints evals/data-verdict.json (sha256-bound, one-shot — ADR-026 §3)
  -> draft PR (human review; never auto-merge — ADR-010/012)
```

The `admit_tool` screen runs **twice** by design: once in the writer (to set the proposed `status`),
and again in the **validator** (RQ3) as the authoritative gate — the writer's output is untrusted input
to the gate, so the gate re-runs the pure check rather than trusting the proposed `status` field
(defense-in-depth; mirrors how `gate_data_edit` recomputes the hash rather than trusting the verdict).

**RETIRE / status-change rows (RQ4 of the original ticket, folded in).** The same writer proposes
**status changes**, not just additions: a tool flagged stale/compromised by wh-hxt.1's staleness signal
or by a watchlist hit becomes a row with `status:"retired"` / `"stale"` / `"rejected-integrity"` and a
required `reason` + `source_url`. This is the symmetric path — `emit_registry_row` takes the existing
row and the new status; the change-log line is `YYYY-MM-DD · - · capability · tool · source · rationale`
(the `-` form, already in the registry change-log on `tool-registry.md:66` for the Trivy demotion). The
RETIRE input (a staleness/compromise signal) is wh-hxt.1's / the watchlist's to produce; the writer is
the common renderer for both ADD and RETIRE.

---

## RQ3 — The write-lane: the sidecar is DATA → it MUST be added to `gate_data_edit.DATA_SEGMENTS` with a test

**DECISION (a BINDING acceptance criterion on the impl ticket, carried verbatim from wh-562/QA-#2):**
`gate_data_edit.DATA_SEGMENTS` ships **watchlist-only** (wh-hxt.6); **this ticket's impl MUST add the
sidecar's path to `gate_data_edit.DATA_SEGMENTS` WITH a test** — so the sidecar is **never
write-enabled before it is DATA-gated.** This is non-negotiable: without it, the sidecar would either
(a) be writable under no DATA gate at all, or (b) fall through to `gate_kb_edit` and be admitted by an
unrelated eval-J KEEP — the false-merit merge ADR-026 forbids.

The verdict mechanism itself is **already decided — consume ADR-026 §3, do not re-decide** (the spike
body's groom note (2)): the Gate-2 validator mints a content-bound, one-shot `evals/data-verdict.json`;
`gate_data_edit.py` recomputes the write-target's sha256 and blocks on mismatch/replay; the verdict is
never the eval-J `gate-verdict.json`. The sidecar rides the **same** mechanism. The **remaining RQ3
work** is the **registry-row validation PROFILE** — what "schema-valid" means for a sidecar row vs a
watchlist entry (ADR-026 §3 notes the validator was sited in `_shared/scripts/` precisely because this
ticket is its second caller). Concretely, the wh-hxt.5 validator gains a second mode:

| Validator mode | Object | Checks (all pure, no LLM — Policy 5) |
|---|---|---|
| `watchlist` (wh-hxt.5) | `known-compromised.osv.json` entry | id-bound primary-source advisory URL · `watchlist-1.0` schema · regression-green (`malware_db.load_malware_db` + `is_known_bad`) — ADR-026 §1 |
| `registry` (this ticket) | `tool-registry.json` row | **(a)** `tool-registry-1.0` schema-valid · **(b)** `admit_tool(row)` returns admitted (License-gate + Egress-gate — ADR-025 §1) OR a `status` that explains a non-admit (`rejected-license`/`rejected-integrity`/`retired`/`stale` with a `reason`) · **(c)** the drift-lock is green (sidecar ↔ `.md` ↔ `SCANNER_PREFERENCE`, RQ1) · **(d)** the proposed `(capability, tool)` is **not** on the watchlist with an `active` status (an integrity cross-check — a tool the watchlist marks compromised cannot be admitted `active`) |

`gate_data_edit` is scoped to the **named DATA file paths** (ADR-026 §3): watchlist (wh-hxt.6) +
sidecar (this ticket). Symmetrically, `gate_kb_edit` must **exclude** the sidecar path (as ADR-026 §3
already requires for the watchlist — `gate_kb_edit` "excludes those paths so a DATA write is not
double-gated by the KB verdict"). **This is a load-bearing impl AC:** `gate_kb_edit.GATED_SEGMENTS`
(`gate_kb_edit.py:18`) currently includes `/_shared/reference/`, which *covers the sidecar path* — so
absent a DATA-path skip, every sidecar write would be **double-gated** (blocked by the absent eval-J
verdict). The impl must add the sidecar path to the `gate_kb_edit` DATA-skip set (the same skip wh-hxt.6
adds for the watchlist) **with a test**, in the **same** hook-ordering window ADR-026 §3 mandates:
`gate_data_edit` registered + the `gate_kb_edit` skip merged **before** the sidecar file is created.

**Verdict-writer / schema freeze (SEC-Q12, carried from wh-562 triage):** the `tool-registry-schema.json`
pin (the file that defines "valid" for a sidecar row) is **gate-grade** — it must be added to
`confine_self_writes.FROZEN_BASENAMES` (`confine_self_writes.py:29`), the same protection
`keep_or_revert.py` and (per ADR-026 §3) `validate_watchlist.py` + `watchlist-entry-schema.json` get,
so the outer loop cannot weaken the gate that admits its own DATA edits. The **sidecar data file**
(`tool-registry.json`) is NOT frozen — it is the writable DATA object; only its *schema* and the
*validator* are frozen.

---

## RQ4 — Which arm drives it: `sec-kb-refresh` (primary); `sec-learn` deferred (dry)

**DECISION: `sec-kb-refresh` is the primary proposing arm; `sec-learn` is a deferred secondary**
(consume the ticket-body + ADR-026 facts; do not re-derive):

- **`sec-kb-refresh` fits structurally.** Tool discovery is **feed-shaped** — a new scanner is
  announced, relicensed, or compromised, which is exactly the deterministic *poll → extract → render →
  validate → draft-PR* pipeline `sec-kb-refresh` already runs (`poll_feeds.py` + `SKILL.md:34-37`'s
  existing — prose-only — tool-proposal claim). The new `admit_tool` + `emit_registry_row` modules live
  in `sec-kb-refresh/scripts/` beside `poll_feeds.py`. (The writer itself is **arm-agnostic** — a pure
  module — so `sec-learn` could call it later without change.)
- **`sec-learn` is structurally dry — DEFER (RQ5 of the original ticket).** Verified 2026-06-11: the
  T-8.3 capture hooks exist as tested scripts (`capture_hooks.py` + the `.sh` wrappers) but are
  registered in **no** `hooks.json`/`settings.json` (pending human-auth —
  `docs/plan/phase-8-self-improvement.md:107`), and `evals/traces/` does **not** exist on disk → a
  `/sec-learn` run harvests **0 rows**; its `>=3-sessions` pre-gate (`SKILL.md:27`) is prose AND
  unsatisfiable. This matches the Hades dogfood RCA (the self-improving loop is design-intent, not
  operational). **Do not wire `sec-learn` here.** The capture-hook **registration is a pending human
  decision** — flag it; do not perform it (self-modifying startup config, ADR-016 §scope-caveat). If it
  later gets registered, encoding the `>=3-sessions` threshold over `harvest.py:31-37`'s `by_session`
  output is the cheap follow-up — out of scope otherwise.

---

## Do we need a new ADR? **No.**

The design **consumes** three ratified ADRs and adds no new structural decision:

- **ADR-025 §1** delegates `admit_tool(record) -> (admitted, reason)` IMPL to this ticket (named: *"SPEC
  in the spike §8; IMPLEMENTED in wh-hxt.4"*). This spike implements that delegation; it does not
  re-decide the policy.
- **ADR-026 §3** already scopes the registry sidecar as Gate-2's second DATA object ("the wh-hxt.4
  registry sidecar"), names the content-bound one-shot DATA-verdict mechanism, and states the
  `DATA_SEGMENTS`/`gate_kb_edit`-skip discipline. This spike applies it; it does not extend it.
- **ADR-024 §6(a)** carries the ADR-015 *"registry self-updates"* design-intent clarification *"until
  wh-hxt.4 lands."* **When the impl ships, that intent is satisfied in code** — no new ADR is needed to
  state it; ADR-024 §6(a) + ADR-015 already own the sentence (exactly-one, as required).

The **sidecar schema** (`tool-registry-1.0`) is a *projection of ADR-025 §5's already-decided column
set* into JSON — a derived artifact, not a new decision, so it does not warrant its own ADR (the
analogous `watchlist-1.0` schema is likewise pinned by reference under ADR-026 §2, not given a separate
ADR). If, at impl time, the sidecar's existence is judged to need a one-line ARD note, it is an
**append-only clarification under ADR-015** ("the machine mirror that realizes self-updates lands as
`tool-registry.json`"), decided at write time — **not pre-claimed here** (Policy 1; the ticket body's
"never pre-claim a number").

---

## Draft impl-ticket spec section (NOT a `bd create` — the TL files this)

> **Headline:** *Implement the tool-registry sidecar (`tool-registry.json` + `tool-registry-schema.json`)
> and the deterministic row writer (`admit_tool` + `emit_registry_row` via `merge_markdown_patch`),
> behind `gate_data_edit` (DATA-gated) and the Gate-2 DATA verdict — `sec-kb-refresh` primary arm.*

**Depends on (hard ordering):** wh-hxt.5 (the `_shared/scripts/validate_watchlist.py` Gate-2 validator —
this ticket adds its `registry` mode) · wh-hxt.6 (`gate_data_edit.py` + `DATA_SEGMENTS` + the
`gate_kb_edit` DATA-skip — this ticket adds the sidecar path to all three) · wh-hxt.7 (the rewritten
`.md` registry — the sidecar's initial rows are generated from it). The sidecar file is created **only
after** `gate_data_edit` is registered and the `gate_kb_edit` skip is merged (ADR-026 §3 hard ordering).

**Scope (what the impl builds):**

1. `plugins/white-hacker/skills/_shared/reference/tool-registry-schema.json` — Draft-2020-12 schema for
   `tool-registry-1.0` (RQ1 shape). **Add to `confine_self_writes.FROZEN_BASENAMES`** (gate-grade,
   SEC-Q12) — a human-PR'd hook change.
2. `plugins/white-hacker/skills/_shared/reference/tool-registry.json` — the sidecar data file, rows
   generated from the post-wh-hxt.7 `.md`. **NOT frozen** (it is the writable DATA object).
3. `plugins/white-hacker/skills/sec-kb-refresh/scripts/admit_tool.py` — the pure `admit_tool(record) ->
   (admitted, reason)` screen (ADR-025 §1: License-gate + Egress-gate; `_elect_permissive_arm` for dual
   licenses). No LLM/network/RNG.
4. `…/sec-kb-refresh/scripts/emit_registry_row.py` (or a function in the same module) — renders the
   sidecar row + the `## Change log` line via `merge_markdown_patch` (`patch_merge.py:40` — its first
   non-test caller; add `sec-learn/scripts` to the `sec-kb-refresh` test path or vendor the function per
   the repo's cross-skill-import precedent `_shared/scripts/conftest.py:10-15`). Parallel emit path —
   **does not** touch `poll_feeds.VALID_CLASSES`.
5. **The `registry` validator mode** in `validate_watchlist.py` (RQ3 table): schema-valid + `admit_tool`
   re-checked + drift-lock green + watchlist integrity cross-check. The Gate-2 verdict path is reused
   unchanged (ADR-026 §3).
6. **`gate_data_edit.DATA_SEGMENTS` += the sidecar path, WITH a test** (the binding RQ3 AC). **+ the
   `gate_kb_edit` DATA-skip for the sidecar path, WITH a test** (so it is not double-gated).
7. **The drift-lock extension** (RQ1): sidecar ↔ `.md` ↔ `SCANNER_PREFERENCE` (capability closure + tool
   coverage + schema-valid), keeping `test_registry_lock.py` GREEN and adding the sidecar assertions.

**Verification criteria (DoD — each runnable):**

- [ ] `uv run pytest …/sec-kb-refresh/scripts/tests/test_admit_tool.py` — `admit_tool` pins **both**
      `== (True, …)` for an MIT/Apache local tool AND `== (False, …)` for each reject class (LGPL, GPL,
      AGPL, BSD-3, proprietary, `network-required`, `telemetry-off-by-flag` with no flag); the dual
      `"MIT OR Apache-2.0"` case is admitted (Policy 9 — both the positive and the wrong-value branch).
- [ ] `uv run pytest …/sec-kb-refresh/scripts/tests/test_emit_registry_row.py` — an ADD row renders the
      sidecar object + a `· + ·` change-log line; a RETIRE row renders `status:"retired"` + a `· - ·`
      line; `merge_markdown_patch` appends under `## Change log` without disturbing other sections.
- [ ] `uv run pytest …/_shared/scripts/tests/test_registry_lock.py` — GREEN (capability lock unchanged)
      AND the new sidecar drift-lock asserts a divergent sidecar row FAILS (a `(capability, tool)` in
      the `.md` but absent from the sidecar, and vice-versa).
- [ ] `uv run pytest …/hooks/tests/test_gate_data_edit.py` — the sidecar path is in `DATA_SEGMENTS`; a
      sidecar write with a matching content-bound verdict is ALLOWED and a mismatched/replayed verdict is
      BLOCKED (mirrors the watchlist test).
- [ ] `uv run pytest …/hooks/tests/test_gate_kb_edit.py` — a sidecar write is **NOT** blocked by the
      absent eval-J `gate-verdict.json` (the DATA-skip works); a `*.md`/KB write still is.
- [ ] `uv run --with jsonschema python validate_watchlist.py --profile registry tool-registry.json` →
      exit 0 on the real sidecar; exit 1 on a row with a non-permissive license or a missing `reason` on
      a `rejected-*` status.
- [ ] `confine_self_writes.FROZEN_BASENAMES` contains `tool-registry-schema.json`
      (`uv run pytest …/hooks/tests/test_confine_self_writes.py` pins it frozen; the data `.json` writable).

**Out of scope (flag, don't do):** wiring `sec-learn` (dry — capture hooks unregistered, a pending human
decision); registering `gate_data_edit` in `hooks.json` (self-modifying config — human-auth, the same
gate ADR-016 §scope-caveat governs); the live `evals/score.py` SAST-downgrade measurement (ADR-025 §4 /
ADR-027 §6 — a separate gated arm, not this ticket).

---

## Risk & open questions

1. **Ordering fragility (the false-merit window).** If the sidecar file is created before
   `gate_data_edit` is registered + the `gate_kb_edit` skip is merged, the sidecar is either ungated or
   double-gated. **Mitigation:** the hard-ordering AC (ADR-026 §3) is restated as a blocking dependency
   in the impl ticket; the two `gate_*` tests are part of the same PR as the sidecar file.
2. **Drift-lock granularity.** `test_registry_lock.py` locks at the **capability** level today; the
   sidecar lock adds **tool-row** coverage. Risk: a too-strict tool-row lock makes routine `.md` edits
   (e.g., a prose tweak) fail CI. **Mitigation:** the lock asserts only `(capability, tool, status)`
   set-equality between the `.md` capability sections and the sidecar — not prose; the change-log and
   narrative sections are not locked.
3. **`merge_markdown_patch` first-caller risk.** The function is pure + tested but has had **no** real
   caller (`patch_merge.py:40`, no non-test caller repo-wide). Risk: the registry change-log format is
   a single `## Change log` section with a bullet list, not multiple `##` sections — confirm the
   section-keyed merge appends a bullet correctly (it replaces a whole `##` section on heading match).
   **Mitigation:** the writer builds the *complete* new `## Change log` section (old bullets + the new
   line) and lets `merge_markdown_patch` replace-in-place — covered by `test_emit_registry_row.py`.
4. **Watchlist integrity cross-check coupling (RQ3 check (d)).** The `registry` validator mode reads the
   watchlist to reject admitting a compromised tool `active`. Risk: it couples the sidecar gate to the
   watchlist file's presence. **Mitigation:** if the watchlist is absent, the check degrades to a
   warning (ADR-003 floor) — admissibility (license+egress) still gates; integrity is a *second*,
   best-effort cross-check, not the primary gate (the primary integrity control is CONTAIN admission at
   execution, ADR-024 §5).
5. **`sec-learn` stays dry indefinitely.** If the capture hooks are never human-authorized, the writer
   only ever runs from `sec-kb-refresh`. This is **acceptable** — `sec-kb-refresh` is the primary arm by
   design; `sec-learn` is a bonus path that needs no code change to adopt later (the writer is
   arm-agnostic).

## Follow-up tickets needed

- **The impl ticket** (the draft spec above) — file via `/design-ticket`; depends on wh-hxt.5/.6/.7.
- **(flag, not file here)** the `sec-learn` capture-hook **registration** — a pending **human** decision
  (`docs/plan/phase-8-self-improvement.md:107`); when taken, a small follow-up encodes the
  `>=3-sessions` threshold over `harvest.py:31-37`. Out of scope for the impl ticket.

## References

**ADRs (ratified, `docs/ARD.md`):** ADR-015 (capability-not-brand registry; self-updates — the intent
this lands), ADR-024 §5 (four-objects-never-merged; the artifact-provenance admission arm) + §6(a) (carries
the self-updates clarification until wh-hxt.4) + §8 (out-of-lane self-edit asymmetry), ADR-025 §1 (the
`admit_tool` two-gate screen — IMPL delegated here) + §5 (the registry-schema columns the sidecar mirrors)
+ §6 (admissibility ≠ admission), ADR-026 §1 (the four gates) + §3 (the content-bound one-shot DATA
verdict + `DATA_SEGMENTS`/`gate_kb_edit`-skip + the validator's `_shared/scripts` home as this ticket's
second caller), ADR-027 (the diversified rows the writer first carries), ADR-003 (floor/degrade),
ADR-006 (pin+verify), ADR-010/012 (proposes, never auto-merges; human draft-PR), ADR-016 (confinement
defense-in-depth — the writer is out-of-lane).

**Code/registry anchors (read 2026-06-11):**
`plugins/white-hacker/skills/_shared/reference/tool-registry.md:3-7,63,66` (the prose registry header +
change-log format) ·
`…/sec-detect/scripts/detect_tools.py:110-119` (`SCANNER_PREFERENCE` — the thin executable twin) ·
`…/_shared/scripts/validate_findings.py:24,31-42` (the shared-validator pattern to mirror) +
`…/_shared/scripts/conftest.py:10-15` (the cross-skill-import precedent) ·
`…/_shared/scripts/tests/test_registry_lock.py:30-44,51` (the capability-level drift-lock to extend; the
`r"0\.7[01]"` line wh-hxt.7 retires) ·
`…/sec-kb-refresh/scripts/poll_feeds.py:23,84` (`VALID_CLASSES` + the hard-assert — the reason for a
parallel emit path) + `…/sec-kb-refresh/SKILL.md:34-37` (the prose-only tool-proposal claim this realizes) ·
`…/sec-learn/scripts/patch_merge.py:1-12,40` (`merge_markdown_patch` — its first real caller) +
`…/sec-learn/scripts/harvest.py:31-37` (the `by_session` output for the deferred `>=3` gate) ·
`…/hooks/confine_self_writes.py:29,40` (`FROZEN_BASENAMES` + `ALLOW_SEGMENTS` — the sidecar is in-lane;
its schema is frozen) · `…/hooks/gate_kb_edit.py:18` (`GATED_SEGMENTS` covers `/_shared/reference/` — the
double-gate the DATA-skip prevents) · `docs/plan/phase-8-self-improvement.md:107` (the unregistered
capture hooks — `sec-learn` deferral).
**Absent on disk (this spike's hard deps — wh-hxt.5/.6/.7):** `gate_data_edit.py`,
`validate_watchlist.py`, `watchlist-entry-schema.json`, `known-compromised.osv.json`.

**Sibling research docs:** `docs/research/20260609_supply_chain_compromise_monitoring.md` (wh-5es — the
parallel-emit-path precedent: `to_watchlist_candidate`, not a new VALID_CLASS) ·
`docs/research/20260609_tool_admissibility_license_gdpr.md` (wh-xn0 — the admissibility matrix + the
`admit_tool` §8 spec) · `docs/research/20260609_trivy_replacement_sca_iac.md` (wh-nvk — the rows that
first exercise the writer) · `docs/research/20260609_trivy_teampcp_supply_chain.md` (wh-562 — the Gate-2
design this spike consumes).
