# Research: Trivy / TeamPCP supply-chain compromise — verification, exposure, response

**Date:** 2026-06-09
**Author:** white-hacker (spike grounding)
**Spike Ticket:** wh-562 · **Interim action:** wh-d5b
**Status:** **RQ1 (verification) + RQ2 (exposure) FINAL** (2026-06-09); the **Gate-2 design (RQ-A..E +
the watchlist-mechanism ADR text) DECIDED 2026-06-10** below. RQ3 (interim quarantine) decoupled to
wh-d5b; RQ6 (the `AISEC-SUPPLY-CHAIN-002` KB entry) delegated to wh-q86 (CLOSED). The ADR text awaits
serial append by the TL (it does not edit `docs/ARD.md` from here).

> This file is materialized AHEAD of the spike being fully worked because the verification + exposure
> findings are CONFIRMED, sourced, and load-bearing (a tool the agent runs is compromised). Capturing
> it in `docs/research/` now — rather than only in the ticket body + gitignored agent-memory — is the
> right home for confirmed threat-intel (repo convention: research `.md` under `docs/research/`).

## Summary

**Verdict: CONFIRMED (high confidence).** Trivy (aquasecurity) was compromised by threat actor
**TeamPCP** on **2026-03-19** — **CVE-2026-33634 / GHSA-69fq-xp46-6x23**. The attacker force-pushed
imposter commits to the `trivy-action`/`setup-trivy` tags and published a malicious binary + Docker
images carrying the "TeamPCP Cloud stealer." **Our exposure is PARTIAL, not acute:** white-hacker
invokes the Trivy **binary offline** (`trivy fs … --skip-db-update`) — never the force-pushed Action,
the Docker image, or a live DB fetch — and the tool-registry already pins away from the malicious
versions. The two sharp findings: (1) **version-tag pinning was defeated by the force-push** — only
commit-SHA / image-digest / binary-checksum pinning is immutable; (2) `--skip-db-update` does **not**
stop a **poisoned local binary**, so **binary checksum-verify-at-install is our load-bearing control**,
and today the registry's safe-version note is *prose, not an enforced gate*.

**Gate-2 (the wh-562 design below, 2026-06-10).** The watchlist/registry DATA that records "package@version
is known-bad" needs its own deterministic gate — the eval keep-or-revert gate (Gate-1) structurally cannot
score a DATA edit (no corpus signal), so reusing it would be a false-merit merge. Gate-2 = a pure-function
validator (`_shared/scripts/validate_watchlist.py`) checking **per-entry GHSA/OSV provenance + `watchlist-1.0`
schema + regression-green**, minting a SEPARATE `evals/data-verdict.json` enforced by a parallel
`gate_data_edit.py`; the watchlist file lands at **`_shared/reference/known-compromised.osv.json`** (already
inside the write-lane). The one watchlist-mechanism ADR (RQ-D below) also carries the **ADR-021 tag→SHA
supersession** delegated by ADR-024 §6(b) — finding (1) above, made an enforced pinning rule.

## RQ1 — Verification (artifact-by-artifact, primary sources) — FINAL

| Artifact | Malicious | Safe | white-hacker invokes it? | Primary source |
|---|---|---|---|---|
| **Binary** | **v0.69.4** | v0.69.2 / v0.69.3; v0.70.0+ / v0.71.0 | **YES** (offline `--skip-db-update`) | GHSA-69fq-xp46-6x23 / CVE-2026-33634 |
| **Docker images** | **v0.69.5, v0.69.6** | — | NO | Aqua advisory |
| **`trivy-action` tags** | **76 / 77 force-pushed** | **v0.35.0** (only clean) | NO | Aqua / Microsoft |
| **`setup-trivy` tags** | all | **v0.2.6** | NO | Aqua |
| **Vuln-DB** (`trivy-db`/`trivy-java-db`) | updates **suspended** during remediation (availability hit; not confirmed-poisoned) | cached | offline cache only | Aqua |

- **Timeline / vector:** incomplete credential rotation after a late-Feb breach → compromised
  `aqua-bot` account → imposter-commit **tag force-push** + malicious binary/images **re-published
  2026-03-22**.
- **Payload:** "TeamPCP Cloud stealer" — dumps Runner.Worker memory; harvests SSH / cloud / K8s /
  Docker / Git secrets; AES-256 + RSA-4096 exfiltration.
- **Real-world impact:** EU Commission AWS-key abuse; ~71 EU entities; ~91.7 GB exfiltrated.
- **Campaign pattern (CONFIRMED, spreading):** the same actor also hit **Checkmarx KICS** and
  **LiteLLM** (PyPI) — "weaponize widely-used dev/security tooling via CI/registry tag-forging."

## RQ2 — Our exposure — FINAL

| Vector | white-hacker touches it? | ADR-006 version-pin defends? | Gap → fix |
|---|---|---|---|
| Malicious **binary** v0.69.4 | **YES** — `trivy fs … --skip-db-update` (`deps-scan/SKILL.md:44`) | partially (registry pins away from v0.69.4, `tool-registry.md:50-53`) — but caveat is **prose, not enforced**; a poisoned binary on PATH would still run | **binary checksum/signature-verify at install** (ADR-006) — the load-bearing control |
| **Docker image** v0.69.5/.6 | **NO** (we never pull the image) | n/a | none |
| **`trivy-action`** force-pushed tags | **NO** (we run the CLI, not the Action — ADR-002) | **version-tag pin DEFEATED by force-push** → only commit-SHA holds | pin Actions to commit-SHA *if ever used* (we don't) |
| **Vuln-DB** fetch | **NO** — `--skip-db-update` (offline cache) | n/a | none |
| **CI** | **NO** white-hacker CI dependency on Trivy infra | n/a | none |

**Conclusions:**
- **Net exposure = LOW–MEDIUM and partial.** We avoid the Action/image/live-DB vectors entirely (we run
  the offline binary), and the registry already names the bad versions. The residual risk is a user
  with a **poisoned binary on PATH** that the *prose* caveat doesn't stop.
- **Pinning granularity is the structural lesson:** ADR-006 pins **versions**, but the primary vector
  was a **tag force-push** (a mutable ref). Immutable pinning = **commit-SHA + image-digest + binary
  checksum/signature**. This sharpens ADR-006 for every registry tool, not just Trivy.
- `supply_chain.py` has **no** Trivy subprocess/docker call (stdlib-only offline floor); Trivy is
  consumed as JSON via `normalize_deps.py` — so even the binary path is only reached when a user has
  Trivy installed and the agent shells out to it in a tool-assisted (non-floor) review.

## Gate-2 — the deterministic DATA gate for watchlist/registry edits (wh-562 design)

**Re-scoped 2026-06-09** (loop-leverage audit `20260609_supply_chain_loop_leverage.md` §4.1 + §5.1/LBC-6):
the original RQ3–RQ6 split is superseded. RQ3 (interim quarantine) decoupled to **wh-d5b**; RQ6 (the
`AISEC-SUPPLY-CHAIN-002` KB entry) delegated to **wh-q86** (CLOSED). What remains — and what wh-562 now IS
— is **Gate-2: the deterministic DATA gate for supply-chain watchlist/registry DATA edits.** The earlier
"binary checksum-verify is our load-bearing control" framing was corrected: the OSSF snapshot pin is
ALREADY SHA-verified in code (`fetch-snapshot.sh:16` 40-hex enforce → `:34` clone → `:36` checkout → `:37`
`git rev-parse HEAD == PIN || exit 1` → `:40` writes `PINNED_SHA`); ARTIFACT provenance (tool binaries/images)
is ADR-024's CONTAIN **admission** arm. The integrity gap that wh-562 closes is **(a)** per-entry provenance
at load time (`load_malware_db` (`malware_db.py:27`) never verifies a primary source) and **(b)** the
watchlist's write lane (its home is not in `confine_self_writes.ALLOW_SEGMENTS` (`:40`), so the outer loop
cannot write it). Gate-2 is the SECOND of three gates that are NEVER merged (ADR-024 §5): eval **Gate-1**
(KB review-quality edits, `evals/` keep-or-revert) · **Gate-2** (watchlist/registry DATA, here) · **CONTAIN
admission** (TOOL artifacts, ADR-024). ADR-025 added a fourth NAME — **admissibility** (license + egress
policy) — so the discipline is four gates, four objects.

### RQ-A — the Gate-2 validator (deterministic; no LLM/RNG — Policy 5)

**Home decision: `_shared/scripts/validate_watchlist.py`** (NOT `deps-scan/scripts/`). The decisive driver
is **≥2 callers** (ADR-015 / Policy 2 — add a shared port only at the second implementer, never for one):

1. **The watchlist** — `wh-k6l` instantiates `known-compromised.osv.json`; every entry (seed batch
   included) must pass Gate-2 (`wh-k6l` COORDINATION block + Acceptance Criteria).
2. **The tool-registry sidecar** — `wh-hxt.4` RQ3 routes registry-row PRs through *"wh-562's Gate-2 checks:
   schema-valid + admissibility-screen pass + lock-test green ⇒ mint the DATA verdict; never an eval-J KEEP"*
   (`bd show wh-hxt.4`). The registry sidecar lives in `/_shared/reference/`.

Two callers, one DATA-shaped gate ⇒ `_shared`. This is not speculative: **the precedent already exists** —
`_shared/scripts/validate_findings.py` is a shared deterministic validator there, loading a pinned schema via
`SCHEMA_PATH = Path(__file__).resolve().parent.parent / "reference" / "finding-schema.json"`, running
`Draft202012Validator`, with file + cross-doc modes and exit codes 0/1/2 (`validate_findings.py:24,31-42,
101-136`). And `_shared/scripts/conftest.py:10-15` **already** adds `deps-scan/scripts` to `sys.path` "when
present", so a validator in `_shared` can `import malware_db` for the regression-green check with no
cross-package install. `test_registry_lock.py` also already lives in `_shared/scripts/tests/` — so the whole
DATA-gate surface (validator + registry lock) co-locates in one skill.

**Script: `plugins/white-hacker/skills/_shared/scripts/validate_watchlist.py`** — mirrors `validate_kb.py`
structure exactly (Policy 11 conformance):

- `SCHEMA_PATH = Path(__file__).resolve().parent.parent / "reference" / "watchlist-entry-schema.json"`
  (the pinned `watchlist-1.0` schema — see RQ-C; sits next to the data it gates, exactly as `kb-entry-schema.json`
  sits next to `validate_kb.py`).
- `load_schema()` → `validate_entry(meta, schema)` (returns `[]` on valid; `Draft202012Validator.iter_errors`
  formatted like `validate_kb.validate_entry` / `validate_findings.validate`).
- `validate_file(path) -> (entry_id, errors)` and `validate_dir(path) -> errors` with a cross-file
  **unique-id** check (an OSV `id` is the primary advisory id; never reused — mirrors `validate_kb.validate_dir`).
- **The three Gate-2 checks**, each a pure function:
  1. **Per-entry primary-source advisory URL REQUIRED — and bound to the entry's own `id` (SEC-Q4).**
     Assert `references[]` holds ≥1 entry whose `url` matches a GHSA/OSV/CVE advisory host (`^https?://` +
     a host allow-list: `github.com/advisories/`, `osv.dev/`, `nvd.nist.gov/`, a project
     `github.com/<owner>/<repo>/security/advisories/GHSA-…`). The host allow-list alone is **insufficient**
     — a real-but-UNRELATED GHSA link, or `github.com/attacker/repo/security/advisories/GHSA-fake`, would
     pass it. So the **id↔URL binding is the load-bearing check (land it now, not at impl time):** at least
     one qualifying `references[].url` MUST contain the entry's OWN `id` (the `id` substring appears in the
     URL). For the per-project `…/security/advisories/GHSA-…` branch specifically, require **host ==
     `github.com` AND the advisory id parsed from the URL == the entry's `id`** (a project-hosted advisory
     for a *different* GHSA id, or on a non-`github.com` host, fails). This is the schema doc's stated
     contract (`20260609_supply_chain_compromise_monitoring.md:73` "REQUIRED ≥1 GHSA/OSV provenance URL
     (wh-562 Gate-2 asserts this)") made id-bound. Encoded as a `required`+`pattern` in the JSON Schema for
     the array shape AND a belt-and-suspenders host **and id-match** check in code (a `references` array of
     the wrong host shape, or one whose URLs never name the entry's `id`, fails).
  2. **Schema validity** against the pinned `watchlist-1.0` schema (RQ-C) — `target ∈ {dependency,tool,
     extension}`, `affected[].package.{ecosystem,name}` shapes, the `extension` block shape for
     `target:extension`, `database_specific.{retrieved,watchlist_confidence}`.
  3. **Regression-green** — a `--check-regression` flag that runs the existing `malware_db`/deps-scan loader
     contract over the candidate: load the candidate file via `malware_db.load_malware_db(<file-or-dir>)`
     (it never raises by contract — `malware_db.py:32`) and assert the version-aware predicate
     `is_known_bad(name, version, db)` (`malware_db.py:48`) returns the expected verdict for the entry's own
     `(name, version)` (bad-version → True; a sibling clean version → False — the exact-set, never-substring
     invariant the version-aware S8 depends on, `supply_chain.py:1042-1048`). "Regression-green" concretely =
     the validator's own check PLUS the deps-scan suite (`uv run pytest plugins/white-hacker/skills/deps-scan/
     scripts/tests` — `test_malware_db.py` + `test_supply_chain.py`) staying green; the impl ticket (RQ-E) wires
     this as the AC.

- **CLI (mirrors `validate_kb.py`):**
  `uv run --with jsonschema python validate_watchlist.py <watchlist-file-or-dir> [--check-regression]`
- **Exit-code contract:** `0` = all entries valid (provenance + schema + regression), `1` = ≥1 invalid (with
  a per-entry reason printed), `2` = usage error. Identical to `validate_kb.py:15` / `validate_findings.py:13`.
- **Determinism:** pure stdlib + `jsonschema` (the same dep `_shared/scripts/pyproject.toml` already
  declares); no LLM, no RNG, no network (Policy 5). It reads OSV JSON as **values** (the `malware_db._read_osv`
  posture, `malware_db.py:62-68`), never executes anything from the snapshot.
- **Value-plane guard (SEC-Q5).** Feed-derived strings (`references[].url`, any advisory text) stay in the
  `.json` **value plane** — the validator emits only PASS/FAIL + a fixed-vocabulary reason (the failing
  check name + the offending key), **never** echoing a feed string into agent-facing prose (the same
  posture as the feeder, which copies no advisory prose into entries — monitoring doc:198-209). Corollary
  for the read side: any future checklist/registry enumeration over `_shared/reference/*` (e.g. a
  `sec-learn` pass) MUST be scoped to `*.md` so the watchlist `.json` is never read as instructions — it is
  detection DATA consumed by `load_malware_db`, not a prose source the agent interprets. The impl ticket (i)
  carries this as a guard note + a test (a crafted `references[].url` cannot appear in the validator's
  stdout beyond the fixed reason vocabulary).

### RQ-B — the write lane (the outer loop CAN write the watchlist — under Gate-2, never ungated)

> **FINAL watchlist file path (load-bearing — wh-k6l + the wh-5es feeder + wh-nvk consume this; it must not move):**
> **`plugins/white-hacker/skills/_shared/reference/known-compromised.osv.json`**
> (a single file; the loader walks a dir recursively, so a per-ecosystem subdir under the same
> `_shared/reference/` prefix is a forward-compatible option — but the canonical pinned path is this file.)

**Why `_shared/reference/`, not `deps-scan/reference/` (supersedes wh-k6l's draft path — Rule 7).** `wh-k6l`
step 1 names `deps-scan/reference/known-compromised.osv.json` but **explicitly defers the path to "wh-562
RQ-B" and says "confirm it before step 1 … so it never moves"** (`bd show wh-k6l` COORDINATION + Steps). The
decision is `_shared/reference/` because:

- **`/_shared/reference/` is ALREADY in `confine_self_writes.ALLOW_SEGMENTS` (`:40` =
  `("/ai-attack-kb/", "/_shared/reference/", "/PATCHES/", "/evals/traces/")`).** So the
  `confine_self_writes` *lane* already covers a write to this one watchlist file — the `:38-39` comment says
  exactly *"so sec-learn can PROPOSE checklist/tool-registry diffs"*. **Scope note (SEC-Q7):** this is NOT a
  blanket grant. The outer loop may write **this one `known-compromised.osv.json` file, and only under a
  DATA-verdict KEEP** (the `gate_data_edit` gate below). The fact that the broader `/_shared/reference/`
  segment is writable does **not** extend to other DATA objects (e.g. the wh-hxt.4 registry sidecar) — each
  DATA object is admissible only once it is named in `gate_data_edit.DATA_SEGMENTS` and carries its own
  DATA-verdict KEEP; an unregistered DATA file in the segment must not be created (Fix-2 ordering, below).
  `deps-scan/reference/` is in **neither** the ALLOW lane nor a gate segment, so siting the watchlist there
  forces a frozen-area edit to `ALLOW_SEGMENTS` — and `confine_self_writes` is **out-of-lane for the outer
  loop to self-edit** (ADR-024 §8; loop-leverage §4.2/LBC-5: hook bodies are caught by default-deny).
  Choosing the path that needs **zero hook edit to the ALLOW lane** is the simplicity-first answer (Policy 2)
  and keeps the write-lane boundary untouched.
- **`/_shared/reference/` is ALREADY in `gate_kb_edit.GATED_SEGMENTS` (`:18` =
  `("/ai-attack-kb/", "/_shared/reference/")`).** So a write there is already gated — but TODAY it is gated by
  the **wrong verdict kind** (an eval-J `evals/gate-verdict.json==KEEP`, `gate_kb_edit.py:40-49`). That is
  precisely the false-merit-merge hazard (see the verdict mechanism below) — and the reason a DATA path needs a
  DATA verdict, not the KB verdict. Co-siting the watchlist with the registry sidecar (`wh-hxt.4`, also
  `/_shared/reference/`) means **one** DATA-gating change covers both DATA objects.
- **The loader is path-agnostic, so the read side imposes no constraint that would override the pin.**
  `load_malware_db(snapshot_dir)` takes an **operator-supplied** dir (`malware_db.py:27`; `MALWARE-DB.md:39`
  shows the operator passing the OSSF `osv` tree) — there is **no hardcoded committed-watchlist path today**.
  So `wh-k6l`'s loader-merge step simply points the loader at the **pinned** `_shared/reference/` file (above)
  IN ADDITION to the optional big OSSF snapshot (union the maps); `_shared/reference/` costs nothing on the
  read side. The path is fixed by the pin at `:155` and must not move — the loader's flexibility is why the
  pin can sit in `_shared/reference/` for the write-lane's sake, **not** a licence to relocate it later. (The
  watchlist file also ships in the vendor manifest — `_shared` is already a `CONSUMER_SKILLS` member, ADR-022.)

**The verdict mechanism — a SEPARATE DATA verdict, NEVER an eval-J KEEP.** The hazard (ticket Problem
statement; loop-leverage LBC-2 + Addendum A1): `gate_kb_edit` admits a `/_shared/reference/` write on
`evals/gate-verdict.json==KEEP`, but that KEEP is earned by a corpus-scored KB change — a watchlist DATA row
has **no** corpus-measurable merit (`score.py:64-95` consumes only findings-vs-`label.json`), so reusing the
eval KEEP would smuggle a poisoned/wrong-version row through on unrelated merit. Decision:

- **Gate-2 mints its OWN verdict file: `evals/data-verdict.json`** (a sibling of `evals/gate-verdict.json`,
  written by `validate_watchlist.py` when ALL three checks pass for the candidate — the same on-disk
  verdict-file pattern `gate_kb_edit` proves, `gate_kb_edit.py:40`). It is **read-only to the agent** (minted
  by the validator in the PR pipeline, like `keep_or_revert.py` mints `gate-verdict.json`).
- **The verdict is CONTENT-BOUND and ONE-SHOT (SEC-Q2 — fixes the replay/TOCTOU hole gate_kb_edit leaves
  open).** `gate_kb_edit.py:40-49` checks only `exists()` + `verdict=="KEEP"` — **no content binding, no
  consume** — so a KEEP minted for candidate A would approve any later write (a poisoned candidate B) to the
  same gated path. The DATA verdict closes both gaps:
  - **Shape:** `{"verdict": "KEEP"|"REVERT"|"INCONCLUSIVE", "path": "<the DATA file>", "sha256":
    "<hex of the EXACT validated bytes>", "validated": "<iso8601>"}`. `validate_watchlist.py` computes the
    sha256 of the candidate file it actually validated and records it.
  - **Content binding:** `gate_data_edit.py` recomputes the **write-target's** content hash (for a `Write`,
    the proposed new bytes; for an `Edit`, the post-edit bytes) and **blocks (exit 2) on any mismatch** with
    the verdict's `sha256` (and on a `path` mismatch). A KEEP for content A therefore cannot admit content B.
  - **One-shot consume:** the verdict is consumed — `gate_data_edit` treats it as valid for exactly the one
    matching write and the verdict file is deleted/invalidated after a successful match (regenerated per
    validation run), so a stale KEEP cannot be replayed for a second, unvalidated write.
- **A parallel gate hook, `gate_data_edit.py`** (mirrors `gate_kb_edit.py` structure), with
  `DATA_SEGMENTS` = the **path-specific** DATA file paths (initially ONLY the watchlist file — see Fix-6/the
  DATA_SEGMENTS note in RQ-E ticket (ii); the wh-hxt.4 sidecar path is added BY wh-hxt.4), NOT the broad
  `/_shared/reference/` segment. It blocks (exit 2) a write to a DATA path unless `evals/data-verdict.json`
  is a KEEP whose `path` + `sha256` match the write target (above). This is the clean resolution of the gate
  mismatch `wh-hxt.4` RQ3 names: **the KB verdict gates KB-shaped `/_shared/reference/` writes; the DATA
  verdict (content-bound, one-shot) gates the DATA files.**
- **How the hook distinguishes DATA-gated from KB-gated paths.** `gate_kb_edit` matches by *segment substring*
  (`gate_kb_edit.py:22-24`); the DATA files are *specific paths* inside `/_shared/reference/`. The two gates
  compose as separate PreToolUse entries: `gate_data_edit` matches the DATA file paths and requires the DATA
  verdict; `gate_kb_edit` continues to match the `/_shared/reference/` segment for the prose checklists/registry
  *markdown*. To avoid double-gating the DATA files (a DATA write must NOT also be forced to carry a KB KEEP),
  `gate_kb_edit` excludes the DATA paths (a small, tested `DATA_PATHS` skip set there) — this is the ONE
  belt-and-suspenders edit the impl ticket makes to `gate_kb_edit`, kept surgical (Policy 3). The
  `confine_self_writes` ALLOW lane is unchanged (the DATA file is already inside `/_shared/reference/`).

> **RQ-B DECISION.** Watchlist file = **`plugins/white-hacker/skills/_shared/reference/known-compromised.osv.json`**
> (already write-lane-allowed + segment-gated; supersedes wh-k6l's `deps-scan/reference/` draft — zero hook edit
> on the lane). Verdict = a SEPARATE **`evals/data-verdict.json`** minted by `validate_watchlist.py`,
> **content-bound (sha256) + one-shot** (SEC-Q2), enforced by a parallel **`gate_data_edit.py`** scoped to the
> DATA file paths; the eval-J `gate-verdict.json` is NEVER reused for a DATA row. `gate_kb_edit` excludes the
> DATA paths so a DATA write isn't double-gated by the KB verdict.
>
> **HARD ORDERING INVARIANT (SEC-Q3 + QA-#1 — load-bearing; wh-k6l + the feeder must honor it).** `hooks.json`
> does NOT register `gate_data_edit` today, and `known-compromised.osv.json` would fall under
> `gate_kb_edit`'s `/_shared/reference/` GATED_SEGMENT. So the watchlist file **MUST NOT be created until**
> `gate_data_edit.py` is registered in `hooks.json` AND the `gate_kb_edit` DATA_PATHS skip is merged + tested
> (RQ-E ticket (ii) lands FIRST). Until then a premature watchlist file would either **(a)** block on a
> missing eval-J `gate-verdict.json` (Gate-1 is fail-closed; the file is absent on disk), or **(b)** — once
> any unrelated KB change mints an eval-J KEEP — be admitted on that KEEP: the exact **false-merit merge** this
> design exists to prevent. Order: **ticket (i) validator+schema → ticket (ii) `gate_data_edit`+skip+register
> → THEN wh-k6l creates the file / the feeder writes entries.** Never the reverse.

### RQ-C — the schema (RESOLVED; consume `watchlist-1.0`, do not re-decide)

Gate-2 validates against **`watchlist-1.0`** — the plain-OSV-superset schema **wh-5es RQ2 finalized**
(`20260609_supply_chain_compromise_monitoring.md:59-81` canonical example, **:162-168 the RQ2 DECISION**). It is
consumed here, never re-litigated (ticket GROOM 2026-06-10 item 2; the schema doc is the contract both Gate-2 and
the feeder build to). What Gate-2 validates against it:

- `schema_version: "watchlist-1.0"`; `id` = the primary advisory id (GHSA preferred; OSV/CVE ok); `target ∈
  {dependency, tool, extension}` (REQUIRED); `affected[]` = plain OSV (`package.{ecosystem,name}` mandatory +
  `versions` — `load_malware_db` reads this unchanged for `target:dependency|tool`); `references[]` ≥1 GHSA/OSV
  URL (the RQ-A provenance check); `database_specific.{retrieved, watchlist_confidence}`; for `target:extension`
  the `extension.{marketplace,id,bad_versions}` block **outside** `affected[]` (loader-ignored). `ecosystem`
  mandatory (provenance + dir path) but **not** the match key today (accepted fail-safe residual). RubyGems
  entries carry **canonical** versions. **No per-entry digest** — force-push resistance lives in the SHA-pinned
  snapshot (`fetch-snapshot.sh:37`), not the entry.

**Where the schema pin lives (so the validator and the wh-5es feeder share ONE pinned artifact):**
**`plugins/white-hacker/skills/_shared/reference/watchlist-entry-schema.json`** — a JSON Schema (Draft 2020-12)
encoding `watchlist-1.0`, sited next to the data it gates and next to the validator (the
`kb-entry-schema.json` ↔ `validate_kb.py` convention; `finding-schema.json` ↔ `validate_findings.py`). The
feeder (`wh-5es` (a)) targets this exact pinned shape (schema-first ordering: the schema lands with Gate-2,
**before** the feeder writes entries).

### RQ-D — ADR text (folds in wh-5es's one-watchlist ADR deliverable)

See the **`## ADR text — TL appends serially`** section below. It states the Gate-1/Gate-2 split, references
`watchlist-1.0` (never restates it), records the write-lane decision, and carries the **MANDATORY ADR-021
tag→SHA supersession delegated by ADR-024 §6(b)**. Per the ticket + `wh-5es` (`20260609_supply_chain_compromise_
monitoring.md:7-8`), wh-5es writes NO ADR — its monitoring-mechanism design folds into this one (one watchlist →
one ADR).

### RQ-E — draft impl ticket specs (feed `/design-ticket` post-wave; NOT `bd create`d this wave)

#### (i) Gate-2 validator — `_shared/scripts/validate_watchlist.py` + the pinned `watchlist-1.0` schema
- **Proposed title:** `feat(_shared): Gate-2 watchlist/registry DATA validator (provenance + watchlist-1.0 schema + regression-green)`
- **Type:** task (impl) · **Epic:** wh-hxt · **Why now:** the watchlist (`wh-k6l`), the OSSF feeder
  (`wh-5es` (a)), and the registry sidecar (`wh-hxt.4`) ALL block on a validated DATA shape — schema-first
  ordering means this lands before any of them writes an entry.
- **Scope (exact files):** NEW `plugins/white-hacker/skills/_shared/scripts/validate_watchlist.py`; NEW
  `plugins/white-hacker/skills/_shared/reference/watchlist-entry-schema.json` (the pinned `watchlist-1.0`
  JSON Schema); NEW `plugins/white-hacker/skills/_shared/scripts/tests/test_validate_watchlist.py`; a
  neutralized OSV fixture set under `_shared/scripts/tests/fixtures/` (a valid entry, a no-provenance entry,
  an unrelated/id-mismatched advisory-URL entry, a schema-invalid entry, a bad-version + clean-sibling pair
  for the regression check). **REQUIRED landing — gate-grade protection (SEC-Q12):** EDIT
  `plugins/white-hacker/hooks/confine_self_writes.py` to add `validate_watchlist.py` to `FROZEN_BASENAMES`
  (`:29`) AND a `FROZEN_PATHS`/segment entry for `watchlist-entry-schema.json` (so the schema pin is not
  self-writable either) — see the gate-grade rationale below; this is itself a human-PR'd hook change and a
  named precondition for trusting the DATA verdict.
- **Gate-grade / out-of-lane (SEC-Q12 — the verdict-writer trust asymmetry).** The eval KEEP is minted by
  `evals/keep_or_revert.py`, which is in `confine_self_writes.FROZEN_BASENAMES` (`:29`) — the outer loop
  cannot rewrite the thing that mints its verdict. `validate_watchlist.py` mints the DATA verdict and the
  pinned `watchlist-entry-schema.json` defines what "valid" means, so **both must have the SAME protection**
  (otherwise the loop could weaken its own gate). **Decision: option (a) — add `validate_watchlist.py` to
  `FROZEN_BASENAMES` and freeze the schema pin**, mirroring how `keep_or_revert.py`/`baseline.json`/
  `score.py`/`label-schema.json` are protected. (Option (b) — leave them in `_shared/scripts` + `_shared/
  reference` and merely add a confinement test that the outer loop cannot Write/Edit them — is rejected: it
  documents the boundary instead of enforcing it, and a basename freeze is the existing, tested mechanism.)
  The validator + schema are **human-PR'd-only code, gate-grade, out-of-lane** (ADR-024 §8 self-edit
  asymmetry) — same status as `keep_or_revert.py`.
- **Acceptance criteria (objective + runnable):**
  - a valid `watchlist-1.0` entry → exit 0; an entry missing `references[]` (or with a non-advisory host) →
    exit 1 with a stated reason (pin BOTH `== valid→0` AND `!= invalid passes`, Policy 9).
  - **id↔URL binding (SEC-Q4):** an entry whose only `references[].url` is a real-but-UNRELATED advisory
    (host valid, but the URL does not contain the entry's `id`) → exit 1; a project-hosted
    `github.com/<owner>/<repo>/security/advisories/GHSA-fake` whose advisory id ≠ the entry's `id` → exit 1;
    an entry whose `references[].url` DOES contain its own `id` → passes that check (pin BOTH).
  - a schema-invalid entry (bad `target`, missing `ecosystem`) → exit 1.
  - `--check-regression` over a bad-version entry → `is_known_bad` True; over its clean sibling → False
    (the exact-set, never-substring invariant — `!= substring-match`).
  - **value-plane guard (SEC-Q5):** a fixture with a crafted `references[].url` / advisory text → that feed
    string does NOT appear in the validator's stdout beyond the fixed reason vocabulary (the check name + the
    offending key only).
  - `validate_watchlist.py` mints `evals/data-verdict.json` (KEEP) only when all checks pass, and the verdict
    records `{path, sha256-of-validated-bytes}` (the SEC-Q2 content binding ticket (ii) enforces).
  - **confinement (SEC-Q12):** a test asserts the outer loop's `confine_self_writes` BLOCKS a Write/Edit to
    `validate_watchlist.py` AND to `watchlist-entry-schema.json` (the freeze landed).
  - `uv run --with jsonschema python validate_watchlist.py <fixture-dir> --check-regression` exits 0.
- **Tests that must stay green:** the hooks suite (**121 passed** baseline, TL-verified — grows by the freeze
  + confinement tests) + the deps-scan suite (`uv run pytest plugins/white-hacker/skills/deps-scan/scripts/
  tests`) + `_shared` suite incl. `test_registry_lock.py`.
- **Dependencies:** none upstream (it defines the shape); **blocks** `wh-k6l`, `wh-5es` (a), `wh-hxt.4`. The
  `confine_self_writes` freeze (above) lands WITH this ticket so the verdict-writer is gate-grade from day one.

#### (ii) The DATA write-lane — `evals/data-verdict.json` + `gate_data_edit.py`
- **Proposed title:** `feat(hooks): gate_data_edit — DATA verdict gate for the watchlist + registry sidecar (no eval-J reuse)`
- **Type:** task (impl) · **Epic:** wh-hxt · **Why now:** without it the watchlist file at
  `_shared/reference/known-compromised.osv.json` is gated by the WRONG verdict (the eval-J KEEP) — the
  false-merit-merge hazard. The lane must exist before the feeder/`wh-k6l` write entries.
- **Scope (exact files):** NEW `plugins/white-hacker/hooks/gate_data_edit.py` (mirrors `gate_kb_edit.py`;
  recomputes the write-target's sha256 and requires a content-bound + one-shot `evals/data-verdict.json`
  KEEP — see the SEC-Q2 binding in RQ-B); EDIT `plugins/white-hacker/hooks/gate_kb_edit.py` (a tested
  `DATA_PATHS` skip so the DATA files aren't double-gated by the KB verdict — surgical, Policy 3); EDIT
  `plugins/white-hacker/hooks/hooks.json` (register `gate_data_edit` as a PreToolUse entry); NEW
  `plugins/white-hacker/hooks/tests/test_gate_data_edit.py`. **`confine_self_writes.ALLOW_SEGMENTS` is NOT
  edited** (the DATA file is already inside the allowed `/_shared/reference/` segment).
- **DATA_SEGMENTS scope (Fix-6 / QA-#2 — no silent ungated path).** `gate_data_edit.DATA_SEGMENTS` ships
  initially with **ONLY** the watchlist path `…/_shared/reference/known-compromised.osv.json` — NOT a
  placeholder for the wh-hxt.4 sidecar. The sidecar path is added to `DATA_SEGMENTS` (with its own test) **as
  part of wh-hxt.4**, so the registry sidecar is never write-enabled before it is DATA-gated. A DATA object
  with no `DATA_SEGMENTS` entry simply has no write lane (it cannot be created — Fix-2 ordering), which is
  the safe default. (Cross-ref the wh-hxt.4 coordination note below.)
- **Acceptance criteria (objective + runnable):**
  - a Write to `_shared/reference/known-compromised.osv.json` with NO `data-verdict.json` → blocked (exit 2);
    with a matching content-bound `data-verdict.json==KEEP` → allowed (pin BOTH, Policy 9).
  - a Write to the DATA path with only an eval-J `gate-verdict.json==KEEP` (no DATA verdict) → still BLOCKED
    (proves the eval-J KEEP cannot smuggle a DATA row).
  - **content binding (SEC-Q2):** a `data-verdict.json` KEEP minted for content A, then a Write of content B
    to the same DATA path → BLOCKED (sha256 mismatch). Pin BOTH: the matching-content write is ALLOWED.
  - **one-shot (SEC-Q2):** after one successful matching write consumes the verdict, a second Write reusing
    the same (now-stale) verdict → BLOCKED (no replay).
  - a KB-markdown write under `/_shared/reference/` (e.g. `tool-registry.md`) is unaffected by `gate_data_edit`
    and still honors `gate_kb_edit` (no regression to the KB lane).
  - `uv run pytest plugins/white-hacker/hooks/tests` exits 0 (the **121** baseline grows by the new tests).
- **HARD ORDERING (SEC-Q3 + QA-#1 — restated as an AC):** this ticket (ii) MUST land — `gate_data_edit`
  registered in `hooks.json` AND the `gate_kb_edit` DATA_PATHS skip merged + tested — **before**
  `known-compromised.osv.json` is created by wh-k6l or written by the feeder. AC: a test asserts that once
  registered, a write to the watchlist path is governed by `gate_data_edit` (the DATA verdict), NOT
  `gate_kb_edit` (the eval-J verdict). Verified-ordering is a release-gate note for the launch plan.
- **Tests that must stay green:** the hooks suite (**121 passed** baseline) incl.
  `test_confine_self_writes.py` + `test_gate_kb_edit.py`.
- **Dependencies:** (i) (the validator mints the content-bound DATA verdict) → THIS (ii) → THEN consumed by
  `wh-k6l` (the first DATA writes) + `wh-5es` (a) (the feeder's draft-PR entries) + `wh-hxt.4` (the registry
  sidecar, which adds its own path to `DATA_SEGMENTS`). The ordering is load-bearing (Fix-2), not advisory.

#### Coordination notes (consumed by the sibling tickets — restate so nobody re-asks)
- **wh-k6l (the watchlist file).** The FINAL path is `_shared/reference/known-compromised.osv.json` (RQ-B,
  superseding wh-k6l's `deps-scan/reference/` draft — satisfies wh-k6l's AC "file path confirmed with wh-562
  RQ-B"). **HARD ORDERING (SEC-Q3 + QA-#1):** wh-k6l MUST NOT create the file until RQ-E ticket (ii) has
  landed (`gate_data_edit` registered + the `gate_kb_edit` DATA_PATHS skip merged/tested). A file created
  earlier would (a) block on the absent eval-J `gate-verdict.json`, or (b) once any unrelated KB KEEP exists,
  be admitted on it — the false-merit merge. wh-k6l's loader-merge points `load_malware_db` at this pinned
  path in addition to the optional OSSF snapshot.
- **wh-hxt.4 (the registry sidecar).** `gate_data_edit.DATA_SEGMENTS` ships with ONLY the watchlist path;
  **wh-hxt.4 MUST add its sidecar path to `DATA_SEGMENTS` (with a test) as part of wh-hxt.4** (Fix-6 / QA-#2)
  — the sidecar is never write-enabled before it is DATA-gated. wh-hxt.4's registry rows are validated by the
  SAME `validate_watchlist.py` and gated by the SAME content-bound DATA verdict (the verdict's `path`/`sha256`
  bind to the sidecar file on a sidecar write).
- **wh-5es (the OSSF feeder).** Schema-first: ticket (i)'s `watchlist-entry-schema.json` is the exact shape
  the feeder's `to_watchlist_candidate` targets; every feeder candidate rides the draft-PR + the content-bound
  Gate-2 verdict (never an eval-J KEEP), and only after ticket (ii) lands.

## ADR text — TL appends serially

> Append-only (Policy 11). **Appended 2026-06-10 as ADR-026** (the first of the wave's TL-serialized
> pair; wh-nvk's followed as ADR-027). House format mirrors ADR-024/025. Status normalized
> `proposed`→`accepted` at append (the ADR-024/025 ratify-at-spike-close precedent); the ARD copy is
> otherwise identical.

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

## References (primary first)

- Aqua advisory — https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/
- GHSA-69fq-xp46-6x23 / CVE-2026-33634 — https://github.com/advisories/GHSA-69fq-xp46-6x23
- Microsoft Security — https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/
- Unit 42 (TeamPCP campaign) — https://unit42.paloaltonetworks.com/teampcp-supply-chain-attacks/
- Wiz — https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack
- Sysdig (campaign spread to KICS) — https://www.sysdig.com/blog/teampcp-expands-supply-chain-compromise-spreads-from-trivy-to-checkmarx-github-actions
- Repo anchors — `plugins/white-hacker/skills/deps-scan/SKILL.md:44`, `_shared/reference/tool-registry.md:50-53`, `deps-scan/scripts/supply_chain.py` (no Trivy subprocess), `sec-detect/scripts/detect_tools.py:110-119` (`SCANNER_PREFERENCE`).
- Gate-2 design anchors — `_shared/scripts/validate_findings.py:24,31-42,101-136` (the shared-validator pattern Gate-2 mirrors) + `_shared/scripts/conftest.py:10-15` (cross-skill `import malware_db`); `ai-attack-kb/scripts/validate_kb.py` (the dir/file + unique-id + exit-code pattern); `hooks/gate_kb_edit.py:18,22-24,40-49` (the verdict-file gate Gate-2 parallels) + `confine_self_writes.py:40` (ALLOW_SEGMENTS — the write-lane); `deps-scan/scripts/malware_db.py:27,48` (`load_malware_db` + `is_known_bad`) + `supply_chain.py:1015-1050` (version-aware S8); `docker/deps-scan-sandbox/fetch-snapshot.sh:16,34,36,37,40` (the SHA-pinned snapshot — force-push resistance); `docs/research/20260609_supply_chain_compromise_monitoring.md:59-81,162-168` (the `watchlist-1.0` schema) + `20260609_supply_chain_loop_leverage.md` §4.1/§5.1/A1 (the Gate-2 split + DATA-verdict path); `docs/ARD.md` ADR-021/ADR-024 §5,§6(b)/ADR-025 (the delegation + the four-objects discipline).

## Follow-up

- [x] Verification (RQ1) + exposure (RQ2) recorded here (FINAL).
- [x] wh-562 Gate-2 design DECIDED (2026-06-10): RQ-A validator (`_shared/scripts/validate_watchlist.py`),
  RQ-B write-lane (`_shared/reference/known-compromised.osv.json` + `evals/data-verdict.json` +
  `gate_data_edit.py`), RQ-C schema (`watchlist-1.0`, pinned at `_shared/reference/watchlist-entry-schema.json`),
  RQ-D the one watchlist-mechanism ADR text (above; carries the ADR-021 tag→SHA supersession delegated by
  ADR-024 §6(b)), RQ-E two draft impl-ticket specs.
- [x] TL — appended 2026-06-10 as **ADR-026** (serial with wh-nvk's ADR-027).
- [ ] `/design-ticket` — carve the two RQ-E impl tickets: (i) the Gate-2 validator + pinned schema;
  (ii) the DATA write-lane (`gate_data_edit.py` + `evals/data-verdict.json`).
- [ ] wh-d5b — interim quarantine (do-now); RQ6 KB entry → wh-q86 (CLOSED).
