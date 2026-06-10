# Research: Continuous supply-chain-compromise monitoring (target deps + IDE extensions)

**Date:** 2026-06-09
**Author:** white-hacker (spike grounding)
**Spike Ticket:** wh-5es · **Related:** wh-562 (agent tools), wh-81y (privacy), wh-0vx (onboarding)
**Status:** **RQ1 (campaign verification) FINAL** (2026-06-09); **RQ2–RQ7 (design) DECIDED 2026-06-10**.
Each RQ below resolves to a DECISION. This spike writes **NO ADR** — its design folds into **wh-562's one
watchlist-mechanism ADR** (one watchlist → one ADR; the strategy doc:117-119 + ticket override). The
feeder's containment (fetch network-ON / analyze network-OFF) is now an **ADR-024 requirement**, not just a
pattern — cited inline.

> Materialized ahead of the spike being fully worked because the campaign verification is CONFIRMED +
> sourced + load-bearing. The full design (watchlist schema, the S8 fix, the new extension capability,
> the cadence, the privacy boundary) is the spike's remaining job — see wh-5es.

## Summary

The **TeamPCP / Mini Shai-Hulud** campaign is CONFIRMED across **three surfaces**: poisoned **PyPI/npm
dependencies** (LiteLLM, Telnyx, TanStack), a poisoned **IDE extension** (Nx Console — a surface
white-hacker does **not** scan today), and the resulting **repo/credential theft** (~3,800 GitHub
*internal* repos, exfiltrated *via* that extension). The design (wh-5es): one shared known-compromised
**watchlist** fed by the outer loop (`sec-kb-refresh`), an **inner-loop** check of the target's deps
(deps-scan S8 — version-aware across 6 ecosystems, DELIVERED) **and** the user's IDE extensions (a NEW
`ide-hygiene` capability), run **at install + a fast SessionStart drift check** (no daemon — honors the
scheduler-aversion + the resource caps). The full design (RQ2–RQ7) is **DECIDED 2026-06-10** below; the
PRIMARY deliverable is the **OSSF feeder** that finally wires `/sec-kb-refresh` into the watchlist.

## RQ1 — Campaign verification (primary sources) — FINAL

| Artifact | Verdict | Versions / IoC | Primary source |
|---|---|---|---|
| Trivy (anchor, the agent-tool angle → wh-562) | CONFIRMED | bin v0.69.4, img 0.69.5/.6, action 76/77 tags | GHSA-69fq-xp46-6x23 / CVE-2026-33634 |
| **LiteLLM** (PyPI) | CONFIRMED | 1.82.7, 1.82.8 (cred-stealer) | GHSA-5mg7-485q-xm76 |
| **Telnyx** (PyPI) | CONFIRMED | 4.87.1, 4.87.2 (backdoor) | Akamai / ISC SANS |
| **@tanstack/\*** (npm) | CONFIRMED | ~42 pkgs / 84 versions (2026-05-11) | Wiz / TanStack postmortem |
| **Nx Console** (VS Code / OpenVSX ext) | CONFIRMED | `nrwl.angular-console` v18.95.0 | GHSA-c9j4-9m59-847w / CVE-2026-48027 |
| **~3,800 GitHub repos** | CONFIRMED — GitHub **internal** repos (not arbitrary OSS), exfiltrated **via** the Nx Console extension | — | BleepingComputer / Nx postmortem |
| OSSF `malicious-packages` carries each entry at a specific path | PARTIAL — Apache-2.0/OSV format confirmed; a sampled path 404'd; **GHSA is the confirmed primary** | — | github.com/ossf/malicious-packages |

**Key takeaway:** the IDE-extension vector (Nx Console) is the surface white-hacker has **zero**
coverage for today, and it was the *pivot* for the largest blast radius (the repo theft) — so the new
`ide-hygiene` extension scan is the highest-value gap this spike closes.

## RQ2 — THE OSV-SUPERSET WATCHLIST SCHEMA (FINALIZED — wh-k6l instantiates; wh-562's Gate-2 validates)

**The decision in one line:** the watchlist is a directory of **plain OSV JSON docs** — exactly the shape
`load_malware_db` already walks (`malware_db.py:27`, the `affected[].package.{name,ecosystem}` + `versions`
fold) — with **two additive, ignorable extension fields** (`target` and, for the extension kind, an
`extension` block). load_malware_db parses the *package* kind **unchanged**; the extension kind is read by
the new ide-hygiene module (RQ4), not by load_malware_db. ONE file/feed/updater, three target tags behind one
shape.

**Why plain-OSV-superset, not a bespoke format.** `load_malware_db` (`malware_db.py:27-45`) and
`_accumulate` (`:71-91`) already consume the OSSF `malicious-packages` OSV layout (`./osv/<ecosystem>/…`,
MALWARE-DB.md:18) and `_read_osv` (`:62-68`) tolerates unknown keys (it only reads `affected`). So any field
we add **outside** `affected[]` is silently ignored by the existing loader — zero code change for the
package kind. This is the simplicity-first path (Policy 2): superset an existing parser, don't fork one.

**The canonical schema (one doc per entry):**

```jsonc
{
  "schema_version": "watchlist-1.0",
  "id": "GHSA-5mg7-485q-xm76",            // the PRIMARY advisory id == the entry id (GHSA preferred; OSV/CVE ok)
  "target": "dependency",                  // REQUIRED extension key: dependency | tool | extension
  "modified": "2026-06-10",                // OSV field; used for incremental delta polling
  "affected": [                            // PLAIN OSV — load_malware_db reads exactly this for target:dependency|tool
    {
      "package": { "ecosystem": "PyPI", "name": "litellm" },   // OSV-canonical ecosystem string (PyPI/npm/Go/Maven/RubyGems/crates.io)
      "versions": ["1.82.7", "1.82.8"]     // explicit list → those versions; absent/[] → whole-package wildcard "*"
    }
  ],
  "references": [                          // REQUIRED ≥1 GHSA/OSV provenance URL (wh-562 Gate-2 asserts this)
    { "type": "ADVISORY", "url": "https://github.com/advisories/GHSA-5mg7-485q-xm76" }
  ],
  "database_specific": {                   // OSV's sanctioned namespace for non-standard fields — Gate-2-checked, loader-ignored
    "retrieved": "2026-06-10",             // when the feeder fetched it (provenance)
    "watchlist_confidence": "low"          // AUTO-EXTRACTED candidates land low; human review can raise
  }
}
```

**The `ecosystem` key — what it does and does NOT do today (the RQ3 residual, file-grounded).**
`ecosystem` lives in `affected[].package.ecosystem` (populated by OSSF), but `_accumulate`
(`malware_db.py:71-91`) reads `package.get("name")` + `versions` ONLY and **discards `ecosystem`**,
collapsing to `{name: set[versions]}` (verified: `ecosystem` appears in `malware_db.py` solely in the `:11`
docstring, never in code). And `signal_s8` matches **by name only** (`supply_chain.py:1042`,
`if name not in malware_db`). So **`ecosystem` is carried in the schema for provenance + future
disambiguation, but is NOT part of the match key today.**
DECISION: **keep `ecosystem` mandatory in the schema** (it is the OSV-canonical disambiguator and the dir
path `osv/<ecosystem>/`), and record an **accepted residual**: a name-collision across ecosystems (e.g. an
npm `foo` and a PyPI `foo`, only one compromised) can produce a cross-ecosystem name match. This is
**fail-safe** (S8 is a human-triaged candidate, never a block — `supply_chain.py:1030-1036`), low-likelihood
(distinct registries rarely share an exact name + a real compromise), and closing it is an *optional*
`load_malware_db` upgrade to a `{(ecosystem,name): versions}` key — a **DRAFT follow-up**, NOT this wave (it
would touch the frozen-by-tests loader + S8 signature; out of this spike's lane).

**Parked nit #1 — Gemfile.lock platform suffix (RESOLVED here as an ecosystem-aware normalization rule).**
`_resolved_gem` (`supply_chain.py:535-547`) returns the Gemfile.lock `specs:` version **verbatim** —
`nokogiri (1.15.4-arm64-darwin)` → `resolved="1.15.4-arm64-darwin"` — while OSV-RubyGems records the
**canonical** `1.15.4`. When ONLY a platform row is present, `is_known_bad("nokogiri", "1.15.4-arm64-darwin",
db)` misses the canonical `1.15.4` entry (a narrow FN; the generic row wins when both are present — probed,
ticket NOTES). **Schema-side rule (the fix's home):** RubyGems watchlist entries store the **canonical**
version only (mirrors how OSV-RubyGems publishes), and the *resolution* side strips the trailing
`-<platform>` suffix before matching. Since the schema mandates canonical versions, the one-line code fix is
small and additive (strip `-<platform>` in `_resolved_gem`, or normalize at the `is_known_bad` call) — but it
is a **deps-scan code change (frozen-by-tests area), so it ships as a DRAFT follow-up**, not this spike. The
schema's contract ("RubyGems = OSV-canonical versions") is what makes that fix unambiguous.

**Parked nit #2 — Maven one-level `${prop}` resolution (accepted FN class, documented).** `signal_s8`'s
Maven resolution path resolves `${prop}` **one level** (a chained `${a}→${b}` stays wildcard-only; probed
loop-safe, ticket NOTES). DECISION: **accept this as a known FN class** in the schema notes — a deeply-indirected
Maven version that the resolver leaves unresolved simply falls to the wildcard-only path (flags only on a `"*"`
DB entry, never a specific-version FP). No schema change; a one-line docstring note belongs on `_resolved`
the next time that area is touched (carry into the same deps-scan DRAFT follow-up as nit #1).

**The `target` tag — three kinds, one shape:**

| `target` | Read by | `affected[]` used? | Extra block |
|---|---|---|---|
| `dependency` | `load_malware_db` → `signal_s8` (inner-loop dep check) | YES (name+versions) | — |
| `tool` | `load_malware_db` (the agent's OWN tools — wh-562's surface; same loader) | YES (name+versions) | — |
| `extension` | the NEW ide-hygiene module (RQ4) — NOT load_malware_db | NO (ignored by loader) | `extension` block (below) |

**The `extension` block (target:extension only).** A VS Code / OpenVSX extension is identified by
`marketplace + publisher.name + version`, NOT a package-registry coordinate, so it gets its own block
**outside `affected[]`** (so `load_malware_db` ignores it cleanly — it only reads `affected`):

```jsonc
{
  "id": "GHSA-c9j4-9m59-847w",
  "target": "extension",
  "affected": [],                                  // empty → load_malware_db skips it (no package coordinate)
  "extension": {
    "marketplace": "openvsx",                       // openvsx | vscode  (the registry the id resolves against)
    "id": "nrwl.angular-console",                   // <publisher>.<name> — the canonical extension id `code --list-extensions` prints
    "bad_versions": ["18.95.0"]                     // explicit list; [] or absent → whole-extension wildcard "*"
  },
  "references": [{ "type": "ADVISORY",
    "url": "https://github.com/nrwl/nx-console/security/advisories/GHSA-c9j4-9m59-847w" }],
  "database_specific": { "retrieved": "2026-06-10", "watchlist_confidence": "low" }
}
```

**`repos` kind — DROPPED (decision).** The ~3,800-repo blast radius (RQ1) is an *outcome IoC*, not a
**watchlist-matchable** local artifact: a per-user tool cannot meaningfully diff "is one of my repos on a
leaked-repo list" without enumerating + transmitting the user's repo inventory (a privacy violation, RQ7) and
the list is GitHub-internal, not a stable public feed. DECISION: **no `repos` target kind.** The repo-theft
lesson is captured by scanning the *vector* (the poisoned extension, target:extension) — which is the
matchable, preventable surface — not the *outcome*.

**Digest fields (the force-push case) — decision.** ADR-006 / ADR-024's admission arm pins **tools** by
SHA/digest. The *watchlist DATA* schema does **not** carry a per-entry artifact digest: a watchlist entry
records "package@version is known-bad" (an identity), not "verify this artifact's digest" (that is the
CONTAIN admission gate's job on the agent's own tools — strategy doc:166-188, a *different* object kind, three
gates never merged). The **force-push lesson applies to the snapshot pin, not the entry**: the OSSF snapshot
itself is pinned to a **full 40-hex commit SHA** and PIN-verified (`fetch-snapshot.sh:14-16,37`; MALWARE-DB.md:48
records SHA `174a862b…`). So: **no digest field on watchlist entries; the snapshot is SHA-pinned** — that is
where force-push resistance lives. (A future image/binary IoC — "this *digest* is malicious" — would extend
`database_specific`, but no 2026 campaign in RQ1 needs it.)

> **RQ2 DECISION.** Plain-OSV-superset (`load_malware_db` parses target:dependency|tool unchanged) + a
> required `target` tag + an `extension` block for target:extension (outside `affected[]`, loader-ignored) +
> `references[]` (≥1 GHSA/OSV URL, Gate-2-asserted) + `database_specific.{retrieved,watchlist_confidence}`.
> `ecosystem` mandatory (provenance + dir path) but **not** the match key today (cross-ecosystem name
> collision = accepted fail-safe residual). RubyGems entries store **canonical** versions (resolves parked
> nit #1 schema-side); Maven deep-`${prop}` = accepted FN class (parked nit #2). **`repos` kind DROPPED.**
> **No per-entry digest** — force-push resistance lives in the SHA-pinned snapshot.

## THE OSSF FEEDER — the PRIMARY deliverable (closes gap G1)

**The gap (file-grounded).** `/sec-kb-refresh` does NOT feed the watchlist today: `poll_feeds.py:69`
`PARSERS={osv,atlas,atom}` has no OSSF parser; `:23` `VALID_CLASSES` is 5 KB stems (no supply-chain); the
module **renders KB markdown only** (`to_candidate_entry` + `render_entry`, `:82-107`). Yet `MALWARE-DB.md:79`
+ `deps-scan/SKILL.md:110` NAME `/sec-kb-refresh` as the re-pin cadence — **prose with zero code.** The feeder
closes this.

**Design — extend, don't fork (reuses the `poll_feeds` parse→diff→render pipeline).**

1. **The parser — `parse_ossf(raw) -> list[dict]`, added to `PARSERS` (`poll_feeds.py:69`).**
   *Input shape:* one OSSF `malicious-packages` **OSV JSON doc** (the same shape `load_malware_db` reads —
   `affected[].package.{ecosystem,name}` + `versions`, MALWARE-DB.md:66-71), read from a **pre-fetched, pinned
   snapshot** (`osv/<ecosystem>/…`), never the network (the analyze half of the split). It emits the
   `poll_feeds` item dict — but with the watchlist fields carried through:
   ```python
   {"feed": "ossf", "id": <osv-id>, "title": <osv-id>,
    "url": <references[].url or "https://osv.dev/vulnerability/"+id>,
    "target": "dependency", "ecosystem": <package.ecosystem>,
    "package": <package.name>, "versions": <versions or ["*"]>}
   ```
   It reuses the SAME `json.loads` + `.get()` defensive style as `parse_osv` (`:26-34`) — untrusted data
   parsed as **values**, never executed (Rule-of-Two; the OSSF tree is OSV metadata, not malware —
   `fetch-snapshot.sh:8-9`).

2. **The candidate writer — `to_watchlist_candidate(item) -> dict`, a PARALLEL emit path (DECISION below).**
   It emits the RQ2 OSV-superset doc carrying **ONLY** `{id(==source advisory), target, affected:[{package,
   versions}], references:[{url}], database_specific:{retrieved}}` — **never free-form advisory prose**
   (no summary, no description; the writer doesn't even read OSV `details`). `watchlist_confidence:"low"` +
   the human-gated draft-PR (below) are the safety rails.

3. **`VALID_CLASSES` — a PARALLEL emit path, NOT a new class (DECISION).** `to_candidate_entry` **hard-asserts**
   `technique_class in VALID_CLASSES` at `poll_feeds.py:84`, and shapes a *KB technique* entry
   (`AISEC-<CLASS>-NNN`, `technique_class`, `detections`, maps to `ai-llm.md`). A watchlist entry has **no
   technique_class** and a totally different shape (an OSV doc). Bolting "supply-chain" into `VALID_CLASSES`
   would force a KB-shaped entry onto watchlist DATA — a category error (it would render to
   `ai-attack-kb/` markdown, the wrong lane). So: **`to_watchlist_candidate` is a separate function emitting
   OSV-JSON, leaving `VALID_CLASSES` + `to_candidate_entry` untouched.** The two paths share only the
   `parse → poll(diff) → emit` plumbing. (This mirrors the loop-leverage finding: KB edits ride Gate-1; DATA
   edits ride wh-562's Gate-2 — *different verdicts, different shapes, never merged*.)

4. **The fetch/analyze split — an ADR-024 REQUIREMENT (cite ADR-024).** ADR-024 ratified CONTAIN: fetch
   (network-ON) is split from analyze (network-OFF). The feeder honors it by construction:
   **FETCH** = the existing `docker/deps-scan-sandbox/fetch-snapshot.sh` (sealed, network-ON, throwaway,
   clones+SHA-pins the OSSF `osv/` tree — `:24-41`); **ANALYZE** = `parse_ossf` + `to_watchlist_candidate`
   run network-OFF over that pinned snapshot. `poll_feeds.py`'s module docstring already states "NO network
   here — the caller fetches" (`:5-7`) — the feeder slots into that exact contract. **No new fetch code** —
   the ratified split is reused.

5. **Rule-of-Two — preserved (white-hacker dogfood).** `FEED_HOSTS` already contains `github.com` +
   `raw.githubusercontent.com` (`confine_self_writes.py:41,44`); **git is NOT a `NET_VERB`**
   (`:51` — curl/wget/nc/…, not git), so the clone is not even an egress-gated verb. The analyze half holds
   the untrusted OSV data but has **no egress** (network-OFF) and **no secrets** co-located → the Agents Rule
   of Two holds (never untrusted-input + egress + secrets at once). Poisoned-feed safety is the **same
   `safe_dump` pattern** the KB path proves: a crafted OSV `summary`/`details` cannot inject a YAML key
   because the writer (a) never copies prose into the entry and (b) renders via `yaml.safe_dump` if serialized
   to YAML — `test_poll_feeds.py:66-95` pins exactly this invariant for the KB path; the feeder's TDD adds the
   analogous test (a poisoned OSSF doc with an `injected_key` in `details` produces a candidate with **only**
   the whitelisted keys).

6. **Gate-2 (cross-ref wh-562) + the human-gated draft PR (ADR-012).** Every candidate the writer emits is
   **draft-PR only, never auto-merged** (ADR-012; `poll_feeds.py:7` "Drafts go to a PR; never auto-merged").
   **wh-562's Gate-2** is the deterministic admission gate for the DATA entry: per-entry GHSA/OSV provenance
   URL present (the `references[]` the writer always emits) + OSV-schema validity + regression-green (no LLM,
   no RNG — Rule 5; strategy doc:158-166). **Schema-first ordering:** Gate-2's schema lands **before** this
   feeder writes entries (the feeder targets wh-562's validated shape; this RQ2 schema is the contract both
   sides build to). The watchlist write target must also be added to `confine_self_writes` `ALLOW_SEGMENTS`
   (`:40`) so the outer loop can write it — that wiring is **wh-562's** lane (it owns the write-lane +
   Gate-2), named here as the dependency.

> **FEEDER DECISION.** Add `parse_ossf` to `poll_feeds.PARSERS` (reads the pinned OSSF OSV snapshot,
> network-OFF) + a **parallel** `to_watchlist_candidate` writer emitting ONLY `{source-url, package, version,
> ecosystem, retrieved}` in the RQ2 OSV-superset shape — **leaving `VALID_CLASSES`/`to_candidate_entry`
> untouched** (a new emit path, not a new class). FETCH = `fetch-snapshot.sh` (sealed, SHA-pinned); ANALYZE =
> network-OFF parse/emit — the ADR-024 split, reused. Draft-PR + Gate-2 (wh-562) gate every entry; Rule-of-Two
> holds (git ∉ NET_VERB, analyze has no egress, `safe_dump`).

## RQ3 — version-aware S8: DELIVERED upstream (only the schema aspects remain here)

**Status: DELIVERED** by wh-4k9 + wh-7o1 (both CLOSED). `signal_s8` (`supply_chain.py:1015-1050`) is
**version-aware** across npm/PyPI/Go/Maven/RubyGems/crates.io + Pipfile: it matches the lockfile-`resolved`
(or exact manifest pin) version via `is_known_bad(name, version, db)` (`malware_db.py:48`), and flags an
unresolved range ONLY on a `"*"` wildcard entry (`supply_chain.py:1044-1049`) — the name-only FP bomb is
**gone** (the body's earlier `:744/:754 name-only` references are HISTORICAL). The only RQ3-adjacent residual
is the **ecosystem-key disambiguation + digest** question — both resolved in RQ2 above (ecosystem carried but
not the match key = accepted residual; no per-entry digest).

> **RQ3 DECISION.** No work here — version-aware S8 is shipped (`supply_chain.py:1015`). The ecosystem/digest
> schema aspects are folded into RQ2.

## RQ4 — the ide-hygiene extension scan (a NEW capability port + a thin module)

**The port (ADR-015 — capability, not brand).** Add an `ide-hygiene` capability whose port is:
```python
list_installed_extensions() -> list[dict]   # [{"marketplace": "vscode|openvsx", "id": "<pub>.<name>", "version": "x.y.z"}]
```
This mirrors the existing capability-detection pattern: `detect_available_tools` (`detect_tools.py:322`) is a
`shutil.which`-driven, degrade-clean enumerator — the ide-hygiene enumerator is the same idea for extensions.

**Enumeration (deterministic; no LLM — Rule 5):**
1. **Primary:** `code --list-extensions --show-versions` (and the same for `cursor`/`codium` if present) —
   prints `<pub>.<name>@<version>` lines, parsed verbatim. Resolved via `shutil.which("code")` (the
   `detect_available_tools` pattern).
2. **On-disk fallback (no `code` on PATH):** read the extensions dir manifests — `~/.vscode/extensions/*/package.json`
   (and `~/.cursor/extensions/`, `~/.vscode-oss/extensions/` for Codium/OpenVSX) → `{publisher}.{name}@{version}`
   from each `package.json` (`name`,`publisher`,`version`). Plain stdlib JSON read, treated as **untrusted
   data** (parse, never execute — same posture as `_read_osv`).
3. **The match:** for each enumerated extension, look it up in the `target:extension` watchlist entries by
   `(marketplace, id)` and check `version ∈ bad_versions or "*"`. **Reuse `is_known_bad`** semantics
   (`malware_db.py:48` — exact set membership or `"*"`, never substring) by building a
   `{id: set[bad_versions]}` map from the extension block — the SAME exact-match logic, so the FP-resistance
   is inherited.

**Degrade (ADR-003 — the floor is "nothing", and that's valid).** No `code` on PATH **and** no extensions
dir on disk → the capability is **unavailable**: emit **zero** findings, record `ide-hygiene` in
`tools_unavailable`, `tool_assisted:false`. **Never block, never error.** (Identical contract to S8's
malware-db degrade — MALWARE-DB.md:9-14.)

**Where it lives (LEAN — DECISION).** A **thin NEW module behind the port**, NOT bolted into deps-scan
(which is *target-repo* dependency scanning; extensions are a *machine* surface → different trust boundary,
RQ7). Candidate home: a small `ext_scan.py` in a new `ide-hygiene` skill (or under `_shared` if a second
consumer appears — but today only one consumer exists, so per Policy 2 / ADR-015 it starts as one thin
module, no premature `_shared` port). It imports nothing from deps-scan except the `is_known_bad` *idea*
(re-implement the 3-line exact-match, or import `malware_db.is_known_bad` directly — the latter if the path
shim is clean; decide at impl).

**PoC — NOT needed (DECISION; `docs/research/poc-ext-scan/` intentionally NOT created).** The two
load-bearing facts are already proven by existing code: (a) the `shutil.which` + degrade-clean enumerator
pattern is `detect_available_tools` (`detect_tools.py:322`, tested), and (b) exact-version matching is
`is_known_bad` (`malware_db.py:48`, tested). `code --list-extensions --show-versions` is a documented,
stable VS Code CLI contract (publisher.name@version), and the on-disk `package.json` shape is the standard
VS Code extension manifest — neither is novel enough to warrant a PoC. The impl follow-up's TDD (fixtures: a
fake `code` stub + a fixture extensions dir) is the right place to pin the parse, not a spike PoC. **No PoC
artifact is load-bearing here.**

> **RQ4 DECISION.** A new `ide-hygiene` capability + port `list_installed_extensions()`; enumerate via
> `code --list-extensions --show-versions` with an on-disk `~/.vscode/extensions/*/package.json` fallback;
> match `(marketplace,id,version)` vs `target:extension` entries reusing `is_known_bad` exact-set semantics;
> degrade to `tools_unavailable` + zero findings when neither `code` nor a dir exists (ADR-003). A **thin new
> module**, not part of deps-scan. **No PoC needed.**

## RQ5 — cadence: on-demand command + a FAST bounded SessionStart drift check (NO daemon/cron/loop)

**The standing aversion (honored).** No daemon, no cron, no `/loop`/`ScheduleWakeup` — work is driven on
demand or at natural hook points, never on a background timer.

**The recommendation (two surfaces + one opt-in):**
1. **On-demand command** — a `/sec-supply-check` (or a `deps-scan`/ide-hygiene CLI flag) the user runs
   deliberately: enumerates the target's already-parsed deps + the installed extensions, matches both vs the
   **pinned** watchlist, prints matches. Unbounded depth is fine here (the user asked for it).
2. **A FAST, BOUNDED SessionStart drift check** — at session start, a check whose cost is **strictly
   bounded**: (a) the **pinned watchlist** already on disk (no fetch — analyze-only), (b) the **already-parsed
   lockfile** for the current repo (deps-scan already parses it — reuse, don't re-walk), (c) **one**
   `code --list-extensions --show-versions` invocation (a single subprocess, bounded timeout). **The bound,
   stated explicitly: pinned-watchlist-read + one-lockfile-parse + one-extensions-listing. NO recursive HOME
   walk, NO network, NO per-ecosystem full-tree load** (the OSSF tree is ~895 MB / 201k npm entries —
   MALWARE-DB.md:57; SessionStart must point at the **small per-target subset**, never the full tree). Output
   is **factual `additionalContext`** (ADR-017, the <10 KB / <8000-byte cap the companion already respects),
   silent-degrade (no `code` / no dir → emit nothing). Resource-discipline: a single bounded subprocess, no
   fan-out, no pool (CLAUDE.md § Resource discipline).
3. **CI opt-in** — the same check as a CI step for teams that want a gate; off by default.

**Why SessionStart and not CI-only.** The machine surface (extensions, RQ4/RQ7) is a *developer-workstation*
property, not a repo property — CI runs on ephemeral runners that have **no** developer extensions installed,
so a CI-only check **cannot see** the highest-value surface (the Nx-Console-class vector). SessionStart is
where the developer's actual machine state is observable. The bound makes it cheap enough to be free.

> **RQ5 DECISION.** On-demand `/sec-supply-check` (unbounded, deliberate) **+** a FAST bounded SessionStart
> drift check (pinned watchlist + already-parsed lockfile + ONE `code --list-extensions`; no recursive HOME
> walk, no network, no full-tree load; factual `additionalContext` ≤8 KB; silent-degrade) **+** CI opt-in.
> **No daemon/cron/loop.**

## RQ6 — sec-init wiring (HANDOFF #1 to wh-0vx)

**The ask (NAMED, not schema-edited — per HANDOFF #1).** wh-0vx OWNS `project_profile_schema.json`; this
spike must **not** propose schema edits — it **names the factual companion key** it wants and records the
exact factual sentence shape for wh-0vx (or a follow-up) to host.

- **The key I want:** **`supply_chain_check`** — a single factual summary string (or a small object if
  wh-0vx prefers; a string is sufficient).
- **The exact factual sentence shape** (FACTUAL, never imperative — `init_profile.py`'s `is_factual` rejects
  imperatives; this must pass `write_profile`'s injection-safety refusal (init_profile.py, the is_factual gate)):
  > `"0 of N installed dependencies and 0 of M installed IDE extensions match the 2026-06 supply-chain watchlist (pin <SHA8>)."`
  - It states a **count and a result**, no instruction — passes `is_factual` (it doesn't start with
    always/never/you must/ignore/disregard/do not).
  - Concrete example: `"0 of 214 installed dependencies and 0 of 37 installed IDE extensions match the 2026-06 supply-chain watchlist (pin 174a862b)."`
- **The watchlist DATA stays in `reference/`** (the pinned OSSF snapshot + the watchlist file), **never** in
  the committed profile — the profile carries only the **factual one-line result**, exactly as it already
  carries `tools_unavailable`/`present_capabilities` summaries, not the underlying tool inventories. (This
  keeps RQ7's data-minimization: the profile never stores the extension inventory, only the match *result*.)
- **Schema change DEFERRED to dev-wh-0vx / a follow-up.** Per HANDOFF #1: I do not edit the schema. If
  wh-0vx's in-flight key set (`package_managers`, `build_test_commands`, `in_scope_focus`) lands first, the
  TL relays it and `supply_chain_check` is added in the same additive pass (old profiles still validate —
  it's an optional key). The DRAFT follow-up below carves the wiring impl.

> **RQ6 DECISION.** NAME a factual companion key **`supply_chain_check`** holding one factual sentence
> ("0 of N deps and 0 of M extensions match the 2026-06 watchlist (pin <SHA8>)"); watchlist DATA stays in
> `reference/`, never the committed profile; the schema edit is **deferred to wh-0vx** (additive, optional
> key — old profiles validate).

## RQ7 — privacy boundary (reconciled with wh-81y)

Scanning installed IDE extensions = scanning the **user's machine**, a broader trust boundary than reviewing
a target repo. The boundary, four invariants:

1. **One-time explicit consent.** The machine/extension scan runs only after a one-time explicit opt-in
   (recorded once, like the sec-init onboarding's one-time flow). No silent first-run machine enumeration.
2. **Read-only + no-egress.** The scan reads `code --list-extensions` / on-disk manifests and matches against
   the **offline pinned** watchlist — **never** the network during analysis (the ADR-024 analyze half is
   network-OFF). It cannot exfiltrate because it has no egress (Rule-of-Two: the analyze step holds the
   inventory but has no network + no secrets).
3. **Data minimization — surface MATCHES only, never the inventory.** The scan **never stores or transmits
   the extension/dependency inventory.** It surfaces only the **matches** (the compromised items found, with
   their advisory URL). The companion's `supply_chain_check` (RQ6) records only a **count + result**, not the
   list. A clean machine leaves **zero** inventory data anywhere.
4. **Public-intel-in, user-data-never-out.** The only data that crosses the boundary is **public threat
   intel coming IN** (the pinned OSSF/GHSA watchlist, fetched once in the sealed FETCH step). **No user data
   ever goes OUT** — not to a server, not to the watchlist, not to a log. This is the dual of the feeder's
   Rule-of-Two: the feeder fetches public intel with egress-but-no-user-data; the scan matches user data with
   no-egress-at-all.

This reconciles with wh-81y (the privacy spike): wh-81y owns the broader machine-scan privacy policy; this RQ
states the **extension-scan-specific** boundary consistent with it. If wh-81y defines a consent-storage
mechanism, the ide-hygiene opt-in reuses it (named dependency, not a second mechanism).

> **RQ7 DECISION.** One-time explicit consent; read-only + no-egress (offline pinned watchlist); surface
> **matches only**, never store/transmit the inventory; public-intel-IN / user-data-never-OUT. Reuses
> wh-81y's consent mechanism if defined.

## Decisions at a glance

| RQ | Decision (one line) |
|---|---|
| RQ2 | Plain-OSV-superset (`load_malware_db` parses target:dependency\|tool unchanged) + `target` tag + an `extension` block (outside `affected[]`) + `references[]` + `database_specific.{retrieved,watchlist_confidence}`; `ecosystem` mandatory but NOT the match key (cross-ecosystem collision = accepted fail-safe residual); RubyGems = canonical versions (resolves nit #1); Maven deep-prop = accepted FN (nit #2); **`repos` DROPPED**; **no per-entry digest** (snapshot is SHA-pinned). |
| FEEDER | `parse_ossf` → `PARSERS` (reads the pinned OSSF snapshot, network-OFF) + a **parallel** `to_watchlist_candidate` writer (only {source-url,package,version,ecosystem,retrieved}); `VALID_CLASSES`/`to_candidate_entry` untouched (new emit path, not a new class); FETCH=`fetch-snapshot.sh` / ANALYZE network-OFF (ADR-024 split); draft-PR + wh-562 Gate-2 gate every entry; Rule-of-Two holds (git ∉ NET_VERB, `safe_dump`). |
| RQ3 | DELIVERED — `signal_s8` (`supply_chain.py:1015`) is version-aware across 6 ecosystems; no work here; ecosystem/digest folded into RQ2. |
| RQ4 | New `ide-hygiene` capability + port `list_installed_extensions()`; enumerate `code --list-extensions --show-versions` + on-disk `package.json` fallback; match vs `target:extension` reusing `is_known_bad`; degrade to `tools_unavailable` (ADR-003); a thin new module, not deps-scan; **no PoC needed**. |
| RQ5 | On-demand `/sec-supply-check` + a FAST bounded SessionStart drift check (pinned watchlist + already-parsed lockfile + ONE `code --list-extensions`; no HOME walk, no network, no full-tree load; factual ≤8 KB; silent-degrade) + CI opt-in; **no daemon/cron/loop**. |
| RQ6 | NAME a factual companion key **`supply_chain_check`** ("0 of N deps and 0 of M extensions match the 2026-06 watchlist (pin <SHA8>)"); watchlist DATA stays in `reference/`; schema edit **deferred to wh-0vx** (additive optional key). |
| RQ7 | One-time consent; read-only + no-egress; surface MATCHES only, never the inventory; public-intel-IN / user-data-never-OUT; reuses wh-81y's consent mechanism. |

## Draft follow-up tickets (for `/design-ticket`)

> Drafts only — **NOT** `bd create`d this wave (launch override #3). Each is self-contained for grooming.
> They fold into the epic wh-hxt; the watchlist schema/Gate-2 they target is wh-562's; the file is wh-k6l's.

### (a) OSSF feeder: `parse_ossf` + `to_watchlist_candidate` in `poll_feeds` (the PRIMARY impl)
- **Type:** task (impl) · **Epic:** wh-hxt · **Blocked-by:** wh-562 (the Gate-2 schema/validator must land
  first — schema-first ordering) + wh-k6l (the watchlist file location) + the `ALLOW_SEGMENTS` write-lane
  entry (wh-562's lane).
- **Goal:** wire the FEEDER decision — add `parse_ossf(raw)` to `poll_feeds.PARSERS` (reads the pinned OSSF
  OSV snapshot, network-OFF) + a **parallel** `to_watchlist_candidate(item)` emitting the RQ2 OSV-superset doc
  with ONLY `{id, target:"dependency", affected:[{package:{ecosystem,name},versions}], references:[{url}],
  database_specific:{retrieved,watchlist_confidence:"low"}}`. Leave `VALID_CLASSES`/`to_candidate_entry`
  untouched. Draft-PR output; never auto-merge.
- **Files:** `sec-kb-refresh/scripts/poll_feeds.py` (add the parser + the writer); `scripts/tests/test_poll_feeds.py`
  (TDD); a neutralized OSSF OSV fixture under `scripts/tests/fixtures/`.
- **ACs:** `parse_ossf` parses a pinned OSSF OSV doc → the watchlist item dict (name+ecosystem+versions
  carried) · `to_watchlist_candidate` emits ONLY the whitelisted keys (no `details`/prose) · a **poisoned
  OSSF doc** (an `injected_key` in `details`) yields a candidate with exactly the whitelisted keys
  (mirrors `test_poll_feeds.py:66-95`) · output is draft-PR-shaped, network-OFF · every candidate carries ≥1
  GHSA/OSV `references[].url` (Gate-2-ready) · gate green (`pytest sec-kb-refresh/scripts/tests`).

### (b) ide-hygiene extension scan: the capability port + a thin module
- **Type:** task (impl) · **Epic:** wh-hxt · **Blocked-by:** the RQ2 schema (`target:extension` shape) — so
  the matcher has a shape to read. Independent of (a).
- **Goal:** implement RQ4 — a new `ide-hygiene` capability with port `list_installed_extensions() ->
  [{marketplace,id,version}]`; enumerate `code --list-extensions --show-versions` (+ `cursor`/`codium`) with
  an on-disk `~/.vscode/extensions/*/package.json` fallback; match `(marketplace,id,version)` vs
  `target:extension` watchlist entries reusing `is_known_bad` exact-set semantics; degrade to
  `tools_unavailable` + zero findings (ADR-003) when neither `code` nor a dir exists.
- **Files:** a NEW thin module (`ext_scan.py` in a new `ide-hygiene` skill) + `pyproject.toml`/`conftest.py`/
  `tests/`; reuse `malware_db.is_known_bad`. Register the capability in the registry/`SCANNER_PREFERENCE`-style
  map if the detection layer needs it.
- **ACs:** a fixture `code` stub (printing `pub.name@ver` lines) → the port returns the parsed list · the
  on-disk `package.json` fallback fires when `code` is absent · a known-bad extension+version flags; a
  known-bad name at a *clean* version does NOT (exact-set, not substring) · no `code` + no dir → zero
  findings + `ide-hygiene` in `tools_unavailable`, never raises · gate green.

### (c) The cadence surfaces: `/sec-supply-check` + the bounded SessionStart drift check
- **Type:** task (impl) · **Epic:** wh-hxt · **Blocked-by:** (b) (needs the extension scan) + the deps-scan
  watchlist match (S8, already shipped).
- **Goal:** implement RQ5 — an on-demand `/sec-supply-check` command (enumerate already-parsed deps +
  installed extensions, match vs the pinned watchlist, print matches) **and** a FAST **bounded** SessionStart
  drift check (pinned-watchlist + already-parsed-lockfile + ONE `code --list-extensions`; **no** recursive
  HOME walk, **no** network, **no** full-tree load — point at the small per-target subset; factual
  `additionalContext` ≤8 KB; silent-degrade). CI step opt-in (off by default).
- **Files:** a command md under `commands/` (or a deps-scan/ide-hygiene CLI flag); a SessionStart hook
  registration; tests asserting the bound (no HOME walk, no network call) + the factual-context cap.
- **ACs:** `/sec-supply-check` prints matches for a fixture with a known-bad dep + a known-bad extension ·
  the SessionStart check reads only {pinned watchlist, the current lockfile, one extensions listing} —
  asserted by test (no recursive walk, no network) · emits factual `additionalContext` ≤8 KB · silent-degrade
  when `code`/dir/snapshot absent · CI step is opt-in · gate green.

### (d) sec-init companion wiring: `supply_chain_check` factual line (HANDOFF #1 follow-up)
- **Type:** task (impl) · **Epic:** wh-hxt · **Blocked-by:** wh-0vx (owns the schema) + (b)/(c) (produce the
  match result). *(May be folded INTO wh-0vx if it lands after the schema keys.)*
- **Goal:** implement RQ6 — add the optional factual `supply_chain_check` key to the companion (additive,
  `additionalProperties:false`-compatible, old profiles still validate) carrying the factual sentence
  ("0 of N deps and 0 of M extensions match the 2026-06 watchlist (pin <SHA8>)"); build it in
  `init_profile.build_profile` from the match result; it MUST pass `is_factual` + `write_profile`'s
  injection-safety check. Watchlist DATA stays in `reference/`.
- **Files:** `sec-init/scripts/project_profile_schema.json` (additive key — **wh-0vx's lane**);
  `sec-init/scripts/init_profile.py` (`build_profile`); `scripts/tests/` (the key validates; the sentence is
  factual; a profile with it is < 8000 bytes).
- **ACs:** the schema accepts a profile WITH `supply_chain_check` and one WITHOUT (additive) · the generated
  sentence passes `is_factual` (`init_profile.py`, by symbol — the gate moved under wh-0vx's hardening) · `write_profile` writes it (injection-safe) · the
  profile stays < 8000 bytes (SessionStart cap) · old profiles still validate · gate green.

## References (primary first)

- GHSA-5mg7-485q-xm76 (LiteLLM) — https://github.com/advisories/GHSA-5mg7-485q-xm76
- GHSA-c9j4-9m59-847w / CVE-2026-48027 (Nx Console) — https://github.com/nrwl/nx-console/security/advisories/GHSA-c9j4-9m59-847w
- GHSA-69fq-xp46-6x23 / CVE-2026-33634 (Trivy) — https://github.com/advisories/GHSA-69fq-xp46-6x23
- TanStack postmortem — https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- Wiz "Mini Shai-Hulud" — https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
- Nx postmortem — https://nx.dev/blog/nx-console-v18-95-0-postmortem
- GitHub repo-breach link — https://www.bleepingcomputer.com/news/security/github-links-repo-breach-to-tanstack-npm-supply-chain-attack/
- OSSF malicious-packages (Apache-2.0, OSV) — https://github.com/ossf/malicious-packages

### Repo anchors (verified 2026-06-10 against the uncommitted wave-1b tree)
- `malware_db.py:27` `load_malware_db` (`{name:set[versions]}`, drops `ecosystem`), `:48` `is_known_bad`
  (exact-set/`"*"`, never substring), `:62-91` `_read_osv`/`_accumulate` (tolerates unknown OSV keys).
- `supply_chain.py:1015-1050` `signal_s8` (VERSION-AWARE, 6 ecosystems; name-only match key at `:1042`);
  `:535-547` `_resolved_gem` (returns the platform-suffixed version verbatim — parked nit #1).
- `poll_feeds.py:23` `VALID_CLASSES` (5 KB stems), `:69` `PARSERS={osv,atlas,atom}`, `:82-107`
  `to_candidate_entry`/`render_entry` (`:84` hard-asserts `technique_class in VALID_CLASSES` — the
  parallel-emit-path decision), `:5-7` "NO network here — the caller fetches".
- `test_poll_feeds.py:66-95` the poisoned-feed `safe_dump`-cannot-inject pattern (the feeder's TDD reuses it).
- `confine_self_writes.py:41,44` `FEED_HOSTS` (github.com + raw.githubusercontent.com), `:51` `NET_VERBS`
  (git ∉ NET_VERBS), `:40` `ALLOW_SEGMENTS` (the watchlist write-lane entry — wh-562's lane).
- `fetch-snapshot.sh:8-9,14-16,24-41` the ratified sealed FETCH (network-ON, SHA-pin, throwaway).
- `MALWARE-DB.md:18,48,57,66-71` OSSF `osv/<ecosystem>/` layout + the pinned SHA `174a862b…` + the ~895 MB
  full-tree caveat (RQ5's bound).
- `init_profile.py` — `is_factual`, `build_profile`, `write_profile` (injection-safety refusal);
  `project_profile_schema.json:7` `additionalProperties:false` (RQ6 additive-key constraint).
- `detect_tools.py:322` `detect_available_tools` (the `shutil.which` degrade-clean enumerator pattern RQ4 mirrors).
- `deps-scan/SKILL.md:110`, `sec-init/SKILL.md`, `sec-kb-refresh/SKILL.md` (the `/sec-kb-refresh` re-pin prose
  the feeder closes).

## Follow-up

- [x] Campaign verification (RQ1) recorded here (FINAL).
- [x] wh-5es — RQ2 OSV-superset schema FINALIZED; the OSSF feeder designed; RQ3 confirmed DELIVERED; RQ4–RQ7
  each → a DECISION (above). **No separate ADR** — folds into wh-562's one watchlist-mechanism ADR.
- [ ] Impl (DRAFT follow-ups above, `/design-ticket`): (a) the OSSF feeder · (b) the ide-hygiene extension
  scan · (c) the cadence surfaces · (d) the sec-init `supply_chain_check` wiring.
