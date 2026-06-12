# MONITOR staleness signal — release-age + archived/EOL GitHub-API fields, thresholds, verdict shape

**Date:** 2026-06-12 · **Status:** definition (the signal the wh-5es feed arm consumes; ADR-012 human-gated)
**Owner:** ping@jaigouk.kim · **Ticket:** wh-hxt.18 (split from wh-hxt.1, part 2 of 3) · **G6** of
`docs/research/20260609_supply_chain_loop_leverage.md:254`

## Scope — what this defines and what it does NOT

This is the **DEFINITION** the MONITOR stage's *staleness/health* arm runs on
(`docs/research/20260609_supply_chain_tooling_strategy.md:100-105`, signal (b)). It specifies, for a tool
already in the registry/watchlist:

1. the **GitHub-REST-API input fields** a staleness check reads,
2. the **deterministic thresholds** that turn those fields into a verdict (a pure rule — no runtime
   judgment call, Policy 5), and
3. the **output shape** — one *staleness verdict* per tool / watchlist row.

It is the **input/threshold/output contract** for a future `staleness` (a.k.a. `github`) parser that plugs
into `poll_feeds.py` `PARSERS` (`plugins/white-hacker/skills/sec-kb-refresh/scripts/poll_feeds.py:69`).
It does **NOT** implement the network fetch — the live polling plumbing (egress-confined fetch, state diff,
draft-PR rendering) is **wh-5es's** (CLOSED; ONE feed mechanism, do not fork it —
`docs/research/20260609_supply_chain_tooling_strategy.md:118`). This doc carries the signal; wh-5es carries it.

**Why a separate signal from the compromise watchlist.** MONITOR polls **two** health signals
(`…tooling_strategy.md:100-105`): (a) *compromise* advisories → the known-compromised watchlist
(`watchlist-1.0`, ADR-026 §2), and (b) *staleness/health* — cadence / last-commit age / archived / EOL.
**Staleness ≠ compromise** but is its own risk (the `trivy-mcp` lesson: an unmaintained wrapper pinning a
stale binary). This doc is signal (b) only; the OSV-superset watchlist schema
(`plugins/white-hacker/skills/_shared/reference/watchlist-entry-schema.json`) stays the compromise channel
and is **not forked** here.

## 1. GitHub-API input fields (the exact REST fields)

The signal is computed from two GitHub REST v3 endpoints, both unauthenticated-readable for public repos.
**The fetch is wh-5es's** (network-on, egress-allowlisted); this section names the fields the parser reads
from the *recorded JSON* (network-off parse, mirroring `poll_feeds.py`'s "no network here" contract,
`poll_feeds.py:4-7`).

| Signal | Endpoint | JSON field | Type | Meaning |
|---|---|---|---|---|
| **Release age** | `GET /repos/{owner}/{repo}/releases/latest` | `published_at` | ISO-8601 `str` | when the newest release shipped; age = `now − published_at` |
| **Archived** | `GET /repos/{owner}/{repo}` | `archived` | `bool` | repo is archived (read-only) → maintainer has stopped — IMMEDIATE flag |
| **Disabled** | `GET /repos/{owner}/{repo}` | `disabled` | `bool` | repo disabled by GitHub/owner → treated as archived (IMMEDIATE) |
| **Last commit** | `GET /repos/{owner}/{repo}` | `pushed_at` | ISO-8601 `str` | last push to any branch; **fallback** release-age proxy when a repo cuts no GitHub Releases |
| **EOL / feature-complete** | (no single API field) | derived | — | see §1.1 — there is no GitHub boolean for "EOL"; it is signalled, not queried |

Notes that keep the parse deterministic and degrade-never-raise (ADR-003, Liskov contract):

- `releases/latest` **404s** when a repo has zero published releases (GitHub returns 404, not an empty body).
  The parser MUST treat a missing `latest_release` as `status: unknown` and **fall back to `pushed_at`** for
  the age computation — never raise. (A tool distributed only via tags, not Releases, is the common case.)
- `published_at` may be `null` on a draft release; treat `null` as missing (fall back to `pushed_at`).
- All timestamps are UTC ISO-8601 (`...Z`). Age is whole **days** (floor of the timedelta) — see §2.

### 1.1 EOL / feature-complete — there is no GitHub boolean for it

GitHub exposes `archived`/`disabled` but **no** "end-of-life" or "feature-complete" field. Those states are
declared by maintainers in prose (README, release notes, a `SECURITY.md`, or an external page such as
endoflife.date). So this signal is **NOT** auto-derived from a single API call; it is a **registry-recorded
flag** the human review sets (ADR-012, human-gated) and the parser reads as an input:

- `feature_complete: true` (registry/watchlist `database_specific`) → the tool ships **security patches
  only**; cadence-based "stale" must NOT fire on a long release gap alone (that gap is *expected*). It is
  reported as `status: eol` (informational), not `stale`.
- `eol_date: "<ISO date>"` (optional) → once `now >= eol_date`, `status: eol` with IMMEDIATE severity
  (same tier as `archived`).

This keeps the runtime rule pure (Policy 5): the human sets the flag once at admission; the parser does
date/flag arithmetic, never a judgment call.

## 2. Thresholds (deterministic — a pure rule, Policy 5)

The verdict is a **total function** of `(published_at|pushed_at, archived, disabled, feature_complete,
eol_date, now)`. No LLM, no RNG, no network at decision time. Stated as an ordered rule (first match wins):

```
is_stale(latest):
  1. archived == true OR disabled == true        -> status = "archived"  (severity IMMEDIATE)
  2. eol_date set AND now >= eol_date             -> status = "eol"       (severity IMMEDIATE)
  3. feature_complete == true                     -> status = "eol"       (severity INFO; cadence rule SKIPPED)
  4. age_days >= STALE_DAYS (540)                 -> status = "stale"     (severity HIGH)
  5. age_days >= WATCH_DAYS (365)                 -> status = "aging"     (severity MEDIUM)
  6. published_at AND pushed_at both missing      -> status = "unknown"   (severity INFO)
  7. otherwise                                    -> status = "fresh"     (severity NONE)

age_days = floor(now - (published_at or pushed_at))   # whole days, UTC
```

### The day thresholds + rationale

| Constant | Value | Rationale (deterministic, defensible) |
|---|---|---|
| `WATCH_DAYS` | **365** | One year with **no release AND no commit** → the tool is *aging*; surface it for a human look before it becomes a liability. A year is the widely-used "is this still maintained?" first bar (matches the ADMIT maintenance gate's "release cadence / last-commit recency" framing, `…tooling_strategy.md:87-89`). MEDIUM: watch, don't act. |
| `STALE_DAYS` | **540** (~18 months) | 18 months with no release AND no commit → *stale*; propose (human-gated) a DIVERSIFY/RETIRE review. 18 months clears two normal annual cycles, so it is past plausible "quiet but alive". HIGH: act. Chosen > 365 so a tool gets a full year in `aging` before escalating. |
| `archived` / `disabled` / `eol_date≤now` | **IMMEDIATE** | A binary, unambiguous maintainer/owner signal — the maintainer has stopped. No age math; flag now. This is the case that would have caught `trivy-mcp` (an *unmaintained* wrapper). |
| `feature_complete` | **INFO (EOL), cadence rule skipped** | Security-patch-only is a *declared* posture, not decay — a long release gap is expected and must NOT trip the cadence rule. Reported so the human keeps tracking a successor (the gitleaks→Betterleaks case — a CONFIRMED succession, §6), but it is not a "go act now" flag. |

These are **starting constants**, not magic: they live as module-level names (`WATCH_DAYS`, `STALE_DAYS`)
so a future tuning is a one-line DATA change (Open/Closed — extend via data, not by editing the rule). Any
change is human-PR'd; the rule body never changes shape.

**Why "no release AND no commit"** (both, not either): an actively-developed tool may go > 18 months
between tagged *releases* while committing weekly (`pushed_at` recent) — that is healthy, not stale. Using
the **more-recent** of `published_at`/`pushed_at` as the age basis avoids a false `stale` on a
slow-release-cadence-but-live project. Equally, a repo with frequent releases but a recent `archived: true`
is caught by rule 1 regardless of age. Both directions are pinned in the test (§4).

## 3. Output shape — the staleness verdict (one per tool / watchlist row)

One verdict dict per tool, mirroring the existing parser item shape's "flat dict, JSON-serializable,
provenance-carrying" convention (`poll_feeds.py:26-66` produce `{feed,id,title,url}`; the verdict is the
staleness analogue):

```jsonc
{
  "tool": "owner/repo",          // the registry/watchlist identity this verdict is about
  "status": "fresh",             // fresh | aging | stale | archived | eol | unknown  (the rule's output)
  "signal": "release_age",       // which field decided: release_age | last_commit | archived | disabled | eol | feature_complete | none
  "age_days": 92,                // whole days since the more-recent of published_at/pushed_at; null if both missing
  "severity": "none",            // none | info | medium | high | immediate  (maps 1:1 from status per §2)
  "basis": "published_at",       // which timestamp age_days was computed from: published_at | pushed_at | null
  "checked": "2026-06-12"        // ISO date the check ran (provenance; = `now`)
}
```

Field rules:

- `status` ∈ the closed set above — never free text (an enum, like `watchlist_confidence` in
  `watchlist-entry-schema.json:92`).
- `severity` is a **pure function of `status`** (the §2 mapping) — it is not an independent input, so the
  two can never disagree.
- `tool` is the GitHub `owner/repo` identity (repo-relative to the upstream, not a local path — the
  public-repo / no-machine-data constraint, `.claude/CLAUDE.md` Security posture).
- The verdict carries **no** finding-schema `file` field and is never written with an absolute path — it is
  tool metadata, not a code finding.

**Consumer contract.** wh-5es's plumbing renders a `status != "fresh"` verdict into a **human-gated
proposal** (a draft PR / a `bd` ticket suggesting a DIVERSIFY/RETIRE review) — **never an auto-swap**
(ADR-012: the registry self-corrects through the outer loop, but a human applies the change;
`…tooling_strategy.md:100-101`, "proposes (human-gated) registry changes"). `archived`/`eol` =
IMMEDIATE-severity proposal; `stale` = HIGH; `aging` = MEDIUM (watch); `fresh`/`unknown` = no proposal
(`unknown` may be logged for the human to pin a `pushed_at` basis).

## 4. PARSERS interface contract (what the wh-5es plumbing must satisfy)

The existing parsers are `raw: str -> list[dict]{feed,id,title,url}`, registered by name in `PARSERS`
(`poll_feeds.py:69`) and dispatched by `poll()` (`poll_feeds.py:72-79`). A staleness parser is the **same
port, one new shape**:

```
parse_staleness(raw_github_json: str, *, now: str) -> list[verdict]
```

- **Same registration:** `PARSERS["staleness"] = parse_staleness` (or `"github"`) — a new key joins the
  dict; the core dispatch (`poll()`, `main()`) is **untouched** (Open/Closed; mirrors how `osv`/`atlas`/
  `atom` each just added a key). `poll()` already keys state by `feed_type`; a verdict's stable id for
  diffing is its `tool` (so re-polling an unchanged-status tool yields zero "new").
- **CONTRACT CAVEAT (QA Gap C) — `poll()` dedups by `item["id"]`, the verdict has NO `id` key.** `poll()`
  (`poll_feeds.py:72-79`) diffs items by `it["id"]`, but the staleness verdict's stable id is `tool`, not
  `id` — so registering `parse_staleness` into `PARSERS` **as-is would raise `KeyError: 'id'`** at the
  `poll()` diff. Before wiring it in, wh-5es's plumbing MUST either (a) add an `id` alias in the parser
  (`verdict["id"] = verdict["tool"]`) or (b) extend `poll()` to key off `tool` for this feed. This is a
  DEFINITION note — the choice + wiring is **wh-5es's** scope (the poller), not this contract's. (The §5
  helper deliberately emits `tool` only, keeping the verdict shape clean per §3; the alias is a plumbing
  concern, not a shape change.)
- **Input is recorded JSON, NOT a live call** (`poll_feeds.py:4-7`): `raw_github_json` is the already-fetched
  body of the GitHub REST responses (the `repos/{...}` object, optionally with the `releases/latest` object
  merged under a `latest_release` key). The fetch that produces it is wh-5es's egress-confined plumbing — this
  function does **zero** network I/O, exactly like `parse_osv`/`parse_atom`.
- **`now` is injected, never `date.today()` inside the pure path** — so the rule is testable both directions
  and deterministic (the same input always yields the same verdict). `poll_feeds.py:83` already takes an
  injectable `today=` for the same reason.
- **Liskov / degrade-never-raise (ADR-003):** on a 404 `latest_release`, a `null` timestamp, or a missing
  field, the parser returns a verdict with `status: "unknown"` (or falls back to `pushed_at`) — it **never
  raises**. Every adapter behind this port honors that contract (a malformed feed yields a verdict, not a
  crash), matching the floor-degradation rule the whole tool layer obeys.
- **Untrusted input (Rule of Two):** the GitHub JSON is an untrusted *value* — the parser reads only the
  named fields by key and emits a closed-enum `status`; it never `eval`s feed text or lets a field name
  become a structural key (the same discipline `render_entry`'s `safe_dump` enforces at
  `poll_feeds.py:106`). No secrets are held during the parse; fetch (egress) and analyze (this parse) are
  split, so Rule-of-Two holds.

**Boundary restated:** this ticket DEFINES `parse_staleness`'s input fields, thresholds, and output verdict.
wh-5es IMPLEMENTS the fetch that fills `raw_github_json` and the draft-PR render of a non-`fresh` verdict. The
optional helper below (§5) is the pure threshold core that `parse_staleness` would wrap — it has no network
and is fully tested, so the contract is executable, not just prose.

## 5. Optional pure helper (LANDED — it makes the contract executable)

A pure, deterministic threshold function landed at
`plugins/white-hacker/skills/sec-kb-refresh/scripts/staleness.py` with tests at
`…/tests/test_staleness.py`. It is the §2 rule as code — **no network, no `date.today()` in the pure path,
`now` injected** — so the contract is verifiable, not aspirational. It is the core `parse_staleness` wraps;
it is **not** the poller (no fetch, no state diff, no PR render — those stay wh-5es's). Tests pin **both
directions** per Policy 9 (`== stale` for an old/archived tool AND `!= fresh`/`== fresh` for a current one).

Run the gate:

```
nice -n 10 uv run --project plugins/white-hacker/skills/sec-kb-refresh/scripts --with pytest \
  pytest plugins/white-hacker/skills/sec-kb-refresh/scripts/tests -q
uv run python packaging/validate_manifest.py .
claude plugin validate ./plugins/white-hacker
```

## 6. Motivating cases — would have caught these

Per the repo DO-NOT-COPY / primary-source convention (`.claude/commands/design-ticket.md:106-114`), every
named threat-intel literal below is tagged `[primary-sourced: <url|file:line>]` or `[example-unverified]`.

- **`trivy-mcp` — the staleness lesson (rule 1 / IMMEDIATE).** A 3rd-party MCP wrapper that was
  **unmaintained and pinned a stale Trivy binary** — the indirection hid which binary ran and decoupled the
  version from the pin. The staleness signal catches this as `status: "stale"` (no release/commit past
  `STALE_DAYS`) or, if its repo were archived, `status: "archived"` (IMMEDIATE).
  `[primary-sourced: docs/research/20260609_trivy_replacement_sca_iac.md:178-183]` (in-repo derivation) ·
  canonical repo `[primary-sourced: https://github.com/aquasecurity/trivy-mcp]`. (The Trivy *binary* TeamPCP
  compromise is a separate **compromise**-channel fact, primary-sourced GHSA-69fq-xp46-6x23 / CVE-2026-33634
  — not this staleness signal.)
- **gitleaks → Betterleaks — the feature-complete lesson (rule 3 / EOL-INFO).** gitleaks is
  single-maintainer and declared **feature-complete** (security patches only). The **verifiable cadence
  fact**: release **v8.30.0 = 2025-11-26**, **v8.30.1 = 2026-03-21** — a ~4-month gap consistent with
  security-patch-only.
  `[primary-sourced: docs/research/20260609_trivy_replacement_sca_iac.md:93-98]` (in-repo, with the cadence
  dates) · canonical releases `[primary-sourced: https://github.com/gitleaks/gitleaks/releases]` (the
  operator can confirm the `published_at` dates directly).
  The signal handles this correctly via the `feature_complete: true` flag (§1.1): it reports `status: "eol"`
  / INFO and **does NOT** trip the cadence `stale` rule on the expected long gap — it keeps the human
  tracking a successor without a false "act now".
  The **gitleaks→Betterleaks succession is CONFIRMED** (spike wh-hv1, primary-sourced): Betterleaks is a
  real, MIT-licensed, drop-in successor created/led by **Zach Rice, the original gitleaks author**, who
  started it because he "no longer has full control over the Gitleaks repository and name"; it launched
  ~2026-03-19 — which **corroborates** the gitleaks v8.30.1 = 2026-03-21 cadence cited above.
  `[primary-sourced: github.com/betterleaks/betterleaks · helpnetsecurity.com 2026-03-19]`. **The signal
  still does NOT depend on the name "Betterleaks"** — it fires on the deterministic `feature_complete` flag
  + cadence; "Betterleaks" stays prose/example here and is **never** hardcoded as a detection literal (the
  flag is a registry input, not an IOC literal). The succession being sourced only makes the *human-gated
  successor proposal* concrete; the rule shape is unchanged.

## 7. Constraints honored (checklist)

- **Deterministic (Policy 5):** the verdict is a pure function of dates/flags — no LLM, no RNG, no network at
  decision time. The §5 helper injects `now`; the §4 contract forbids `date.today()` in the pure path.
- **Human-gated, never auto-swap (ADR-012):** a non-`fresh` verdict becomes a *proposal* a human applies; the
  registry self-corrects through the outer loop but the swap is operator-gated (§3 consumer contract).
- **Don't fork the feed mechanism:** the live fetch / state-diff / PR-render stays wh-5es's ONE poller
  (`…tooling_strategy.md:118`); this defines the signal it carries (§4 boundary).
- **Compromise channel untouched:** `watchlist-1.0` (ADR-026 §2) stays the *compromise* feed; this is the
  distinct *staleness/health* signal (b) (`…tooling_strategy.md:100-105`) — not a fork of the watchlist schema.
- **Public repo / no machine data:** repo-relative paths, generic phrasing, no PII; `tool` is an upstream
  `owner/repo`, not a local path (`.claude/CLAUDE.md` Security posture).
- **DO-NOT-COPY literals tagged:** §6 — every named case is `[primary-sourced: …]` or `[example-unverified]`
  per `.claude/commands/design-ticket.md:106-114`.

## References

- `docs/research/20260609_supply_chain_tooling_strategy.md:100-105` (MONITOR signal (b); human-gated),
  `:87-89` (ADMIT maintenance gate), `:118` (wh-5es owns the poller).
- `docs/research/20260609_supply_chain_loop_leverage.md:254` (G6 — staleness signal → MONITOR for tools).
- `plugins/white-hacker/skills/sec-kb-refresh/scripts/poll_feeds.py:26-66` (parser item shape), `:69`
  (`PARSERS`), `:72-79` (`poll()`), `:83` (injectable `today=`), `:106` (`safe_dump` untrusted-value handling).
- `plugins/white-hacker/skills/_shared/reference/watchlist-entry-schema.json` (the *compromise* channel —
  not forked here).
- `docs/ARD.md`: ADR-002 (CLI-first / MCP-optional — the trivy-mcp trap), ADR-003 (degrade to floor),
  ADR-006 (pin + verify), ADR-012 (human-gated swaps), ADR-015 (capability layer / self-updating registry),
  ADR-026 §2 (watchlist-1.0 schema).
- DO-NOT-COPY / primary-source convention: `.claude/commands/design-ticket.md:106-114`.
