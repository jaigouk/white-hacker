# Spike-11: Currency-arm mechanism — how does `sec-kb-refresh` actually get scheduled? (2026-06)

> **Defensive-security / ops-design context.** This spike DECIDES the mechanism that runs the
> outer-loop **currency arm** (`sec-kb-refresh`) on a cadence, under the standing constraint **no local
> `ANTHROPIC_API_KEY` — subscription only; a key/OAuth is CI-only**. It is RC1 of the Hades dogfood RCA
> (`docs/research/20260610_hades_shai_hulud_pypi.md` §5): the self-improving loop is design-intent, not
> operational. No production code here — feasibility + decision + an ADR proposal + a draft impl spec.

**Status:** RESOLVED (RQ2/RQ3/RQ4) · **OPEN operator question on RQ1** (account provisioning — not
externally verifiable; see RQ1 §Operator question)
**Date:** 2026-06-10
**Confidence:** HIGH on mechanism facts (Anthropic Routines docs + Claude Code GitHub Action docs fetched
2026-06-10 from primary sources); the RQ1 *provisioning* status for THIS operator is the one unknown and is
explicitly flagged as an operator question, not asserted.
**Author:** researcher (seat-hxt12, Wave-B1)
**Ticket:** wh-hxt.12 (strand b of the wh-hxt.8 split). Siblings: wh-hxt.8 (the human capture-hook decision
this splits from), wh-hxt.9 (the feeds this routine polls), wh-hxt.10(b)/wh-hxt.14 (the campaign-family
re-poll trigger folded into the impl-task here).
**Related ADRs:** ADR-003 (graceful degradation), ADR-004 (text-diff edits via the gate), ADR-006 (pin +
verify), ADR-009 (one definition, three carriers), ADR-010 (proposes, never pushes), ADR-012 (human-gated
draft-PR, never auto-merge), ADR-024/026 (CONTAIN + the tag→SHA rule for pinned `uses:` refs).

---

## Goal

`sec-kb-refresh` is `disable-model-invocation:true` ("never self-fires"; `SKILL.md:4`). ARCHITECTURE §3.6
(`docs/ARCHITECTURE.md:239-247`) specifies a **cloud Scheduled Routine** (`/schedule`) to run it, but: (1) no
`/schedule` artifact exists in-repo — it is an external Anthropic-platform primitive we do not own; (2) **no
ADR governs scheduling or its auth** (the `docs/ARD.md` set ends at ADR-028, none about a routine); (3) our
constraint is **no local `ANTHROPIC_API_KEY`**. Decide the mechanism before any "wire it" task is filed.

## Background & constraints (the decision context)

- **What runs:** `sec-kb-refresh` → `poll_feeds.py` (PARSERS = `{osv, atlas, atom}`; `:69`) → fetch → diff
  vs `evals/feed-state.json` → LLM-extract → draft dated KB entries (mandatory `source`+`url`+`retrieved`) →
  `validate_kb` + `dedupe_kb` → **open a draft PR, never auto-merge** (`SKILL.md:5,29-37`). Fast tier only.
- **Feeds need no auth (si-07).** OSV/GHSA/ATLAS/arXiv/OWASP are public, no-token reads
  (`docs/research/si-07-threat-feeds.md:7-8`; "No auth for public data", verified). The blocker is the
  *model invocation* (running Claude on a cadence), **not** fetching the feeds.
- **Egress is already allow-listed** for exactly these hosts: `confine_self_writes.FEED_HOSTS` (`:41-46`)
  already contains `api.osv.dev`, `storage.googleapis.com`, `api.github.com`, `raw.githubusercontent.com`,
  `github.com`, `export.arxiv.org`/`rss.arxiv.org`/`arxiv.org`, `genai.owasp.org`, `owasp.org`,
  `cheatsheetseries.owasp.org`, `csrc.nist.gov`, `www.nist.gov`, `modelcontextprotocol.io`,
  `embracethered.com`, `simonwillison.net`. Any chosen mechanism must keep this guardrail intact (deny wins).
- **The standing auth constraint** (memory `qa-and-auth`; `CLAUDE.md` QA-flow §): the agent runs on the
  **Claude Code subscription** locally; a key/OAuth is **CI-only**. The optional headless CI action
  (`ci/security-review.action.yml`) already carries a known auth story (`ANTHROPIC_API_KEY` from
  `secrets`, model pinned `claude-opus-4-8`, `@anthropic-ai/claude-code@2.1.167`, **read-only** token,
  fork-PRs gated — `:14,29,43,49`).
- **The non-negotiables that survive any mechanism:** draft-PR-never-auto-merge (ADR-012); the keep-or-revert
  gate on KB edits (ADR-004; `evals/keep_or_revert.py`); `confine_self_writes` intact; **proposes, never
  pushes** (ADR-010); pin + verify every `uses:` ref to an immutable **commit SHA** (ADR-006/026).
- **User-preference guardrail (memory `avoid-schedulers-and-loops`):** the operator does **not** want
  `/loop` or in-session `ScheduleWakeup`/cron wakeups driving local work. Note both adopted options are
  **out-of-session, infra-side** schedulers (cloud Routine OR GitHub Actions `schedule:`), NOT the local
  `/loop` / in-session scheduler the operator declined — this distinction is load-bearing (see Risk §R5).

---

## RQ1 — Is Anthropic `/schedule` (Scheduled Routines) a real, usable mechanism, and what auth/provisioning?

**It is real and recently shipped — and it runs on the SUBSCRIPTION, not an API key.** Facts, all from the
official docs fetched 2026-06-10:

| Fact | Finding | Source |
|---|---|---|
| What it is | "A routine is a saved Claude Code configuration… Routines execute on **Anthropic-managed cloud infrastructure**, so they keep working when your laptop is closed." Create at `claude.ai/code/routines` or **`/schedule`** in the CLI. | code.claude.com/docs/en/routines |
| Maturity | **Research preview.** "Routines are in research preview. Behavior, limits, and the API surface may change." (`/fire` API ships under beta header `experimental-cc-routine-2026-04-01`.) | code.claude.com/docs/en/routines |
| Introduced | Announced **May 2026** (InfoQ, 2026-05-15); the **June 9 2026** expansion added managed agents on a **schedule** + **credential vaults** in public beta. | infoq.com/news/2026/05/anthropic-routines-claude/ ; techtimes.com 2026-06-10 |
| **Tier required** | "Routines are available on **Pro, Max, Team, and Enterprise** plans **with Claude Code on the web enabled**." | code.claude.com/docs/en/routines |
| **Billing** | "Routines **draw down subscription usage the same way interactive sessions do.**" Plus a per-account **daily run cap**. **No API key / API billing involved.** | code.claude.com/docs/en/routines |
| **Auth precedence (key fact)** | `/schedule` **requires a claude.ai subscription login** and is HIDDEN if a key is set: "If `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` is set in your shell… remove it first, since these take precedence over a claude.ai login." | code.claude.com/docs/en/routines (Troubleshooting) |
| Min cadence | **Hourly.** "The minimum interval is one hour; expressions that run more frequently are rejected." Presets: hourly/daily/weekdays/weekly; custom cron via `/schedule update`. | code.claude.com/docs/en/routines |
| Triggers | **Schedule** (cron), **API** (`POST …/fire`, bearer token), **GitHub** (PR/Release events). Combinable. | code.claude.com/docs/en/routines |
| Drafts a PR | Routines clone the repo, work on `claude/`-prefixed branches by default ("**Allow unrestricted branch pushes**" is opt-in, off by default), and each run is a session you review → create a PR. Fits draft-PR-never-auto-merge. | code.claude.com/docs/en/routines |
| Egress model | Cloud env has a **Default = Trusted** network allowlist; non-allowlisted hosts fail `403 host_not_allowed`. Custom domains must be added per-environment. (Our feed hosts would need to be on the env allowlist — a re-statement of `FEED_HOSTS`, server-side.) | code.claude.com/docs/en/routines |
| Org kill-switch | Team/Enterprise admins can disable routines org-wide (`claude.ai/admin-settings/claude-code`). | code.claude.com/docs/en/routines |

**Reconciliation with the wh-hxt.8 groom premise.** The groom flagged `/schedule` as "likely infeasible…
our constraint is NO local ANTHROPIC_API_KEY." That premise is **inverted by the facts**: `/schedule` is
*subscription-only by design* and is actively **disabled when a key is present**. So the no-local-key posture
**enables** `/schedule`, it does not block it. The real blocker is narrower and is a provisioning question,
not an auth-model conflict.

### Operator question (RQ1 — the one item that may need the operator)

Whether `/schedule` is *usable by THIS operator* depends on three account-side facts that are **not verifiable
from outside the account**:

1. Does the operator's plan (Pro/Max/Team/Enterprise) have **Claude Code on the web enabled**?
2. If on Team/Enterprise, has an admin **disabled the Routines toggle** org-wide?
3. Are the **research-preview** limits (daily run cap, beta-header churn) acceptable for a security-currency
   job we want to be dependable?

**Honest stance:** I cannot confirm provisioning from here — it requires the operator to open
`claude.ai/code/routines` (or run `/schedule list`) and report whether it works. **This is the single
operator question the spike surfaces.** It does **not** block the decision below, because RQ2 is buildable
today regardless of the answer.

---

## RQ2 — The FALLBACK: a maintainer-repo GitHub Actions `schedule:` cron invoking `claude -p`

**Buildable TODAY. Confirmed by the official docs.** The Claude Code GitHub Action page shows a `schedule:`
cron workflow verbatim:

```yaml
# (from code.claude.com/docs/en/github-actions — "Custom automation with prompts")
name: Daily Report
on:
  schedule:
    - cron: "0 9 * * *"
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          prompt: "Generate a summary of yesterday's commits and open issues"
          claude_args: "--model opus"
```

It also documents running a **plugin skill** in a workflow (the exact shape we need):

```yaml
- uses: anthropics/claude-code-action@v1
  with:
    plugin_marketplaces: "https://github.com/anthropics/claude-code.git"
    plugins: "code-review@claude-code-plugins"
    prompt: "/code-review:code-review …"
```

So the currency arm maps cleanly: `schedule:` cron → checkout → install the white-hacker plugin → run
`/sec-kb-refresh` → the skill fetches (feeds need no auth), drafts entries, validates, **opens a draft PR**.

### Auth options for the Actions path (all from primary sources, 2026-06-10)

| Method | How | Bills | Static secret? | Source |
|---|---|---|---|---|
| `ANTHROPIC_API_KEY` | repo secret; what `ci/security-review.action.yml` already uses | **API account** (not subscription) — `claude -p` + `ANTHROPIC_API_KEY` "always bills to the API account, never a Max subscription" | Yes (a long-lived key) | github.com/anthropics/claude-code-action setup.md; github issue #37686 |
| **`CLAUDE_CODE_OAUTH_TOKEN`** | `claude setup-token` locally (**Pro/Max** users), store as repo secret | Subscription credential (billing-to-subscription **not explicitly documented**; it is the subscription OAuth token, contrast the API-key gotcha above) | Yes (a long-lived OAuth token) | github.com/anthropics/claude-code-action setup.md ("Pro and Max users can generate this by running `claude setup-token`") |
| **Workload Identity Federation (OIDC)** | exchange the workflow's GitHub OIDC token for a short-lived Anthropic access token | the federated Anthropic account/credits (an **account**, not the personal subscription) | **No** — "no `ANTHROPIC_API_KEY` secret to create, store, or rotate" | github.com/anthropics/claude-code-action setup.md (Workload Identity Federation) |

**Key auth finding for our constraint.** The Actions path is **CI**, where a key/OAuth is *permitted* by our
rule. Three sub-choices, none blocked:
- `CLAUDE_CODE_OAUTH_TOKEN` keeps it on the **subscription** (best fit for "subscription only" spirit), at the
  cost of a long-lived secret in repo secrets.
- **WIF/OIDC** removes the static secret entirely (best supply-chain posture — nothing to leak/rotate;
  aligns with ADR-006/024), but routes billing through a federated **account/API** path, not the personal sub.
- `ANTHROPIC_API_KEY` is the already-proven path (`ci/…action.yml`) but bills API and is a static key.

### Buildability checklist (RQ2 — does it hold the invariants?)

| Invariant | How the Actions-cron path satisfies it |
|---|---|
| draft-PR-never-auto-merge (ADR-012) | the skill opens a draft PR; the workflow grants **no** auto-merge; least-privilege token (below). |
| proposes, never pushes (ADR-010) | `permissions: contents: read` for the review/extract job; PR creation via a separate least-privilege step/app token scoped to `pull-requests: write` only — never a write token on the model step (mirrors `ci/security-review.action.yml:14`). |
| `confine_self_writes` intact | the plugin's PreToolUse hooks ship with the plugin and run in CI exactly as locally (ADR-009 — one definition, three carriers); egress stays bounded to `FEED_HOSTS`. |
| keep-or-revert gate (ADR-004) | the existing `kb-keep-or-revert-gate` job (`ci/security-review.action.yml:61-81`) already gates KB-touching PRs — the refresh PR is gated on merge, **the same gate**, not a new one. |
| pin + verify (ADR-006/026) | every `uses:` pinned to a **commit SHA** (not a tag — the tag→SHA force-push lesson, ADR-026 §4); `@anthropic-ai/claude-code` pinned, never `latest`. |
| supply-chain least-privilege | prefer **WIF/OIDC** (no static secret) for the model auth; `concurrency` guard; `timeout-minutes`; `--max-turns` cap. |

**Cost.** GitHub Actions minutes + model tokens per run. At an hourly-to-daily cadence touching only feed
**deltas** (`poll_feeds.poll` returns only unseen ids — an unchanged feed yields zero new items, `:72-79`),
the per-run token cost is small (extract only new items). Daily is the cost-sane default; hourly is reserved
for "hot family" bursts (RQ4).

**Verdict: YES, buildable today**, with WIF/OIDC as the cleanest auth and `CLAUDE_CODE_OAUTH_TOKEN` as the
subscription-billed alternative.

---

## RQ3 — DECISION

**Adopt the GitHub Actions `schedule:` cron (`claude -p` / `claude-code-action`) in the maintainer repo as the
currency-arm mechanism NOW.** Treat the cloud `/schedule` Routine as the **preferred long-term shape, gated on
the operator confirming provisioning** (RQ1 operator question) and on it leaving research preview.

**Why Actions-cron now (the decision drivers):**
1. **Buildable today, zero new platform dependency** (Policy 2, simplicity-first). It reuses the auth story,
   the plugin carriers, and the keep-or-revert gate already in `ci/security-review.action.yml` (ADR-009).
2. **Known, CI-scoped auth** that satisfies the standing constraint — a key/OAuth is *allowed in CI*; WIF/OIDC
   even removes the static secret (ADR-006/024 supply-chain posture).
3. **No coupling to a research-preview primitive** for the load-bearing currency loop. `/schedule` is
   explicitly "research preview… API surface may change"; a security-freshness job should not hard-depend on
   a churning beta (Policy 7 — prefer the more-tested path; flag the other).
4. **Graceful degradation (ADR-003), generalized to the mechanism layer.** Two independent schedulers
   (Actions-cron = floor; cloud Routine = enhancement) means the currency arm is not coupled to one vendor
   primitive — the same "capability not brand" logic ADR-015 applies to tools, applied to scheduling.

**Why `/schedule` later, not now:** it is the *cleaner* shape (subscription-billed, no CI minutes, no static
secret, runs while the laptop is closed, `/schedule` is hidden-by-design exactly under our no-local-key
posture). Adopt it **when** (a) the operator confirms Claude Code on the web is enabled + routines not
admin-disabled, AND (b) it exits research preview (stable limits/headers). Until both hold, it is a documented
follow-up, not the primary.

**This needs an ADR — none exists.** A grep of `docs/ARD.md` shows no scheduling ADR; ARCHITECTURE §3.6 asserts
the cloud routine without a governing decision. The proposal below fills the gap and amends §3.6 (the
ARCHITECTURE text edit is a **follow-up**, not this wave).

---

## ADR proposal — TL appends

> The TL appends the block below verbatim to `docs/ARD.md` (next free number is **ADR-029**; the literal
> `0XX` is per the wave instruction — the TL substitutes the real number on append). ARCHITECTURE §3.6 amend
> is a separate follow-up ticket, NOT this wave.

## ADR-0XX — The currency arm runs on a maintainer-repo GitHub Actions `schedule:` cron (`claude -p`) NOW; the cloud `/schedule` Routine is the deferred long-term shape, gated on operator provisioning + GA
**Status:** proposed — resolves spike wh-hxt.12 (`docs/research/spike-11-currency-mechanism-2026-06.md`); the
SCHEDULING ADR for epic wh-hxt (RC1 of the Hades RCA). No scheduling ADR existed; ARCHITECTURE §3.6 asserted a
cloud routine without a governing decision. Platform facts verified from primary docs 2026-06-10. Consumed by
the wh-hxt.8(c) impl-task (the workflow + the campaign-family re-poll trigger from wh-hxt.10(b)/wh-hxt.14).
**Context:** The outer-loop **currency arm** (`sec-kb-refresh`, `disable-model-invocation:true` — never
self-fires) is design-intent, not operational: the only ingestion path today is a human noticing a threat on
social, which is exactly how the Hades/Miasma PyPI wave was missed 1–2 days after we tracked its parent
(`docs/research/20260610_hades_shai_hulud_pypi.md` §5 RC1). The feeds need no auth (si-07), and egress is
already allow-listed (`confine_self_writes.FEED_HOSTS:41-46`); the gap is **invoking the model on a cadence**.
Two mechanisms exist: (1) Anthropic **cloud Scheduled Routines** (`/schedule`; ARCHITECTURE §3.6) — real,
subscription-billed, min-hourly, but **research preview** and gated on per-account provisioning (Claude Code on
the web enabled; not admin-disabled) that is not externally verifiable; (2) a maintainer-repo **GitHub Actions
`schedule:` cron** running `claude-code-action`/`claude -p` — the headless path with a known CI auth story
(`ci/security-review.action.yml`), buildable today. The standing constraint is **no local `ANTHROPIC_API_KEY`
— subscription only; a key/OAuth is CI-only**; notably `/schedule` is *hidden when a key is set*, so the
no-local-key posture **enables** the cloud routine rather than blocking it.
**Decision:**
1. **Adopt GitHub Actions `schedule:` cron as the currency-arm mechanism NOW.** A maintainer-repo workflow
   runs `sec-kb-refresh` on a cadence (RQ4: daily floor + a "hot family" hourly burst), fetches the feeds
   (no auth), LLM-extracts deltas, drafts dated KB entries, validates+dedupes, and **opens a draft PR — never
   auto-merges** (ADR-012). Reuses the existing carriers (ADR-009) and the existing `kb-keep-or-revert-gate`
   (`ci/security-review.action.yml:61-81`) — the refresh PR is gated by the **same** keep-or-revert gate on
   merge, not a new gate.
2. **Auth = CI-scoped, least-privilege; prefer no static secret.** The model step uses **Workload Identity
   Federation (OIDC)** where available (no `ANTHROPIC_API_KEY` to store/rotate — best supply-chain posture,
   ADR-006/024), with **`CLAUDE_CODE_OAUTH_TOKEN`** (`claude setup-token`, Pro/Max) as the subscription-billed
   alternative and the existing `ANTHROPIC_API_KEY` (API-billed) as the proven fallback. The model step gets
   **`contents: read`** and **no write token**; PR creation is a separate step scoped to `pull-requests:
   write` only (ADR-010 — proposes, never pushes). Every `uses:` pinned to an **immutable commit SHA** (the
   tag→SHA force-push lesson, ADR-026 §4); `@anthropic-ai/claude-code` pinned, never `latest` (ADR-006).
   `confine_self_writes` runs in CI exactly as locally (ADR-009); egress stays bounded to `FEED_HOSTS`.
3. **The cloud `/schedule` Routine is the DEFERRED long-term shape, not adopted now.** It is the cleaner
   mechanism (subscription-billed, no CI minutes, no static secret, runs laptop-closed). Adopt it **only when
   both**: (a) the operator confirms Claude Code on the web is enabled and routines are not admin-disabled
   (the RQ1 operator question — not externally verifiable), AND (b) Routines exit **research preview** (stable
   limits/beta headers). Until both hold it is a documented follow-up. When adopted, it runs the SAME skill
   under the SAME draft-PR/gate invariants (ADR-009/012) — only the scheduler changes.
4. **Two schedulers = graceful degradation at the mechanism layer (ADR-003 generalized).** Actions-cron is
   the floor; the cloud Routine is the enhancement. The currency arm depends on a *scheduling capability*, not
   one vendor primitive — the ADR-015 "capability not brand" rule applied to *how the loop fires*. Neither
   path changes `sec-kb-refresh` itself.
5. **Out of scope (named, not silently dropped).** The T-8.3 **capture-hook** registration in the maintainer's
   `.claude/settings.json` is a **separate** human decision (wh-hxt.8(a)) — it feeds the *reflection* arm
   (`sec-learn`), not this *currency* arm; an agent cannot self-register it (`confine_self_writes` denies
   `.claude/settings.json`). The ARCHITECTURE §3.6 text amend (cloud-routine-asserted → cron-now/routine-later)
   is a follow-up ticket.
**Rationale:** A security-freshness loop must be dependable, so it should not hard-depend on a research-preview
primitive whose "API surface may change" (Policy 7 — prefer the more-tested path, flag the other). Actions-cron
is buildable today with zero new platform dependency, reusing auth/carriers/gate we already ship (Policy 2,
ADR-009). The CI-only auth rule is satisfied (a key/OAuth is permitted in CI); WIF/OIDC even removes the static
secret, the strongest supply-chain posture (ADR-006/024). Keeping the cloud routine as a gated follow-up
preserves the cleaner end-state without betting the loop on an unprovisioned beta. Two independent schedulers
generalize ADR-003's graceful degradation from tools to the mechanism layer.
**Supersedes:** Nothing (no prior scheduling ADR). **Amends** ARCHITECTURE §3.6 (the cloud-routine assertion
becomes cron-now / routine-later — via a follow-up doc ticket, not this ADR). Composes with ADR-009 (one
definition, three carriers — the cron is a fourth invocation surface of the same skill), ADR-010 (proposes,
never pushes), ADR-012 (human-gated draft-PR), ADR-004 (the keep-or-revert gate governs the resulting KB
edits), ADR-006/026 (pin to commit SHA), ADR-003/015 (capability-not-brand, now at the mechanism layer).
**Alternatives rejected:** (a) **adopt the cloud `/schedule` Routine now** — it is research preview + gated on
unverifiable per-account provisioning; betting the load-bearing currency loop on a churning beta violates
Policy 7. (b) **`ANTHROPIC_API_KEY` as the primary CI auth** — works, but a long-lived static key is a weaker
supply-chain posture than WIF/OIDC and bills API not subscription; keep it only as the proven fallback.
(c) **A local cron / `/loop` / in-session `ScheduleWakeup`** — the operator declined local schedulers
(memory `avoid-schedulers-and-loops`); also brittle (needs the laptop on) and it would run under the local
subscription session, conflating local + automated usage. (d) **Auto-merge the drafted KB entries** — violates
ADR-012 + the keep-or-revert gate (ADR-004); an auto-extracted entry starts at low confidence and must be
human-reviewed. (e) **Do nothing / keep it manual** — that IS RC1, the root cause the Hades miss surfaced.
**References:** wh-hxt.12 (this spike), `docs/research/spike-11-currency-mechanism-2026-06.md`;
`docs/research/20260610_hades_shai_hulud_pypi.md` §5 RC1; `docs/ARCHITECTURE.md:239-247` (§3.6 — amended);
`plugins/white-hacker/skills/sec-kb-refresh/SKILL.md:4-5,29-37` + `scripts/poll_feeds.py:69,72-79`;
`plugins/white-hacker/hooks/confine_self_writes.py:41-46` (FEED_HOSTS); `ci/security-review.action.yml:14,29,
43,49,61-81` (the known CI auth story + the existing keep-or-revert gate); `docs/research/si-07-threat-feeds.md:
7-8` (feeds need no auth). Platform facts (fetched 2026-06-10): code.claude.com/docs/en/routines (tier =
Pro/Max/Team/Enterprise + Claude Code on the web; "draw down subscription usage"; research preview; min-hourly;
`/schedule` hidden when a key is set); github.com/anthropics/claude-code-action/blob/main/docs/setup.md
(`CLAUDE_CODE_OAUTH_TOKEN` via `claude setup-token` for Pro/Max; Workload Identity Federation — no static key);
code.claude.com/docs/en/github-actions (the `schedule:` cron + plugin-skill workflow examples).
Siblings: wh-hxt.8 (the capture-hook human decision — reflection arm, distinct), wh-hxt.9 (the feeds),
wh-hxt.10(b)/wh-hxt.14 (the campaign-family re-poll trigger folded into the impl-task).

---

## RQ4 — Hand-off to the impl-task (DRAFT impl-ticket spec — strand c of wh-hxt.8; NOT a bd create)

> A draft spec for the TL to file as the wh-hxt.8(c) impl-ticket once this ADR is accepted. Title suggestion:
> **"Wire the currency arm: maintainer-repo Actions `schedule:` cron runs `sec-kb-refresh` → draft-PR, with a
> campaign-family hot-re-poll trigger."**

### Cadence
- **Floor: daily** — `cron: "0 7 * * *"` (one quiet UTC hour). Touches feed **deltas only** (`poll_feeds.poll`
  returns only unseen ids), so per-run token cost is bounded by *new* items. Daily is the cost-sane default
  for a draft-PR loop a human triages.
- **Hot-family burst: hourly** — a *second*, **conditionally-active** schedule (`cron: "0 * * * *"`) that runs
  only the **first-detector subset** of feeds when a campaign family is marked HOT (below). Hourly is the
  platform/Actions minimum that is still polite; it matches `/schedule`'s hourly floor so the cadence is
  portable if we later move to the cloud routine.
- **Weekly full re-score** stays where it is (ARCHITECTURE §3.8 passive-drift re-score) — not this ticket.

### Trigger wiring (the workflow)
1. `on: schedule:` (the two crons above) **+** `on: workflow_dispatch:` (manual "run now" for ops + testing).
2. Job A — **extract** (least privilege): `permissions: contents: read`; checkout (pinned SHA) → install the
   white-hacker plugin (pinned `@anthropic-ai/claude-code`, pinned marketplace SHA) → auth via **WIF/OIDC**
   (`id-token: write`; no static secret) or `CLAUDE_CODE_OAUTH_TOKEN` secret → run `/sec-kb-refresh` →
   the skill fetches (FEED_HOSTS only), drafts entries, runs `validate_kb`+`dedupe_kb`, writes the digest.
3. Job B — **open draft PR** (separate, scoped): `permissions: pull-requests: write` only; create a **draft**
   PR from the `claude/kb-refresh-<date>` branch. **Never** auto-merge. The existing `kb-keep-or-revert-gate`
   (the `ci.yml` job) fires on that PR and gates merge.
4. Guards: `concurrency` (one refresh at a time), `timeout-minutes`, `--max-turns`, and `if:` so cron does not
   run on forks. `confine_self_writes` + the keep-or-revert gate are inherited from the plugin (ADR-009) — do
   not re-implement.

### Folding in the campaign-family hot-re-poll trigger (wh-hxt.10(b))
The Hades RCA RC3 wants a "family is hot → re-poll the first-detector feeds for new waves" mechanism that a
static 90-day `review_by` cannot provide. Concrete design for the impl-task:
- **HOT signal (data, not code-in-the-hook):** a small committed list of active families and their
  first-detector feed hosts — e.g. `shai-hulud → {socket.dev, stepsecurity.io, OSV malicious-packages}`.
  (Note: `socket.dev` / `stepsecurity.io` are **not** yet in `FEED_HOSTS:41-46` — adding them is **wh-hxt.9**'s
  job, the feed-list ticket, and is a prerequisite for the hot-burst to reach those hosts; flag this
  cross-dep, don't silently add hosts here.)
- **Mechanism (deterministic, Policy 5):** the hourly burst job reads that list; for each HOT family it polls
  only those feeds (delta-diff as usual) and drafts entries on the same draft-PR/gate path. A family is marked
  HOT by a human (or by wh-hxt.14's typed `campaign_family` field once it exists) and cleared after N quiet
  days. **No LLM decides "is this hot"** — it is a committed flag + a date, a pure predicate.
- **Dependency note:** the *typed* `campaign_family` field is **wh-hxt.14** (deferred P3); until it lands, the
  hot-list keys on a prose/ID match against existing entries (AISEC-SUPPLY-CHAIN-002/003). The re-poll trigger
  works without the typed field — it just keys on the committed family→hosts list, not the schema field.

### Acceptance criteria (draft, for the impl-ticket)
- [ ] A maintainer-repo workflow runs `sec-kb-refresh` on a daily `schedule:` cron + `workflow_dispatch`,
      authenticated via WIF/OIDC (or `CLAUDE_CODE_OAUTH_TOKEN`), with the model step at `contents: read` and
      PR creation scoped to `pull-requests: write` — drafts a PR, never auto-merges (ADR-010/012).
- [ ] Every `uses:` pinned to a commit SHA; `@anthropic-ai/claude-code` pinned (ADR-006/026); `confine_self_
      writes` + the keep-or-revert gate inherited unchanged (ADR-004/009), verified by the PR triggering the
      existing `kb-keep-or-revert-gate`.
- [ ] An hourly hot-family burst job re-polls only the first-detector feeds for families on a committed
      HOT list (deterministic predicate, no LLM), gated behind an `if:` so it is a no-op when no family is HOT.
- [ ] Cross-dep on wh-hxt.9 recorded (socket.dev/stepsecurity.io must be added to `FEED_HOSTS` before the
      burst can reach them) and on wh-hxt.14 (the typed `campaign_family` field is optional, not required).
- [ ] A dated test/dry-run shows the workflow opens a draft PR from recorded feed fixtures (no live network in
      the test; mirror `test_poll_feeds.py`).

---

## Risk & open questions

- **R1 (operator, RQ1):** `/schedule` provisioning for this operator is **unverifiable from outside** — only
  the operator can confirm Claude Code on the web is enabled + routines not admin-disabled. Mitigation: we
  don't depend on it; Actions-cron is the primary.
- **R2 (auth choice):** `CLAUDE_CODE_OAUTH_TOKEN` is a long-lived secret; WIF/OIDC removes it but routes
  billing through a federated account, not the personal subscription. The impl-ticket should default to
  **WIF/OIDC** for supply-chain hygiene and document the trade. (Subscription-billing of the OAuth token in CI
  is **not explicitly documented** — verify empirically before relying on "it bills the sub", or just use WIF.)
- **R3 (research-preview churn):** even as a *follow-up*, the cloud routine's beta header
  (`experimental-cc-routine-2026-04-01`) and limits may change — re-verify at adoption time.
- **R4 (ToS for OAuth-in-CI):** the action docs do **not** flag a ToS concern for `CLAUDE_CODE_OAUTH_TOKEN` in
  CI, but they also don't bless it for unattended cron; if the impl-ticket picks the OAuth path over WIF,
  spot-check Anthropic ToS/usage terms (ask the operator — Ask-First territory).
- **R5 (scheduler-preference reconciliation):** the operator declined `/loop` / in-session schedulers
  (memory `avoid-schedulers-and-loops`). Both adopted options are **out-of-session infra schedulers**
  (Actions-cron / cloud Routine), explicitly NOT the local `/loop` path — this is consistent with the
  preference, but flag it to the operator for an explicit OK on "an Actions cron is fine."
- **R6 (cost):** daily cron × token cost is small (deltas only) but non-zero; the hourly hot-burst multiplies
  it during a hot window. The impl-ticket caps with `--max-turns` + delta-only polling + a HOT-only `if:`.

## Follow-up tickets (propose)
1. **wh-hxt.8(c) impl-ticket** — the workflow above (the RQ4 draft spec). Blocked on this ADR being accepted.
2. **ARCHITECTURE §3.6 amend** — cloud-routine-asserted → cron-now / routine-later (doc-only; not this wave).
3. **(conditional) cloud `/schedule` adoption** — file only if the operator confirms provisioning AND Routines
   reach GA. Carries the same skill + invariants; only the scheduler changes.

## References
- Ground truth: `docs/research/20260610_hades_shai_hulud_pypi.md` §5 RC1; `docs/ARCHITECTURE.md:239-247` §3.6;
  `plugins/white-hacker/skills/sec-kb-refresh/SKILL.md:4-5` + `scripts/poll_feeds.py:69,72-79`;
  `ci/security-review.action.yml:14,29,43,49,61-81`; `docs/research/si-07-threat-feeds.md:7-8`;
  `plugins/white-hacker/hooks/confine_self_writes.py:41-46` (FEED_HOSTS).
- Platform facts (primary, fetched 2026-06-10):
  - Anthropic — *Automate work with routines* (Claude Code Docs): https://code.claude.com/docs/en/routines
  - Anthropic — *Claude Code GitHub Actions* (Claude Code Docs): https://code.claude.com/docs/en/github-actions
  - Anthropic — *claude-code-action setup* (auth methods, OAuth token, WIF):
    https://github.com/anthropics/claude-code-action/blob/main/docs/setup.md
  - InfoQ — *Anthropic Introduces Routines for Claude Code Automation* (2026-05-15):
    https://www.infoq.com/news/2026/05/anthropic-routines-claude/
  - TechTimes — *Claude Managed Agents Add Cron Schedules and Credential Vaults* (2026-06-10):
    https://www.techtimes.com/articles/318163/20260610/claude-managed-agents-add-cron-schedules-credential-vaultsanthropic-beta-puts-agents-autopilot.htm
  - anthropics/claude-code issue #37686 (the `claude -p` + `ANTHROPIC_API_KEY` API-billing gotcha):
    https://github.com/anthropics/claude-code/issues/37686
