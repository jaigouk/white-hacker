# Research: "Hades" / Miasma PyPI wave — the Shai-Hulud lineage evolves (2026-06)

**Status:** VERIFIED (two independent vendor-research primary sources) · **Date:** 2026-06-10
**Confidence:** HIGH on existence + lineage + AI-config-poisoning; **DISPUTED** on the wiper (see §3).
**Why this doc exists:** dogfood RCA — our system did **not** surface this; a human pasted a Reddit
screenshot. Hades is a new wave of the **Mini Shai-Hulud / Miasma** family we already treat as
load-bearing in ADR-024 and `AISEC-SUPPLY-CHAIN-002`. We tracked the parent and missed the child.
Materialized here per the repo convention (confirmed, sourced threat-intel → `docs/research/`).

## Primary sources (verified 2026-06-10 by WebFetch)
- StepSecurity — *The Hades Campaign (PyPI)* (2026-06-08): https://www.stepsecurity.io/blog/the-hades-campaign-pypi-packages
- Socket — *Shai-Hulud descends to Hades: Miasma PyPI wave* (2026-06-07): https://socket.dev/blog/shai-hulud-descends-to-hades-miasma-pypi-wave
- Corroborating press (not independently fetched): The Hacker News, CSO Online.
- ORIGINAL TIP (unverified, **embellished** — recorded as a discipline lesson): a Reddit r/ClaudeAI
  screenshot + an LLM "synthesized remediation guide." Its core IOCs (`/tmp/.bun_ran`,
  `gh-token-monitor`) are CONFIRMED below; its package names (`pantheon-agents`, `magique-ai`,
  `executor-engine`) and "stygian-cerberus" repo branding match **neither** vendor list → real-core
  wrapped in plausible synthesis. The verification gate is what separated the two.

## 1. What is confirmed (both sources agree)
- **Real + lineage.** Socket: "best understood as a PyPI branch of the same **Mini Shai-Hulud / Miasma**
  lineage, not a standalone incident"; detected "minutes after publication" by AI malware analysis.
  StepSecurity: "the latest evolution of the **Miasma** threat actor." Mass-published 2026-06-07/08;
  PyPI quarantined some by press time.
- **AI-assistant config poisoning is a first-class persistence vector** (the evolution that matters to
  us). Union of named artifacts:
  - **`.claude/setup.mjs`** (Socket) — *our agent's own config directory.*
  - `.cursorrules`, `.windsurfrules`, `.cursor/rules/`, `.github/copilot-instructions.md`,
    `.aider.conf.yml`, `.vscode/tasks.json`, `.vscode/setup.mjs` (StepSecurity)
  - `.github/setup.js`, `.github/workflows/codeql.yml` (Socket)
- **Lockfile / service IOCs.** `/tmp/.bun_ran`, `/tmp/tmp.*.lock`; systemd user services
  `gh-token-monitor.service`, `update-monitor.service` (StepSecurity).
- **NO CVE / GHSA IDs yet** (both). Provenance today = the vendor IOC posts + PyPI quarantine + the
  OSV.dev `malicious-packages` feed (which ingests these) — **not** a GHSA advisory. See §5.

## 2. The package set — INCOMPLETE from any single source (this is itself the lesson)
The two first-detectors report **different counts and largely different names** — neither is the whole
wave:
- **StepSecurity: 33 packages** — e.g. `ensmallen` 0.8.101, `embiggen` 0.11.97, `gpsea` 0.9.14,
  `pyphetools` 0.9.120, `rlask` 3.1.4–3.1.7.
- **Socket: 37 wheels across 19 packages** — e.g. `dynamo-release` 1.5.4, `spateo-release`, `coolbox`
  0.4.1, `ufish`, `napari-ufish`, `bramin` 0.0.2.
- **Overlap is partial; the real IOC set is the UNION** (mostly bioinformatics packages with
  100k+ cumulative downloads). **A watchlist built from ONE vendor would miss half the wave** →
  direct validation of the multi-feed root cause (RC2 below).

## 3. CONFLICT — surfaced, not averaged (Policy 7): is there a destructive wiper?
The two credible vendors **directly contradict** on the most operationally loaded fact:
- **StepSecurity: YES.** "If the token is revoked (returning a 4xx HTTP status), the service triggers
  a destructive wiper" — script `rm -rf ~/; rm -rf ~/Documents`, 72-hour TTL before activation. (This
  is the basis of the "do NOT rotate keys while online" advice.)
- **Socket: NO.** "a credential stealer, **not** destructive malware." The scary string
  `IfYouYankThisTokenItWillNukeTheComputerOfTheOwnerFully` is "a **string label only**, not actual
  destructive functionality."
- **UNRESOLVED.** Socket inspected the payload directly ("minutes after publication"); StepSecurity may
  be describing capability/intent or a different sample. **Adjudication requires reading the actual
  payload, not a vendor summary** — a KB entry must resolve this, not pick a side. **Operational stance:
  treat the wiper as POSSIBLE** (isolate-before-rotate costs little; being wrong is catastrophic) while
  **labeling the claim DISPUTED** in any entry we ship.

## 4. Exposure assessment
The relevant exposure surfaces for any consumer of this campaign are: poisoned AI-assistant config
files (§1), the lockfile/service IOCs, and a lockfile resolving any Hades wheel. The design-level
defenses are the minimal-dependency posture, the SessionStart factual-only allowlist, and the
`confine_self_writes` boundary — the gap a defender should close is **knowing** (currency), not a
specific in-the-wild hit. *(Any concrete machine/environment self-audit is kept in local working notes
— not committed to this public repo.)*

## 5. System implications — the RCA, with the verified evidence (dogfood)
We track the **parent** (`AISEC-SUPPLY-CHAIN-002`, TeamPCP / Mini Shai-Hulud, dated 2026-06-09) but
have no path to the **child** wave 1–2 days later. Four root causes, each → a corrective ticket:

- **RC1 — the loop is open (root).** `sec-kb-refresh` is `disable-model-invocation:true`, "never
  self-fires"; the scheduled routine + T-8.3 capture hooks are unwired. Ingestion today = a human
  noticing on social. **Fix: wire the scheduled currency arm.** (The keystone — content fixes a
  non-running loop needs re-doing by hand each time.)
- **RC2 — feed gap: first-detectors absent.** Socket.dev / StepSecurity / Phylum break PyPI/npm waves
  days before OSV/GHSA — and we already *hand-cited* StepSecurity for ADR-024 without ever wiring them
  as a feed (`si-07`). The 33-vs-37 split proves single-vendor IOC lists are partial. **Fix: add them
  to `si-07`.**
- **RC3 — static-IOC model, no lineage tracking.** A campaign *family* (Shai-Hulud → Mini → Hades/
  Miasma) that re-waves with new packages defeats a frozen list + a 90-day `review_by`. **Fix: a dated
  KB entry `AISEC-SUPPLY-CHAIN-003` (Hades, `campaign_family: shai-hulud`, the §3 wiper marked
  DISPUTED) + a re-poll trigger for active families.**
- **RC4 — detection-class gap: AI-config-file poisoning.** We model what the model *reads at runtime*
  (prompts, tool descriptions, RAG), not the on-disk agent-config that bootstraps execution — the exact
  `.claude/setup.mjs` / `.vscode/tasks.json` vector Hades uses. **Fix: an `ai-llm-review` check that
  scans a target's AI-assistant config files for injected exec instructions.**

**Gate-2 design note (feeds wh-hxt.5):** Hades has **no GHSA yet**, so the watchlist validator's
"required GHSA/OSV advisory URL per entry" must accept the **OSV.dev `malicious-packages` feed** and a
**vendor-advisory host allowlist** (socket.dev / stepsecurity.io), not GHSA alone — else a real,
quarantined campaign is un-admittable for days. Refine wh-hxt.5's provenance allowlist accordingly.

## 6. Provenance / honesty
Two primary vendor sources fetched 2026-06-10; the Reddit tip is unverified and partly embellished
(recorded as the verification-discipline lesson). The wiper is DISPUTED between credible vendors and
must be adjudicated at the payload level before any entry asserts it. No exploit code here (defender's
catalog). Pairs with `AISEC-SUPPLY-CHAIN-001/002`, ADR-024 (CONTAIN), `spike-09-npm-ai-supply-chain`.
