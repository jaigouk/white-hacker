# Spike-09: npm AI supply-chain — detectable signals + remediation (2026-06)

> **Defensive-security context.** white-hacker is an authorized white-hat code-review agent. This
> spike catalogs **detection signals and remediation** for supply-chain malware in a developer's
> *own* dependency tree — a defender's checklist, **not** an attack guide, and it contains **no
> working exploit code**. Signal patterns are quoted from public vendor advisories
> (Microsoft / Unit42 / CISA / OSSF) so the agent can *recognize* a malicious package, never author one.

**Status:** RESOLVED
**Date:** 2026-06-08
**Confidence:** HIGH for the offline signals + remediation ladder (every signal is grepped/parsed
from on-disk `package.json`/lockfiles and is corroborated by 2026 vendor incident reports + canonical
npm/OSSF/GitHub docs); MEDIUM on exact incident counts (they moved fast — Mini Shai-Hulud went 4 → 160+
packages in weeks; the *signal patterns* are stable even where a count is approximate).
**Author:** white-hacker agent
**Related:** `deps-scan` (this spike feeds its **floor**, not the native gate), ADR-006 (tool
supply-chain pinning / hygiene), ADR-015 (swappable capability layer — these signals plug *behind* the
SCA capability), `ai-attack-kb` (the technique entries this spike sources), spike-01 (Trivy pinning).

---

## Question

The `deps-scan` skill today finds **known-CVE** vulnerable deps (native gate → OSV/Trivy → floor). It
has a **blind spot**: novel *malicious* packages (typosquats, slopsquats, install-script malware,
self-propagating worms) are not in a CVE database when they land, so `npm audit`/OSV-by-CVE miss them.
This spike produces **offline, grep/parse-able signals** + a **remediation ladder** so `deps-scan`'s
floor can flag supply-chain-malware *candidates* (low/medium confidence, `tool_assisted:false`),
without a network call and without blocking. Resolve:

1. **What are the 2024–2026 npm AI-supply-chain attack techniques**, and which specifically target
   AI/LLM developers (Anthropic/OpenAI/LangChain/HuggingFace SDKs, Claude Code, MCP)?
2. **Which signals are offline-detectable** in `package.json` / `package-lock.json` / `pnpm-lock.yaml`
   / `yarn.lock`? For each: what to grep/parse, false-positive risk, confidence.
3. **What authoritative feeds & tooling** keep this current, mapped to ADR-015 capabilities, and which
   are **offline-usable** vs **network-only** (incl. `npm audit`'s blind spot)?
4. **What is the remediation ladder** ("what to do") when a suspicious package is found, by urgency?

### Out of scope
- Implementing the detector (follow-up ticket in the Recommendation).
- Network-time behavioral analysis (Socket-style) — we are a static, offline-first agent (ADR-007).

---

## F1 — Attack techniques (2024–2026), AI-developer emphasis

| Technique | Mechanism | AI/LLM angle | Source |
|---|---|---|---|
| **Self-propagating worm (Shai-Hulud lineage)** | Malware in an infected pkg's **`preinstall`** harvests CI/CD + cloud tokens, then re-publishes weaponized versions of *other* packages the stolen token can push — a true worm. | "Mini Shai-Hulud" (Apr–May 2026) hit AI/dev ecosystems incl. **Mistral AI**, TanStack, UiPath, OpenSearch; harvests `~/.claude/mcp.json`, `~/.claude.json` as credentials. | Microsoft (2025-12-09); Akamai; StepSecurity; Unit42 (upd. 2026-06-02) |
| **Typosquatting of AI/popular SDKs** | Publish a lookalike name; dev mistypes or copy-pastes. | OpenSearch/Elastic clients typosquatted (May 2026); the general technique applies directly to `@anthropic-ai/sdk`, `openai`, `langchain`/`@langchain/*`, `llamaindex`, `@huggingface/*`. | Microsoft (2026-05-28) |
| **Slopsquatting (LLM-hallucinated names)** | LLM invents a plausible-but-nonexistent pkg name; attacker pre-registers it; dev pastes the AI's install command. | **AI-native.** ~1 in 5 AI code suggestions reference a nonexistent pkg; **205,474** unique fabricated names catalogued; 43% of hallucinations *repeat* (predictable → pre-registerable). `react-codeshift` spread to **237 repos** (Jan 2026) via AI agent skill files, nobody planting it. | CSA (2026-04-19); Aikido; arXiv 2605.17062 |
| **Malicious lifecycle scripts** | `preinstall`/`postinstall`/`install` run code at `npm install` time — *before* tests/checks, on dev laptops + CI runners. | The delivery vector for nearly every 2026 incident; malicious React Native releases (Mar 2026) used obfuscated `preinstall`. | Splunk; Kodem; Unit42 |
| **Maintainer-account / npm-token compromise** | Phished/stolen 2FA or publish token → push malware under a *trusted* name (no typo needed). | AntV (300+ pkgs via one compromised maintainer, 2026); the worm *automates* this via stolen OIDC/publish tokens. | Snyk; CISA (2025-09-23) |
| **Dependency confusion (substitution)** | Publish a **public** package with the same name as an org's **internal/private** one, at a higher version; the resolver prefers the public one. | 33 malicious npm pkgs (May 2026) spoofed internal corporate scopes + enterprise URLs; GitHub's npm *malware advisories* are "**mostly** substitution attacks." | Microsoft (2026-05-29); GitHub Advisory docs |
| **Bun-runtime evasion** | `preinstall` drops `setup_bun.js` → installs **Bun** → runs `bun_environment.js` (node→shell→bun→payload) to dodge Node-centric monitoring. | Used by Shai-Hulud 2.0; harvests cloud creds with embedded **TruffleHog**. | Microsoft (2025-12-09) |
| **Protestware** | Maintainer ships disruptive/destructive behavior on their *own* legit package (geo-targeted wipes, console spam). | Not AI-specific, but same lifecycle-script + name-trust surface; included for completeness. | (technique class — flag via the same script/obfuscation signals) |

**Takeaway:** the *delivery* funnels through **install-time lifecycle scripts** and **name trust**
(typo/slop/scope). Those are exactly what a static `package.json`/lockfile reader can see offline.

---

## F2 — Offline-detectable signals (the detector spec)

All signals are computed from on-disk files with **zero network**. Each is a *candidate*, not a verdict
— consistent with `deps-scan` floor semantics (`tool_assisted:false`, capped confidence, triage decides).
"FP risk" = how often a benign repo trips it.

| # | Signal | What to grep / parse | FP risk | Confidence | Notes |
|---|---|---|---|---|---|
| **S1** | **Lifecycle install script present** | Parse `package.json` → `scripts.{preinstall,install,postinstall}` exists (and, for deps, scan `node_modules/*/package.json` if present). | **HIGH** (many legit native pkgs use them: `esbuild`, `sharp`, `bcrypt`). | LOW alone | A *necessary-not-sufficient* gate. Only escalates when combined with S5/S6/S7. |
| **S2** | **Dep specified as git/http/tarball URL, not registry semver** | For each dep string in `dependencies`/`devDependencies`/`optionalDependencies`: flag values matching `^(git\+|git:|https?:|github:|file:)` or ending `.tgz`/`.tar.gz`, i.e. NOT a `semver`/range/`npm:` alias. | MEDIUM (monorepos use `file:`/`workspace:`; some pin `github:`). | MEDIUM | Worms used `optionalDependencies` git refs (`github:tanstack/router#<sha>`). Treat `workspace:`/`file:` to in-repo paths as benign; flag remote git/http. |
| **S3** | **Unpinned ranges with NO lockfile committed** | `package.json` has `^`/`~`/`*`/`latest` ranges **and** no `package-lock.json`/`pnpm-lock.yaml`/`yarn.lock` in repo. | MEDIUM (early-stage repos legitimately lack a lockfile). | LOW–MEDIUM | Enables silent pull of a freshly-published malicious version (the worm's "rapid consume" window). Pair with the `minimumReleaseAge` recommendation (F4). |
| **S4** | **Typosquat / slopsquat distance to a curated AI-SDK allowlist** | Damerau-Levenshtein distance 1–2 (or keyboard-adjacency) between each dep name and a **curated allowlist** of known-good AI/popular names (`@anthropic-ai/sdk`, `openai`, `langchain`, `@langchain/core`, `llamaindex`, `@huggingface/inference`, `@modelcontextprotocol/sdk`, `react`, `axios`, `next`, …). Distance 0 = exact match = SAFE. | MEDIUM (distance-1 neighbors can be legit, e.g. `react`↔`preact`). | MEDIUM (≥2 corroborating fields → HIGH) | **Slopsquat extension:** also flag names the allowlist says don't exist but *look* like an AI tool (`huggingface-cli`, `unused-imports`, `react-codeshift`). Keep the allowlist in `reference/` so KB-refresh can extend it (ADR-015). |
| **S5** | **Scoped-name confusion (separator/homoglyph)** | Normalize scope/name: detect `@anthropic_ai` vs `@anthropic-ai`, hyphen↔underscore swaps, doubled chars, and non-ASCII homoglyphs (Cyrillic `а`/`е`/`о`, Greek `ο`) in pkg names. Flag any dep whose ASCII-folded, separator-normalized form **collides** with an allowlist entry but the raw string **differs**. | LOW | **HIGH** | Homoglyph/separator collisions are almost never legitimate — high-signal. |
| **S6** | **Dangerous APIs inside an install script** | If S1 true, read the referenced script file(s) and grep for `eval(`, `new Function(`, `child_process`/`exec`/`spawn`, `require('net'|'http'|'https'|'dns')`, `fetch(`, `Buffer.from(...,'base64')`, env-exfil of `~/.ssh`/`~/.aws`/`~/.npmrc`/`~/.claude`. | LOW (legit installs rarely `eval` + network + base64 together). | **HIGH** when ≥2 hit | This is the strongest single offline tell. The worm's `bun_environment.js`, `setup_bun.js`, and the `bun.sh/install` download URL match here. |
| **S7** | **Obfuscated / minified install code** | For each install-script file: flag (a) single-line file > ~50 KB; (b) any file > ~1 MB (worm droppers were 4.29 MB); (c) hex-identifier density (`_0x[0-9a-f]{4,}`) above a threshold; (d) a `binding.gyp` that contains JS/shell beyond normal gyp (Miasma v2's 157-byte `binding.gyp` exec trick). | LOW–MEDIUM (some legit minified vendored code). | MEDIUM–HIGH | Combine with S6; obfuscation **plus** a network/eval call is near-certain. |
| **S8** | **Local malicious-package match (OSSF/GHSA offline DB)** | If a cloned OSSF `malicious-packages` / GHSA-malware OSV snapshot is on disk, match each dep `name@version` against it. | NONE (exact match). | **HIGH** (it's a known-bad list) | Network-free *iff* the DB was pre-cloned (F3). This is the only signal that yields a confirmed verdict offline. |

**Scoring rule (for the detector):** emit a candidate when **any HIGH-confidence signal fires** (S5, S6,
S8) **or** when **≥2 lower signals corroborate** (e.g. S1+S6, S2+S7, S4+S1). A lone S1/S3 is informational
only. Always `tool_assisted:false`, `category:"supply-chain"`, `access_required:"unknown"` — triage and a
human decide; the floor **never blocks** (matches `deps-scan` SKILL.md:27–29).

---

## F3 — Feeds & tooling, mapped to ADR-015 capabilities (offline vs network)

| Source / tool | Capability (ADR-015) | What it gives | Offline-usable? | Source |
|---|---|---|---|---|
| **OSSF `malicious-packages`** (`github.com/ossf/malicious-packages`, **Apache-2.0**) | SCA / supply-chain-malware feed | OSV-format JSON of confirmed-malicious npm/PyPI pkgs; daily updated; covers typosquat, ATO, dep-confusion, malicious binaries. | **YES** — clone repo, parse `./osv/**/*.json` locally (S8). Pin the clone commit (ADR-006). | github.com/ossf/malicious-packages |
| **GitHub Advisory DB — *malware* advisories** (`github/advisory-database`, OSV JSON) | SCA / malware feed | npm-**exclusive** malware advisories, auto-fed from the npm security team; "mostly substitution attacks." | **YES** — clone/snapshot the OSV JSON; parse offline. | github/advisory-database; GitHub docs |
| **npm provenance / Sigstore attestations** (`npm publish --provenance`) | provenance verification | Links a pkg to its source repo + build (OIDC short-lived cert → Sigstore transparency log); two attestations (provenance + publish). **Proves origin, NOT absence of malware** (npm docs say so explicitly). | **PARTIAL** — `package-lock.json` can be parsed offline to see *whether* a dep has registry signatures recorded; full `npm audit signatures` verification hits the registry/Sigstore (**network**). Use as a *positive trust* signal, not a blocker. | docs.npmjs.com/generating-provenance-statements |
| **Socket.dev** | behavioral SCA (network) | Analyzes pkg *behavior* (70+ red flags), blocks in PR. Catches what CVE DBs don't. | **NO** — network/API. Out of our static scope (ADR-007); note as an escalation tool in the registry. | socket.dev |
| **OpenSSF Scorecard** | repo hygiene | Maintenance/2FA/branch-protection signals for a dependency's *source repo*. | **NO** (queries GitHub). Registry-only reference. | openssf scorecard |
| **`npm audit` / `pnpm audit`** (the existing native gate) | SCA by **known CVE** | Known-CVE vulns in the tree. | network (registry). | — |

**The blind spot (the reason this spike exists):** `npm audit` checks deps against **known CVEs**, not
behavior — novel malware (e.g. `rendition`, `vs-deploy`, malicious React Native releases in 2026) has a
**valid version, installs without error, and is not in any CVE DB**, so `npm audit` **approves it**.
F2's static signals + the offline OSSF/GHSA malware DBs (S8) are how `deps-scan` covers that gap without
adding a network dependency or a single-vendor coupling (ADR-015).

**Ecosystem cooldown defense (recommend, don't implement):** npm `min-release-age` (npm ≥ **v11.10.0**,
`.npmrc`, value in days), pnpm `minimumReleaseAge` (v10.16+), Yarn `npmMinimalAgeGate` (4.10.0+), Bun —
all reject versions younger than N days, defeating the worm's "rapid-consume-before-takedown" window.
This is config advice the agent can *recommend* in a finding's remediation, not something it scans for.

---

## F4 — Remediation ladder ("what to do"), by urgency

When a suspicious package is flagged, walk this ladder (urgency-ordered; map each finding's
`recommendation` to the relevant rung):

0. **Do not install/build yet.** If the repo is uninstalled, run `npm ci --ignore-scripts` (or
   `pnpm`/`yarn` with scripts disabled) so lifecycle hooks can't execute during triage. (ADR-007: static
   first; this keeps the agent itself out of harm's way.)
1. **Confirm intended vs actual name.** For S4/S5 hits, verify the dep name char-by-char against the
   allowlist / the official SDK docs. A separator/homoglyph mismatch (S5) = stop and treat as malicious.
2. **Check the offline malware DBs (S8).** Match `name@version` against the cloned OSSF
   `malicious-packages` + GHSA-malware OSV snapshot. A hit = confirmed; escalate to removal immediately.
3. **Verify provenance/attestation** (network, optional). `npm audit signatures` to see if the pkg has a
   Sigstore provenance/publish attestation. Absence on a pkg that *claims* an official origin is a red
   flag; presence is *positive* but **not** proof of safety (npm docs).
4. **Pin + commit the lockfile.** Replace floating ranges with exact versions and commit
   `package-lock.json`/`pnpm-lock.yaml`/`yarn.lock`; recommend `min-release-age`/`minimumReleaseAge`
   cooldown in `.npmrc`/config to close the rapid-consume window (F3).
5. **Remove or replace.** Delete the malicious/typosquatted dep; install the *correct* package by exact
   name; clear `node_modules` + the lockfile entry and reinstall with `--ignore-scripts`.
6. **Rotate any exposed credentials.** If the malicious pkg's install script ran (S1+S6 indicate
   token/cred harvesting — npm/GitHub/AWS/GCP/Azure/Vault tokens, SSH keys, `~/.claude*`), assume
   compromise: rotate every token reachable from that machine/CI runner. (Worm payloads exfiltrate on
   first install.)
7. **Report upstream.** File to OSSF `malicious-packages` (PR) and/or report the pkg to npm/GitHub so a
   GHSA *malware* advisory is issued — closing the loop so the next scan's S8 catches it by name.

The agent **proposes** these (writes them into the finding's `recommendation` / a `PATCHES/` note);
it **does not** auto-remove, auto-rotate, or push (capability removed — CLAUDE.md security posture).

---

## F5 — Generalizing beyond npm (the capability is ecosystem-agnostic)

npm is the **lead example** (the 2026 incident surface is hottest there), but every signal is a
property of *a manifest + a lockfile + install/build hooks* — present in every package ecosystem.
Build the detector as an **ecosystem-agnostic signal core + a per-ecosystem adapter**: the adapter
normalizes that ecosystem's files into `{deps:[{name, spec, source_type}], lifecycle_scripts,
lockfile_present, script_files}`; the S1–S8 signals + scoring are shared. Map:

| Signal | npm | PyPI (pip/poetry/uv) | RubyGems | Go | Cargo | Maven/Gradle |
|---|---|---|---|---|---|---|
| Manifest / lockfile | package.json / package-lock,pnpm-lock,yarn.lock | pyproject,requirements / poetry.lock,uv.lock | Gemfile / Gemfile.lock | go.mod / go.sum | Cargo.toml / Cargo.lock | pom.xml,build.gradle / — |
| **S1** install/build hook | `pre/post/install` scripts | `setup.py` arbitrary code at build | native ext `extconf.rb` | (none; `go generate`) | `build.rs` | plugin `exec`/`antrun` |
| **S2** non-registry source | git/http/tarball dep | `git+https`, direct URL, `file://` | `git:`/`path:` in Gemfile | `replace`→fork, non-proxy | `git`/`path` dep | system/file-scope dep |
| **S4/S5** typosquat / homoglyph | vs npm allowlist | vs PyPI allowlist | vs gem allowlist | vs module-path allowlist | vs crate allowlist | vs `groupId:artifactId` |
| **S8** known-bad DB | OSSF malicious-packages (OSV) | **same DB** (covers PyPI) | **same DB** | **same DB** | **same DB** | partial |

**Consequence for scope:** ship the **generic core + npm adapter first** (npm incidents are critical
right now); PyPI / RubyGems / Go / Cargo / Maven adapters are follow-on tickets behind the same
interface — no redesign, just a new parser each. The allowlists + ecosystem map live in
`deps-scan/reference/` so `/sec-kb-refresh` extends them as knowledge (ADR-015), exactly like the
attack KB.

---

## Recommendation for white-hacker

**Build a static, offline `deps-scan` *floor* augmentation** ("supply-chain-malware heuristics") behind
the existing **SCA capability** (ADR-015) — NOT a new top-level skill, and NOT a replacement for the
native CVE gate. It runs when the native gate / OSV-by-CVE has nothing to say about *malware*, reads only
on-disk files, emits **low/medium-confidence `tool_assisted:false` candidates**, and **never blocks**
(matches `deps-scan` SKILL.md:27–29). Triage and a human decide.

Concretely:
1. A pure-function module (Rule 5: deterministic, no LLM) that parses `package.json` + the three
   lockfiles and emits S1–S8 candidates → normalized into `VULN-FINDINGS.json`
   (`category:"supply-chain"`, `owasp:["A06:2021"]`), reusing `normalize_deps.py`'s shape.
2. A curated **allowlist** of AI/popular package names in `deps-scan/reference/` (so `/sec-kb-refresh`
   can extend it exactly as it extends the attack KB — ADR-015's self-updating registry).
3. An **optional** pre-cloned OSSF/GHSA malware OSV snapshot for S8 (pinned commit, ADR-006); degrade
   gracefully to S1–S7 when it's absent (`tools_unavailable: ["malware-db"]`).
4. Each finding's `recommendation` references the F4 ladder rung; the agent proposes, never executes.

**Decision drivers satisfied:** simplicity-first (stdlib JSON/regex over `package.json`, no new runtime
dep); graceful degradation (every signal works at the floor; S8 degrades cleanly; ADR-003); no
single-tool coupling (Socket/Scorecard stay *network escalations* in the registry, not hard deps —
ADR-015); supply-chain pinning (pin any cloned DB — ADR-006); static-default (ADR-007, the
`--ignore-scripts` rung keeps us read-only).

## Risk & follow-up

- **FP risk on S1/S3** (lifecycle scripts and missing lockfiles are common). *Mitigation:* never report
  S1/S3 alone — informational only; require corroboration (≥2 signals) before a candidate.
- **Allowlist staleness** — slopsquat/typosquat detection is only as good as the curated list. *Mitigation:*
  put it in `reference/` and wire `/sec-kb-refresh` to extend it; the OSSF/GHSA S8 DB is the authoritative
  backstop.
- **S8 DB drift** if the pinned snapshot ages. *Mitigation:* record the snapshot commit + date in the
  finding; recommend a refresh cadence (KB-refresh).
- **Incident counts are approximate** (fast-moving) — the spike pins *signal patterns*, not counts.
- **Follow-up ticket** (propose via `/design-ticket`): "deps-scan supply-chain-malware floor heuristics
  (S1–S8) + AI-SDK allowlist + optional OSSF/GHSA OSV snapshot," TDD with fixtures (a typosquat repo, a
  homoglyph scope, an obfuscated `preinstall`, a benign native-build pkg that must NOT trip), validated
  against `validate_findings.py`.

---

## Sources

**Incidents / techniques (2025–2026):**
- [Microsoft Security — Shai-Hulud 2.0 detection guidance](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/) — `setup_bun.js`/`bun_environment.js`, preinstall, TruffleHog cred harvest (fetched 2026-06-08)
- [Microsoft Security — Typosquatted npm packages steal cloud/CI secrets](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/) — typosquat name pairs, preinstall, AWS/Vault/npm-token harvest (fetched 2026-06-08)
- [Microsoft Security — 33 malicious npm packages abuse dependency confusion](https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/) — internal-scope spoofing, pre/postinstall C2 beacon (fetched 2026-06-08)
- [Unit42 (Palo Alto) — The npm Threat Landscape (upd. 2026-06-02)](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) — git-URL optionalDependencies, obfuscation markers, `~/.claude` harvest, Mistral targeting (fetched 2026-06-08)
- [Akamai — Mini Shai-Hulud worm returns and goes public](https://www.akamai.com/blog/security-research/mini-shai-hulud-worm-returns-goes-public) (fetched 2026-06-08)
- [StepSecurity — Shai-Hulud hits AntV ecosystem](https://www.stepsecurity.io/blog/shai-hulud-here-we-go-again-mass-npm-supply-chain-attack-hits-the-antv-ecosystem) (fetched 2026-06-08)
- [Snyk — Mini Shai-Hulud hits AntV: 300+ malicious npm packages](https://snyk.io/blog/mini-shai-hulud-antv-npm-supply-chain-attack/) (fetched 2026-06-08)
- [CISA — Widespread Supply Chain Compromise Impacting npm](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) (fetched 2026-06-08)
- [Splunk — Defending Against npm Supply Chain Attacks (detection/analysis)](https://www.splunk.com/en_us/blog/security/npm-supply-chain-attack-detection-analysis.html) (fetched 2026-06-08)
- [Kodem — Malicious React Native npm releases](https://www.kodemsecurity.com/resources/malicious-react-native-npm-releases-trigger-supply-chain-exposure) — obfuscated preinstall, Mar 2026 (fetched 2026-06-08)

**Slopsquatting (AI-native):**
- [Cloud Security Alliance — Slopsquatting research note (2026-04-19)](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_slopsquatting-ai-supply-chain_20260419-csa-styled-1.pdf) — 205,474 fabricated names; ~1-in-5 rate (fetched 2026-06-08)
- [Aikido — Slopsquatting: the AI package hallucination attack](https://www.aikido.dev/blog/slopsquatting-ai-package-hallucination-attacks) — `unused-imports`, `react-codeshift` 237 repos (fetched 2026-06-08)
- [arXiv 2605.17062 — Re-evaluating LLM Package Hallucinations (2026 frontier cohort)](https://arxiv.org/abs/2605.17062) — 5.2%–21.7% hallucination rate, repeat-rate (fetched 2026-06-08)

**Feeds & tooling (currency, ADR-015):**
- [OSSF malicious-packages (Apache-2.0, OSV format, daily, offline-cloneable)](https://github.com/ossf/malicious-packages) (fetched 2026-06-08)
- [GitHub — github/advisory-database (OSV JSON; npm-exclusive *malware* advisories)](https://github.com/github/advisory-database) (fetched 2026-06-08)
- [GitHub Docs — About the GitHub Advisory database (malware = "mostly substitution attacks")](https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database) (fetched 2026-06-08)
- [npm Docs — Generating provenance statements (`--provenance`; "does not guarantee no malicious code")](https://docs.npmjs.com/generating-provenance-statements) (fetched 2026-06-08)
- [Socket.dev — npm minimumReleaseAge & bulk OIDC config](https://socket.dev/blog/npm-introduces-minimumreleaseage-and-bulk-oidc-configuration) — npm v11.10.0 `min-release-age` (fetched 2026-06-08)
- [Configuring minimum release age across npm, pnpm, yarn, bun (craigory.dev, 2026-05-29)](https://craigory.dev/blog/2026-05-29/package-manager-release-cooldown/) (fetched 2026-06-08)
- [pnpm — Mitigating supply chain attacks (minimumReleaseAge, trust policy)](https://pnpm.io/supply-chain-security) (fetched 2026-06-08)
- [PkgPulse — Why npm audit is broken (CVE-only blind spot)](https://www.pkgpulse.com/guides/why-npm-audit-is-broken) (fetched 2026-06-08)
