# Strategy: supply-chain-resilient tooling — a self-correcting capability lifecycle

**Date:** 2026-06-09 · **Status:** strategy (to be ratified as an ADR via the epic below)
**Owner:** ping@jaigouk.kim

## Why (the problem the point-swap doesn't solve)

This quarter alone: **Trivy** was compromised (TeamPCP, CVE-2026-33634) **and** its `trivy-mcp` wrapper
went **unmaintained with a stale pinned binary**. We are picking replacements (Grype/Checkov/OSV/
gitleaks). But a *point-swap is a treadmill*: those tools can also be compromised, and they can also go
stale — **gitleaks is already feature-complete (→ "Betterleaks")**. white-hacker's whole job is to scan
supply chains; it must not *be* a supply-chain victim (ADR-006), and it must not live in perpetual
firefighting. **The durable solution is to govern tools by a LIFECYCLE so that compromise *and*
staleness are NORMAL, gated, reversible events — not emergencies.**

## The principle

Depend on a **CAPABILITY** (SCA · SCA-image · IaC/misconfig · secrets · SBOM · SAST · …), **never a
brand** (ADR-015). The tools behind each capability are a **living, governed, self-correcting registry**
— the outer self-improving loop (ADR-001) applied to *tooling*, exactly as it keeps the attack-KB
current. Tool churn is the steady state, not the exception.

## CONTAIN — the PRIMARY control (assume-breach / zero-trust execution)

**Selection is not security.** The 5-stage lifecycle below is all *selection + verification* — it asks
"is this tool trustworthy?" But **you cannot verify a tool/dependency is uncompromised**, and 2026 proved
verification-by-reputation is defeatable:

- **Provenance proves ORIGIN, not BEHAVIOR.** Mini Shai-Hulud (May 2026; TanStack/Mistral/OpenSearch)
  victims had valid **SLSA Build L3** provenance + OIDC trusted-publishing + 2FA and were STILL
  compromised — the worm hijacked the *legitimate* pipeline (stole the ambient OIDC token from
  `/proc/<pid>/mem`, signed via real Sigstore). StepSecurity: *"SLSA provenance confirms WHICH pipeline
  produced the artifact, not WHETHER the pipeline was behaving as intended."* The only control that
  stopped it **in flight** was an **egress allowlist** killing the C2. Tool *diversity* is the cited fix
  in **zero** 2026 postmortems.
- **Tag pins are force-pushable** (trivy-action 76/77; tj-actions Mar-2025) — only a **full commit-SHA** holds.

So the durable control is NOT "pick a better tool" — it is **assume the tool IS backdoored and make the
backdoor INERT** by denying the three things it needs. This is the 2026 consensus (NIST SSDF SP 800-218 /
SP 800-204D; CISA-NSA *Defending CI/CD*; OpenSSF S2C2F; SLSA L3 hermetic). The **Agents Rule of Two**
already in `agents/white-hacker.md:39-41` is the seed — elevate it from a posture line to a CONTAIN stage
that **wraps the whole lifecycle**.

### The CONTAIN invariant (the minimum bar)
Run **every** tool — Grype, Checkov, OSV-Scanner, gitleaks, and any future tool — so a compromise cannot
steal secrets or exfiltrate. **At least two of these three must be ABSENT at execution:
{ network/egress · credentials in the tool's env · host write access }.**

| Control | Mechanism (we already have the template) | Defeats |
|---|---|---|
| **Offline / no egress** | `--network none`; offline DB (fetch and analyze are separate, network-off) | exfil / C2 / malicious "DB update" |
| **No creds in the tool env** | no tokens/keys in scanner processes (Agents Rule of Two) | credential theft (LiteLLM/Telnyx import-time exfil) |
| **Sandboxed least-privilege** | `docker/deps-scan-sandbox/run.sh` LOCKDOWN (`--read-only`+tmpfs, `--cap-drop ALL`, `no-new-privileges`, non-root, pid/mem caps, `:ro` mounts); escalate to gVisor/microVM | host compromise / persistence |
| **Pinned + provenance-VERIFIED** | full commit-SHA / image-digest (never a tag) + checksum/cosign/SLSA **verified at admission** | tag force-push / swapped binary |
| **Ephemeral** | container torn down per run (`--rm`) | implant persistence |

**First deliverable:** lift the proven `docker/deps-scan-sandbox/` LOCKDOWN from one skill to a **shared
tool-execution lane** so the WHOLE tool set runs inside it — then a backdoored Grype/Checkov is inert.

### The 5 stages are now DEFENSE-IN-DEPTH under CONTAIN
None survives an *undetected* compromise; **CONTAIN does** (it doesn't depend on knowing what's bad):

| Stage | Reframed as | Honest limit |
|---|---|---|
| ADMIT | lower the *probability* of a bad tool | can't detect a not-yet-known compromise |
| PIN+VERIFY | prove origin + immutability (SHA) | provenance ≠ behavior (Mini Shai-Hulud) |
| DIVERSIFY | survive one vendor's *known* failure | a backdoor you can't see hits all sources; raises surface count |
| MONITOR | shorten MTTR *after* disclosure | reactive — the zero-day window is uncovered |
| RETIRE | clean removal once known-bad | only fires after detection |

### CI hardening (the TeamPCP / Shai-Hulud / tj-actions vector)
Pin Actions to **full commit-SHA** (not tags); minimal `GITHUB_TOKEN` (`contents: read`, per-job); OIDC
short-lived creds scope-pinned to an immutable workflow + protected branch; **egress allowlist**
(Harden-Runner block mode — the control that stopped Mini Shai-Hulud); `--ignore-scripts`; ephemeral
runners; atomic secret rotation. EU CRA: reporting obligations **2026-09-11**, SBOM mandatory — Syft/VEX feed it.

### Sources (2026, primary)
StepSecurity *Mini Shai-Hulud* postmortem (valid provenance still passed; egress-block stopped it) ·
SLSA L3 hermetic (oneuptime 2026-02-09) · NIST SP 800-218 + SP 800-204D · CISA-NSA *Defending CI/CD* ·
OpenSSF S2C2F · GitHub SHA-pin policy (2025-08-15) · EU CRA (reporting 2026-09-11).

## The lifecycle — 5 stages of defense-in-depth (under CONTAIN, the primary layer)

1. **ADMIT** — a tool enters the registry only through four entry gates:
   (a) **License** = MIT/Apache-2.0 only (reject BSD/copyleft/proprietary);
   (b) **Data-egress** = local/offline, no source upload, no default telemetry;
   (c) **Maintenance** = actively maintained — release cadence, last-commit recency, not EOL/feature-
       complete *(NEW gate — the trivy-mcp staleness lesson; staleness ≠ compromise but is its own risk)*;
   (d) **Integrity** = pinnable to a commit-SHA/digest **and** checksum/signature-verifiable.
2. **PIN + VERIFY** — pin every tool to an **immutable ref** (commit-SHA / image-digest / binary
   checksum), **never a mutable version tag** (the Trivy `trivy-action` tags were *force-pushed* — a tag
   pin is defeated; only a SHA holds). Verify checksum/cosign/SLSA at install (ADR-006). **CLI-first thin
   binaries** kept current by the package manager — **no vendored-old-version MCP wrapper layer** (the
   `trivy-mcp` trap; ADR-002 CLI-first / MCP-optional).
3. **DIVERSIFY** — **multi-vendor per capability** so no single maintainer compromise/abandonment takes
   out a whole capability (the validated diversity thesis: Anchore + Palo Alto + Google + independent +
   Red Hat). **Cross-check** across sources (OSV-Scanner sanity-checks Grype). Diversity is a *policy*,
   not an accident. Honest caveat: diversity *raises* the count of supply-chain surfaces → every tool
   still passes PIN+VERIFY.
4. **MONITOR** — the outer loop (`sec-kb-refresh`) continuously polls **two** health signals and proposes
   (human-gated) registry changes *before* a tool becomes a liability:
   (a) **Compromise** advisories — GHSA / OSV.dev / OSSF malicious-packages / CISA → the known-compromised
       watchlist;
   (b) **Staleness/health** — release cadence, last-commit age, EOL/feature-complete/archive signals
       *(NEW — caught gitleaks→Betterleaks, would have caught trivy-mcp)*.
5. **RETIRE + REPLACE** — a **reusable, reversible, gated** process: **quarantine** (demote behind the
   capability interface, degrade to the Read/Grep/Glob floor — ADR-003) → **select** a replacement
   (re-run ADMIT) → **record** the decision (ADR) → **retire**. Trivy is the *first run* of this process;
   the next tool failure must be **routine**, not a fresh investigation.

## How the work maps — CONTAIN (primary) + the lifecycle (defense-in-depth)

| Layer / Stage | Owning ticket | What it delivers |
|---|---|---|
| **CONTAIN (PRIMARY)** | **wh-hxt.3** | the assume-breach ADR + lift the deps-scan-sandbox LOCKDOWN to a shared tool-exec lane (offline/no-creds/sandboxed) + the hardened-CI checklist + live-verify one real tool |
| ADMIT (license + data-egress) | **wh-xn0** | the MIT/Apache + local/no-telemetry gates + registry re-audit |
| PIN+VERIFY (provenance arm of CONTAIN) | **wh-562** | SHA/digest pin + checksum/cosign-verify + the compromised-tool watchlist + the threat-watch feed |
| MONITOR (continuous, target + env) | **wh-5es** | the shared watchlist + deps/IDE-extension checks, install + periodic |
| DIVERSIFY (blast-radius, NOT prevention) | **wh-nvk** | the Trivy→{Grype/Syft, Checkov, OSV-Scanner, gitleaks, kube-linter/actionlint} set |

## The gaps this strategy adds (the genuinely-new pieces)

- **CONTAIN — the assume-breach execution layer (THE load-bearing gap; wh-hxt.3).** Everything else asks
  "is this tool trustworthy?" — but you cannot know, and 2026 proved verification-by-reputation is
  defeatable (Mini Shai-Hulud passed valid SLSA L3 + OIDC + 2FA). The durable control is to run *every* tool
  so a compromise is INERT: offline / no-creds-in-env / sandboxed / pinned-and-verified. We already have the
  template (`docker/deps-scan-sandbox/` LOCKDOWN + the Agents Rule of Two) — the gap is *generalizing* it
  from one skill to a shared tool-exec lane that wraps the whole set, plus the hardened-CI checklist.
- **A MAINTENANCE/STALENESS gate + monitor** — the current threat-watch covers *compromise*; staleness
  is a distinct risk (the trivy-mcp lesson). Add a maintenance-health signal (cadence/last-commit/EOL) to
  the ADMIT gate (wh-xn0) **and** the MONITOR feed (wh-5es).
- **A reusable RETIRE→REPLACE lifecycle process** — Trivy is being retired ad-hoc; codify the
  quarantine→select→record→retire path so the next one is routine (it reuses wh-d5b's quarantine +
  wh-nvk's selection + an ADR).
- **DIVERSITY-by-design as registry policy** — make multi-vendor (≥2 sources for high-value capabilities,
  where a compliant second source exists) a stated registry policy, not a one-off for Trivy.

## Riding the self-improvement loops (leverage them — don't build bespoke)

The supply-chain lifecycle IS the outer loop applied to tooling (ADR-001/015): `/sec-kb-refresh` should be
MONITOR, the self-updating registry/watchlist is ADMIT/RETIRE, `/sec-learn` is the self-correction when a
review FPs or misses a compromised dep, and the INNER loop CONSUMES all of it per review. A file-grounded
audit (6 readers, adversarially verified — 5/6 claims confirmed, 1 over-claim caught) found the loop
*machinery* all exists, but the supply-chain arms are wired to the **KB only**. Verdict: **leverage it — YES,
with wiring.**

### What each stage rides, and its honest state
| Stage | Loop arm | State | Note (file-grounded) |
|---|---|---|---|
| CONTAIN | INNER: PreToolUse egress hooks + the deps-scan sandbox | PARTIAL | sandbox is OPT-IN; **not auto-routed** into a default review (S8 degrades to `[]`) |
| ADMIT | OUTER reflect → tool-registry rows | ASPIRATIONAL | registry is PROSE; no registry-row writer; `patch_merge` wired to nothing |
| PIN+VERIFY | OUTER input → watchlist + ADR-006 pin | PARTIAL | snapshot pin **is** SHA-verified (`fetch-snapshot.sh`); missing = per-ENTRY GHSA/OSV verify + schema gate |
| DIVERSIFY | INNER: `SCANNER_PREFERENCE` + degrade-to-floor | PARTIAL (by design) | capability-not-brand is BUILT; it's defense-in-depth, not the answer |
| MONITOR | INNER `signal_s8` ← OUTER `/sec-kb-refresh` | PARTIAL | watchlist degraded-by-default; **name-only** match; `/sec-kb-refresh` doesn't feed it |
| RETIRE | OUTER: `staleness_check --archive` | PARTIAL | only ages out KB entries; no tool/watchlist retire path |
| INNER consumption | the SCAN-PLAN chain | BUILT | the most-built arm; the gap is entirely on PRODUCING + ACTIVATING |

### The crux: supply-chain DATA needs a SECOND gate (Gate-2)
The eval keep/revert gate (**Gate-1**) governs KB *review-quality* edits — it scores "did adding this
technique improve recall without raising FPR?" against the corpus. It **structurally cannot** score a
watchlist/registry DATA edit (no corpus label measures "did adding compromised-package X help"; `score.py`
consumes only findings-vs-`label.json`). So supply-chain edits ride the SAME draft-PR + confinement +
human-review wrapper but need a DIFFERENT inner verdict: **Gate-2 = primary-source (every entry cites a
GHSA/OSV URL) + OSV-schema validity + regression-green**, deterministic, no LLM/RNG (Rule 5), mirroring
`validate_kb.py`. Reusing Gate-1 for a watchlist edit would be a **false-merit merge**. (Also: the deps-scan
watchlist path isn't in `confine_self_writes` ALLOW_SEGMENTS yet, so the outer loop can't even write it.)

### CONTAIN rides the loop differently — by design
The KB self-edits (text behind an interface). CONTAIN enforcement is CODE (hooks / sandbox / gate), and
`confine_self_writes` FROZEN/CONTROL basenames + default-deny put it **out-of-lane** for self-editing
(identity preservation, Rule 5). CONTAIN improvements therefore arrive as **human-PR'd, TDD'd,
keep-or-revert-gated code diffs**, never as KB text — the outer loop proposes; it cannot self-rewrite the
boundary. Rule-of-Two is preserved: feed-polling has egress but holds no secrets, advisories are parsed as
untrusted *values* via `safe_dump`, and fetch (network-on) is split from analyze (network-none).

### The wiring (rides EXISTING tickets — reuse > create)
- **P0** `/sec-kb-refresh` → watchlist: add an OSSF parser + a `{source-url, package, version, ecosystem}`
  candidate writer (same `safe_dump` untrusted-feed handling) → **EXTENDS wh-5es**.
- **P0** Gate-2 for DATA edits: a deterministic OSV-schema + GHSA/OSV-source validator + put the watchlist in
  the write-lane → **EXTENDS wh-562 + wh-k6l**.
- **P1** version-aware S8 (call `is_known_bad` instead of name-only) → **EXTENDS wh-4k9** (already scoped).
- **P1** auto-route the sealed sandbox when a pinned snapshot + docker are present (S8 default-when-safe) →
  **EXTENDS wh-hxt.3**.
- **P2** ADMIT-via-loop: machine-readable registry + a registry-row writer behind `confine`+`gate_kb_edit` →
  **NEW spike (wh-hxt.4)**.
- **P3** RETIRE path for tools/watchlist entries (not just KB `--archive`) → **EXTENDS wh-hxt.1**.

## Outcome

**Security comes from CONTAINMENT, not selection.** Because every tool runs offline + no-creds + sandboxed +
provenance-verified, a compromise of *any* tool — Trivy, its replacement, or one we haven't picked yet — is
**inert**: it has no secrets to steal and no egress to exfiltrate through, even in the window *before* the
advisory drops. On top of that primary control, tool compromise *and* staleness become **normal, fast,
gated** events handled by the lifecycle (the registry **self-corrects** through the outer loop), and
DIVERSIFY keeps a single-vendor failure from taking out a whole capability. The result: white-hacker stays
current and resilient **without a manual treadmill** — and crucially, **swapping a tool is never the thing
that keeps us safe; the containment lane is.**

## References

- ADR-001 (the two nested loops — this is the outer loop applied to tooling), ADR-002 (CLI-first/MCP-optional),
  ADR-003 (degrade to floor), ADR-006 (pin + verify), ADR-015 (capability layer / self-updating registry), ADR-019 (supply-chain class).
- `docs/research/20260609_trivy_teampcp_supply_chain.md`, `20260609_supply_chain_compromise_monitoring.md`,
  `20260609_trivy_replacement_sca_iac.md` (the per-tool scorecard).
- Spikes/tasks: wh-xn0, wh-562, wh-5es, wh-nvk, wh-d5b, wh-4k9, wh-k6l, wh-q86.
