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

## The lifecycle — 5 stages, each a control

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

## How the existing work maps to the lifecycle

| Stage | Owning ticket | What it delivers |
|---|---|---|
| ADMIT (license + data-egress) | **wh-xn0** | the MIT/Apache + local/no-telemetry gates + registry re-audit |
| PIN+VERIFY + compromise-MONITOR | **wh-562** | SHA/digest pin + checksum/cosign-verify + the compromised-tool watchlist + the threat-watch feed |
| MONITOR (continuous, target + env) | **wh-5es** | the shared watchlist + deps/IDE-extension checks, install + periodic |
| DIVERSIFY (current instantiation) | **wh-nvk** | the Trivy→{Grype/Syft, Checkov, OSV-Scanner, gitleaks, kube-linter/actionlint} set |

## The gaps this strategy adds (the genuinely-new pieces)

- **A MAINTENANCE/STALENESS gate + monitor** — the current threat-watch covers *compromise*; staleness
  is a distinct risk (the trivy-mcp lesson). Add a maintenance-health signal (cadence/last-commit/EOL) to
  the ADMIT gate (wh-xn0) **and** the MONITOR feed (wh-5es).
- **A reusable RETIRE→REPLACE lifecycle process** — Trivy is being retired ad-hoc; codify the
  quarantine→select→record→retire path so the next one is routine (it reuses wh-d5b's quarantine +
  wh-nvk's selection + an ADR).
- **DIVERSITY-by-design as registry policy** — make multi-vendor (≥2 sources for high-value capabilities,
  where a compliant second source exists) a stated registry policy, not a one-off for Trivy.

## Outcome

Tool compromise *and* staleness become **normal, fast, gated** events handled by the lifecycle, not
emergencies. The capability registry **self-corrects** through the outer loop. white-hacker stays current
and resilient **without a manual treadmill** — and a TeamPCP-style hit on any one vendor degrades one
capability gracefully instead of breaking the pipeline.

## References

- ADR-001 (the two nested loops — this is the outer loop applied to tooling), ADR-002 (CLI-first/MCP-optional),
  ADR-003 (degrade to floor), ADR-006 (pin + verify), ADR-015 (capability layer / self-updating registry), ADR-019 (supply-chain class).
- `docs/research/20260609_trivy_teampcp_supply_chain.md`, `20260609_supply_chain_compromise_monitoring.md`,
  `20260609_trivy_replacement_sca_iac.md` (the per-tool scorecard).
- Spikes/tasks: wh-xn0, wh-562, wh-5es, wh-nvk, wh-d5b, wh-4k9, wh-k6l, wh-q86.
