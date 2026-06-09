# Research: Trivy / TeamPCP supply-chain compromise — verification, exposure, response

**Date:** 2026-06-09
**Author:** white-hacker (spike grounding)
**Spike Ticket:** wh-562 · **Interim action:** wh-d5b
**Status:** Draft — **RQ1 (verification) + RQ2 (exposure) are FINAL**; RQ3–RQ6 (interim-quarantine
decision, the TeamPCP pattern, the integrity-gate + threat-watch design, the KB entry) are the
remaining spike work, tracked in wh-562.

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

## RQ3–RQ6 — open (tracked in wh-562)

- **RQ3 interim quarantine** → decoupled to **wh-d5b** (demote Trivy in `SCANNER_PREFERENCE` →
  OSV/Grype/govulncheck for SCA, Checkov for IaC; fail-safe behind the capability interface,
  ADR-015/003; reversible once a safe pinned+verified version is cleared).
- **RQ4 TeamPCP pattern** → which other registry tools share the "widely-used tooling" risk profile.
- **RQ5 integrity gate + threat-watch** → a per-tool pinned **SHA/digest + checksum-verify** + a
  **known-compromised watchlist** (extends `malware_db.py` with digests) + a `sec-kb-refresh` feed arm;
  its **own ADR** (next available number) referencing the admissibility spike wh-xn0. Shares the ONE
  watchlist/feed with the target-side monitoring spike wh-5es.
- **RQ6 KB entry** → `AISEC-SUPPLY-CHAIN-002` (TeamPCP imposter-commit / tag-force-push / CI-secret
  pivot) under ADR-019, via the `sec-kb-refresh` draft-PR gate (human-gated, never auto-merge).

## References (primary first)

- Aqua advisory — https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/
- GHSA-69fq-xp46-6x23 / CVE-2026-33634 — https://github.com/advisories/GHSA-69fq-xp46-6x23
- Microsoft Security — https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/
- Unit 42 (TeamPCP campaign) — https://unit42.paloaltonetworks.com/teampcp-supply-chain-attacks/
- Wiz — https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack
- Sysdig (campaign spread to KICS) — https://www.sysdig.com/blog/teampcp-expands-supply-chain-compromise-spreads-from-trivy-to-checkmarx-github-actions
- Repo anchors — `plugins/white-hacker/skills/deps-scan/SKILL.md:44`, `_shared/reference/tool-registry.md:50-53`, `deps-scan/scripts/supply_chain.py` (no Trivy subprocess), `sec-detect/scripts/detect_tools.py:110-119` (`SCANNER_PREFERENCE`).

## Follow-up

- [x] Verification (RQ1) + exposure (RQ2) recorded here.
- [ ] wh-d5b — interim quarantine (do-now).
- [ ] wh-562 — RQ3–RQ6 design + the ADR + the KB entry.
