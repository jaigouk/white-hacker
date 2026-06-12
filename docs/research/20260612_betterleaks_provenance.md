# Research: gitleaks → Betterleaks successor claim — provenance verification (2026-06)

**Date:** 2026-06-12
**Author:** white-hacker session (spike executor)
**Spike Ticket:** wh-hv1
**Status:** Final

## Summary
**VERDICT: SOURCED.** The in-repo "gitleaks → Betterleaks" successor claim is TRUE and
authoritatively sourced. Betterleaks is a **drop-in replacement for gitleaks**, created and led by
**Zach Rice — the original author of gitleaks** (~8 years ago) and now Head of Secrets Scanning at
Aikido Security; he started it because he *"no longer has full control over the Gitleaks repository
and name."* MIT-licensed; maintained by Rice + 3 contributors (RBC / Red Hat / Amazon); Aikido
sponsors (not dependent on it). Launched ~2026-03-19. → The `[example-unverified]` tag in
`docs/research/20260612_staleness_signal.md` should be retagged `[primary-sourced]`; the shipped
`tool-registry.md:90` reference becomes provenance-compliant once cited. **No code change** — the
name was never a detection literal (the staleness signal fires on the deterministic `feature_complete`
flag + release cadence).

## Research Question
- **Q1** — Does an authoritative primary source confirm Betterleaks as the gitleaks successor, authored by the gitleaks maintainer? → **Yes.**
- **Q2** — Canonical URL + confirms (a) successor-status AND (b) maintainer authorship? → **Yes, both.**
- **Q3** — If unsourced, genericize/downgrade? → **N/A — it IS sourced; retag `[primary-sourced]`.**

## Confirmed facts (with sources)
- **Successor / drop-in replacement.** HelpNetSecurity (2026-03-19): *"Betterleaks is built to function as a drop-in replacement for Gitleaks, meaning existing CLI flags and configuration files carry over without modification."*
- **Maintainer = the original gitleaks author.** Zach Rice *"wrote the original Gitleaks code approximately eight years ago and now serves as Head of Secrets Scanning at Aikido Security"*; he is the Betterleaks project lead. (HelpNetSecurity · BleepingComputer · Aikido)
- **Reason.** Rice *"no longer has full control over the Gitleaks repository and name, which prompted him to start a new project."* (HelpNetSecurity)
- **License / governance.** MIT; maintained by Rice + 3 (RBC / Red Hat / Amazon contributors); Aikido-sponsored. (Aikido / press)
- **Launch.** ~2026-03-19 — corroborates the already-sourced gitleaks cadence (v8.30.1 = 2026-03-21) in `20260609_trivy_replacement_sca_iac.md:72`: the maintainer's move and the cadence stall are the same event.

## Options Considered
| Option | Pros | Cons |
| --- | --- | --- |
| **A. Retag `[primary-sourced]`** (it IS sourced) | matches the evidence; closes the provenance gap; keeps a true, useful tracking signal | none |
| B. Genericize to "a successor" | would be correct IF unsourced | contradicts the evidence; discards a true signal the MONITOR arm wants |

## Recommendation
**Option A — retag `[primary-sourced]`.** Cite `https://github.com/betterleaks/betterleaks` (primary
artifact) + `https://www.helpnetsecurity.com/2026/03/19/betterleaks-open-source-secrets-scanner/`
(independent, dated) at each in-repo occurrence. No genericization, no code change.

## References
- https://github.com/betterleaks/betterleaks — the Betterleaks repo (primary artifact)
- https://www.helpnetsecurity.com/2026/03/19/betterleaks-open-source-secrets-scanner/ — drop-in replacement; Rice = original gitleaks author; reason; 2026-03-19
- https://www.bleepingcomputer.com/news/security/betterleaks-a-new-open-source-secrets-scanner-to-replace-gitleaks/ — independent corroboration
- https://www.aikido.dev/blog/betterleaks-gitleaks-successor — the author's-org announcement (Rice = Head of Secrets Scanning at Aikido)

## Follow-up Tasks
- [ ] **dev-wh-hxt-18 (FED via SendMessage):** retag `docs/research/20260612_staleness_signal.md` (`:96/:211/:221/:225`) `[example-unverified]` → `[primary-sourced: github.com/betterleaks/betterleaks + helpnetsecurity 2026-03-19]`.
- [ ] **SHIPPED `plugins/white-hacker/skills/_shared/reference/tool-registry.md:90`** — add the citation (operator-gated edit to a shipped reference; the spike's key provenance-compliance AC).
- [ ] Optional backfill (dated working docs, now CONFIRMED, low-value): `20260609_trivy_replacement_sca_iac.md:95/97/347/348`, `20260609_supply_chain_tooling_strategy.md:11/105`, `20260609_tool_admissibility_license_gdpr.md:270/271`. Cite if/when next touched — not blocking.
