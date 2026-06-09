# Research: Continuous supply-chain-compromise monitoring (target deps + IDE extensions)

**Date:** 2026-06-09
**Author:** white-hacker (spike grounding)
**Spike Ticket:** wh-5es · **Related:** wh-562 (agent tools), wh-81y (privacy), wh-0vx (onboarding)
**Status:** Draft — **RQ1 (campaign verification) is FINAL**; RQ2–RQ7 (design) are the spike work in wh-5es.

> Materialized ahead of the spike being fully worked because the campaign verification is CONFIRMED +
> sourced + load-bearing. The full design (watchlist schema, the S8 fix, the new extension capability,
> the cadence, the privacy boundary) is the spike's remaining job — see wh-5es.

## Summary

The **TeamPCP / Mini Shai-Hulud** campaign is CONFIRMED across **three surfaces**: poisoned **PyPI/npm
dependencies** (LiteLLM, Telnyx, TanStack), a poisoned **IDE extension** (Nx Console — a surface
white-hacker does **not** scan today), and the resulting **repo/credential theft** (~3,800 GitHub
*internal* repos, exfiltrated *via* that extension). The design (wh-5es): one shared known-compromised
**watchlist** fed by the outer loop (`sec-kb-refresh`), an **inner-loop** check of the target's deps
(deps-scan S8 — mostly exists, needs a small fix) **and** the user's IDE extensions (a NEW
`ide-hygiene` capability), run **at install + a fast SessionStart drift check** (no daemon — honors the
scheduler-aversion + the resource caps).

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

## RQ2–RQ7 — design (open, in wh-5es)

- **RQ2 feeds + ONE shared watchlist** (OSV.dev, GitHub Advisory DB, OSSF malicious-packages, CISA) —
  three entry kinds (`packages` / `extensions` / `repos`) behind one schema, extending `malware_db.py`;
  **reconciled with wh-562** (a single `target:{dependency|tool|extension}` tag, not two feeds);
  human-gated draft-PR only.
- **RQ3 target dep check** — deps-scan S8 mostly exists. **Key finding:** `signal_s8`
  (`supply_chain.py:744`) matches by **NAME only** → a watchlist entry for LiteLLM/TanStack would flag
  *every* user of those popular packages (FP bomb). Fix = match the **lockfile-resolved version** via
  `is_known_bad(name, version, db)` (`malware_db.py:47`) + add an `ecosystem` key. Small, additive.
- **RQ4 NEW IDE/extension scan** — enumerate (`code --list-extensions`, `~/.vscode/extensions/`,
  Cursor/OpenVSX) → check vs the `extensions` watchlist (reuse `is_known_bad`); a new `ide-hygiene`
  capability; degrade to nothing if `code`/dir absent (ADR-003).
- **RQ5 cadence** — **on-demand command + a fast SessionStart drift check; NO daemon/cron/`/loop`**
  (scheduler-aversion + resource caps). CI is opt-in. *(Open user decision: keep SessionStart, or
  CI-only.)*
- **RQ6 install-time wiring** — a factual summary line into the sec-init companion (wh-0vx); the
  watchlist data stays pinned in `reference/`, not in the committed profile.
- **RQ7 privacy** — scanning extensions = scanning the **machine**: explicit consent, read-only,
  no-egress, never store/transmit the extension inventory (only the matches). Reconciled with wh-81y.

## References (primary first)

- GHSA-5mg7-485q-xm76 (LiteLLM) — https://github.com/advisories/GHSA-5mg7-485q-xm76
- GHSA-c9j4-9m59-847w / CVE-2026-48027 (Nx Console) — https://github.com/nrwl/nx-console/security/advisories/GHSA-c9j4-9m59-847w
- GHSA-69fq-xp46-6x23 / CVE-2026-33634 (Trivy) — https://github.com/advisories/GHSA-69fq-xp46-6x23
- TanStack postmortem — https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- Wiz "Mini Shai-Hulud" — https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
- Nx postmortem — https://nx.dev/blog/nx-console-v18-95-0-postmortem
- GitHub repo-breach link — https://www.bleepingcomputer.com/news/security/github-links-repo-breach-to-tanstack-npm-supply-chain-attack/
- OSSF malicious-packages (Apache-2.0, OSV) — https://github.com/ossf/malicious-packages
- Repo anchors — `deps-scan/scripts/malware_db.py:26,47`, `supply_chain.py:744`, `deps-scan/SKILL.md:80-84`, `sec-init/SKILL.md`, `sec-kb-refresh/SKILL.md`.

## Follow-up

- [x] Campaign verification (RQ1) recorded here.
- [ ] wh-5es — RQ2–RQ7 design + the ADR + the EPIC/5-child breakdown.
