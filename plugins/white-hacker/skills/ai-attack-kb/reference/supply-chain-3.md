---
id: AISEC-SUPPLY-CHAIN-003
title: Hades / Miasma PyPI wave (Shai-Hulud lineage) — mass-published wheels that poison AI-assistant config files (.claude/ etc.) for execution persistence
technique_class: supply-chain
severity: high
confidence: 0.75
status: active
date: 2026-06-10
modified: 2026-06-10
review_by: 2026-07-10
metadata:
  source: 'Socket — "Shai-Hulud descends to Hades: Miasma PyPI wave" (2026-06-07); StepSecurity — "The Hades Campaign (PyPI)" (2026-06-08); corroborated by OSV.dev malicious-packages. No CVE/GHSA assigned yet.'
  url: https://socket.dev/blog/shai-hulud-descends-to-hades-miasma-pypi-wave
  retrieved: 2026-06-10
supersedes: null
detections:
  - "poisoned AI-assistant config file present / write-touched — the persistence vector: `.claude/setup.mjs`, `.vscode/tasks.json`, `.vscode/setup.mjs`, `.cursorrules`, `.windsurfrules`, `.cursor/rules/`, `.github/copilot-instructions.md`, `.aider.conf.yml`, `.github/setup.js`, `.github/workflows/codeql.yml` (any holding injected exec/setup instructions; `.claude/setup.mjs` is our own agent's config dir — this list is the scan target for the wh-hxt.11 ai-llm-review config check)"
  - "lockfile/runtime IOCs: marker file `/tmp/.bun_ran` or `/tmp/tmp.*.lock`; systemd USER services `gh-token-monitor.service` / `update-monitor.service` installed (the token-monitor that gates the DISPUTED wiper below)"
  - "a lockfile/manifest resolves a known Hades wheel — the IOC package set is the Socket ∪ StepSecurity UNION and INCOMPLETE from either vendor alone (mostly bioinformatics pkgs, 100k+ cumulative downloads): e.g. `ensmallen` 0.8.101, `embiggen` 0.11.97, `pyphetools` 0.9.120, `rlask` 3.1.4-3.1.7 (StepSecurity); `dynamo-release` 1.5.4, `coolbox` 0.4.1, `ufish`/`napari-ufish`, `bramin` 0.0.2 (Socket) — DO NOT rely on these few; use the full known-compromised watchlist (wh-k6l). Resolved-version match is from the target's OWN lockfile (attacker-editable) → cross-check the manifest pin"
  - "DISPUTED destructive wiper (UNRESOLVED, do not assert either side): StepSecurity reports the gh-token-monitor service triggers `rm -rf ~/; rm -rf ~/Documents` on a token-revoked (HTTP 4xx) response, 72h TTL; Socket inspected the payload and reports a label-only credential-stealer (the string `IfYouYankThisTokenItWillNukeTheComputerOfTheOwnerFully` is a label, not functionality). Operational stance: isolate-before-rotate — never rotate the leaked token while the host is online"
xref: ["LLM03:2025", "AISEC-SUPPLY-CHAIN-002", "AISEC-SUPPLY-CHAIN-001"]
---
Hades / Miasma is a PyPI branch of the **Shai-Hulud → Mini Shai-Hulud → Hades/Miasma** lineage
(parent: AISEC-SUPPLY-CHAIN-002), mass-published 2026-06-07/08 as ~33–37 mostly-bioinformatics
wheels, caught minutes after publication. The evolution that matters to an AI-review agent:
**AI-assistant config-file poisoning is now a first-class persistence vector** — the payload writes
injected exec/setup instructions into `.claude/setup.mjs`, `.vscode/tasks.json`, `.cursorrules`,
`.aider.conf.yml`, etc. (our own agent's config dir included), so a reviewer that inspects only
runtime prompts/RAG misses on-disk bootstrap execution. The destructive **wiper is DISPUTED**:
StepSecurity reports a token-4xx / 72h-TTL `rm -rf ~` wiper; Socket inspected the payload and
reports a label-only credential-stealer — UNRESOLVED, so isolate-before-rotate. The package set is
**union-incomplete** (single-vendor IOC lists are partial); no CVE/GHSA yet.

Detection: see `detections` — poisoned AI-config files (the persistence vector, also the
wh-hxt.11 ai-llm-review scan target), the `/tmp/.bun_ran` + `gh-token-monitor`/`update-monitor`
service IOCs, a lockfile resolving a known Hades wheel (use the wh-k6l watchlist — these few names
are not the whole wave), and the DISPUTED wiper line (surface, do not adjudicate).
Lineage / cross-ref: this is a new wave of the same family as **AISEC-SUPPLY-CHAIN-002** (TeamPCP /
Mini Shai-Hulud) — we tracked the parent and missed this child; the `campaign_family` typed field
is deferred (wh-hxt.14, needs an appended ADR per ADR-019). Sibling: **AISEC-SUPPLY-CHAIN-001**
(slopsquatting / AI-SDK typosquatting) — the name-trust failure preceding this version-trust failure.
Open for triage: adjudicate the wiper at the payload level (read the actual sample, not a vendor
summary) and reconcile the full package set into the watchlist once a union list exists.
