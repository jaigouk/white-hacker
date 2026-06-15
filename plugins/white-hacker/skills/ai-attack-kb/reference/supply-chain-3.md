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
  - "deadman-switch / kill-switch SHAPE in a referenced install/CI script (static SIGNAL-ONLY, never-block, human-triaged — flags for review, asserts NO malice): the systemd USER-service IOC (`gh-token-monitor` / `update-monitor.service`) co-present with a 2nd destructive primitive in ONE script. The deps-scan S6 DETECTOR pairs this IOC with the DISPUTED `rm -rf ~` wiper sink (or any standalone dangerous-API S6 pattern) for its 2nd distinct count; `~/Library/LaunchAgents` is human-review/IR persistence narrative ONLY (see the recovery note below) and is NOT a deps-scan detector primitive — it is self-authored IR context, not a Socket/StepSecurity vendor-primary IOC, so it fails the primary-source gate and false-HIGHs a benign macOS daemon-installer. The kill-switch (execution-skip gated on a token-4xx / 72h-TTL response) is the SAME deadman mechanism keyed to response content — do NOT add a broad `4\\d\\d` regex (matches any 400-499 → huge FP); recognize it via the specific service/sink IOCs above. wh-5ox.8 deps-scan S6: ≥2 distinct → HIGH; recognizing the wiper literal stays DISPUTED, it does not adjudicate"
  - "environment-gated-payload SHAPE (geofencing / region-gated detonation; static SIGNAL-ONLY, ≥2-distinct → S6 HIGH): a locale/TZ/region read (`Intl.DateTimeFormat`, `process.env.TZ`, `process.env.LANG`, `navigator.language` — benign stdlib primitives ALONE) GATING a destructive sink (`child_process`, `rm -rf ~`, `exec(`, `spawn(`). Match as ONE `\\A`-anchored co-occurrence (gate AND sink) so a LONE locale read NEVER reaches HIGH; a 2nd independent primitive supplies the 2nd distinct count. App-code analogue: sec-vuln-scan should treat an env/locale-gate→destructive-sink as a gate+sink CORRELATION, not a lone-sink HIGH (NOTE the split: the human-review gate+sink correlation — a locale/TZ read gating `child_process`/`exec`/`spawn`/`rm -rf ~` — is handled per `core-checklist.md` §8 [human-triaged], while the automated deps-scan S6 DETECTOR keys specifically on the locale-gated `rm -rf ~` wiper to stay low-FP, since the broad execution sinks are already standalone S6 patterns)"
xref: ["LLM03:2025", "AISEC-SUPPLY-CHAIN-002", "AISEC-SUPPLY-CHAIN-001", "AML.T0010 [primary-sourced: https://atlas.mitre.org/techniques/AML.T0010]", "T1195.002 [primary-sourced: https://attack.mitre.org/techniques/T1195/002/]", "T1552.005 [primary-sourced: https://attack.mitre.org/techniques/T1552/005/]"]
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
Static install-script SHAPES (wh-5ox.8 deps-scan S6 — signal-only, never-block, human-triaged,
≥2-distinct-pattern → HIGH): (1) the **deadman/kill-switch** — the `gh-token-monitor`/`update-monitor.service`
USER-service IOC co-present with a 2nd destructive primitive (the deps-scan S6 detector uses the DISPUTED
`rm -rf ~` wiper sink or any standalone dangerous-API pattern; `~/Library/LaunchAgents` is human-review/IR
persistence narrative only — see the recovery note — NOT a deps-scan detector primitive); the kill-switch
(execution-skip on a token-4xx / 72h-TTL response) is the SAME mechanism keyed to response content — never
a bare `4\d\d` regex (FP). (2) the
**environment-gated payload** — a locale/TZ/region read (`Intl.DateTimeFormat` / `process.env.TZ` /
`process.env.LANG` / `navigator.language`, benign ALONE) GATING a destructive sink, matched as ONE
`\A`-anchored gate+sink co-occurrence so a lone locale read can never reach HIGH. Recognizing the
wiper literal is NOT adjudicating it — it stays DISPUTED.
Lineage / cross-ref: this is a new wave of the same family as **AISEC-SUPPLY-CHAIN-002** (TeamPCP /
Mini Shai-Hulud) — we tracked the parent and missed this child; the `campaign_family` typed field
is deferred (wh-hxt.14, needs an appended ADR per ADR-019). Sibling: **AISEC-SUPPLY-CHAIN-001**
(slopsquatting / AI-SDK typosquatting) — the name-trust failure preceding this version-trust failure.
Open for triage: adjudicate the wiper at the payload level (read the actual sample, not a vendor
summary) and reconcile the full package set into the watchlist once a union list exists.

## Recovery / IR note — `host-level — outside static-review scope, advisory only`

> This is **operator/IR guidance, not a static-source-review finding**. A static reviewer of the
> tree CANNOT confirm any of the live-host conditions below (running daemon, scraped memory, live
> C2) — see the static-source-vs-EDR scope boundary in `sec-threat-model/SKILL.md`. Surface this as
> advisory only; route execution to the host owner / IR responder, never claim it as static coverage.
> Ordering below is **DISPUTED** (single community source); we adopt **isolate-FIRST** as the
> primary, no-egress-safe sequence and recommend NO third-party "safe-revocation" endpoint.[^revoke]

1. **Isolate FIRST, then rotate (the disputed-ordering call).** The DISPUTED wiper (line 20) is
   gated on a token-revoked (HTTP 4xx) response — so rotating/revoking the leaked token **while the
   host is online** could be the very trigger. **Isolate the host from the network first**
   (pull it off-net), confirm the trigger daemon is dead, and only **then** rotate, from a
   **different, clean host**. This is the existing isolate-before-rotate stance, made operational.
2. **Confirm the daemon is dead; do NOT power off.** Remove/disable the persistence services BEFORE
   rotating: macOS `~/Library/LaunchAgents/*.plist` (`launchctl bootout`), Linux systemd **user**
   units `gh-token-monitor.service` / `update-monitor.service` (`systemctl --user disable --now`).
   **Do not power the host off** — preserve volatile memory (the OIDC-token / payload evidence lives
   there; ADR-024's primary case was an OIDC token scraped from `/proc/<pid>/mem`). Snapshot memory
   for IR before any reboot.
3. **Immutable-config trap.** Persistence files may be set immutable so a naive delete fails
   silently — clear the flag first: Linux `chattr -i <file>`, macOS `chflags nouchg <file>`. Treat a
   "delete succeeded" with no follow-up verify as suspect.
4. **Rotation scope (in this order, only after isolation).** GitHub PAT(s) → npm **publish** tokens
   (plus a registry publish-log audit for rogue versions) → AWS Secrets Manager **across all
   regions** (region-scoping is a common miss). Rotate from the clean host; assume every secret the
   compromised process could read is burned.
5. **Exfil-repo discovery.** Hunt for **attacker-created private repos** in the incident window
   (the campaign stages exfil into fresh private repos): list repos created/pushed under the
   compromised account during the exposure window and treat any unrecognised one as exfil.

[^revoke]: Do **not** route rotation/revocation through any third-party "safe-revocation endpoint."
    Such an endpoint is **C2-shaped** (it phones an external host with a live credential) and
    violates the no-egress / CONTAIN posture (ADR-024 — the egress allowlist was the
    only control that stopped the analogous Mini Shai-Hulud worm in flight). Revoke directly at the
    provider console/API from a clean host instead.
