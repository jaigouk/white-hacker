---
id: AISEC-SUPPLY-CHAIN-002
title: Imposter-commit + tag force-push + CI-secret pivot — compromising dev/security tooling supply chains (TeamPCP / Mini Shai-Hulud 2026)
technique_class: supply-chain
severity: high
confidence: 0.8
status: active
date: 2026-06-09
modified: 2026-06-09
review_by: 2026-09-09
metadata:
  source: GitHub Advisories GHSA-69fq-xp46-6x23 (Trivy CVE-2026-33634), GHSA-5mg7-485q-xm76 (LiteLLM), GHSA-c9j4-9m59-847w (Nx Console CVE-2026-48027)
  url: https://github.com/advisories/GHSA-69fq-xp46-6x23
  retrieved: 2026-06-09
supersedes: null
detections:
  - "GitHub Action / tool pinned to a mutable version tag (e.g. `uses: org/action@v2` or `tool@v0.69`) instead of a full commit-SHA or image digest — a tag pin that can be force-pushed is no pin"
  - "installed artifact (binary/image/package) consumed without verifying its checksum or signature (cosign / GPG) against the publisher's expected value"
  - "installed/locked dependency version matches a known-compromised watchlist (the deps-scan S8 signal): Trivy v0.69.4-.6 / trivy-action 76-77, LiteLLM 1.82.7-1.82.8, Telnyx 4.87.1-4.87.2, ~42 @tanstack/* packages, nrwl.angular-console v18.95.0 — caveat: a specific-version match resolves the version from the target's OWN lockfile, which is attacker-controlled and can be edited to mask the bad version, so the manifest pin warrants a human cross-check rather than trusting the resolved version alone; wildcard (name-only) watchlist entries are unaffected"
  - "CI workflow grants a broad GITHUB_TOKEN or keeps long-lived SSH/cloud/K8s/Docker/Git secrets in the runner environment with no egress allowlist (the runner-memory-dump / secret-harvest blast surface)"
xref: ["LLM03:2025", "AML.T0010 [primary-sourced: https://atlas.mitre.org/techniques/AML.T0010]", "T1195.002 [primary-sourced: https://attack.mitre.org/techniques/T1195/002/]", "T1552.005 [primary-sourced: https://attack.mitre.org/techniques/T1552/005/]"]
---
A breached maintainer/bot account (incomplete credential rotation) is used to force-push imposter
commits over existing release **tags** — mutable refs — and to publish malicious binaries/images;
the payload then dumps CI-runner memory and harvests SSH/cloud/K8s/Docker/Git secrets and pivots to
private repos and infrastructure (the TeamPCP / Mini Shai-Hulud 2026 worm). The key lesson:
version-**tag** pinning is DEFEATED by force-push — only commit-SHA, image-digest, or
artifact-checksum pinning is immutable. Valid provenance (SLSA L3 + OIDC + 2FA) did NOT prevent it,
because the worm rode the legitimate pipeline; **containment** — egress denial and no ambient
secrets in the runner — is what limits blast radius. Confirmed: Trivy (CVE-2026-33634), LiteLLM,
Telnyx, ~42 @tanstack/* packages, and Nx Console (CVE-2026-48027; ~3,800 repos exfiltrated).

Detection: see `detections` — mutable-tag pins (no SHA/digest), unverified checksum/signature at
install, locked versions matching the known-compromised watchlist (deps-scan S8), and CI hardening
gaps (broad GITHUB_TOKEN, long-lived runner secrets, no egress allowlist).
Checklist: maps to the deps-scan supply-chain floor (S8 known-compromised-version signal; pin-to-SHA
/ digest + signature verification) and to CI-workflow hardening — re-pin every Action and tool to an
immutable commit-SHA or image digest, verify artifact signatures, and run with a minimal token, no
ambient secrets, and an egress allowlist so a riding payload cannot exfiltrate.
Sibling: AISEC-SUPPLY-CHAIN-001 (slopsquatting / AI-SDK typosquatting) — the name-trust failure that
precedes this version-trust failure.
