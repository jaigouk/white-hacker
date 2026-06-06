# research:supplychain-iac

> Source: workflow `white-hacker-research` (wycjclbk6), agent `research:supplychain-iac`

## 2026 Supply-Chain, Container & IaC Security for Code Review

This section equips a generic white-hat review agent to flag supply-chain, container, and IaC risks across TS/Go/Python/Java, backend/frontend/AI repos. The 2026 threat backdrop: the **Shai-Hulud npm worm** (Sept 2025, 500+ packages), **Shai-Hulud 2.0** (Nov 2025, 25,000+ malicious GitHub repos, ~350 users), and **Mini Shai-Hulud** (May 2026, 170+ npm + 2 PyPI packages, 404 malicious versions) — self-replicating worms that steal npm/GitHub PAT tokens and auto-republish. Plus the **tj-actions/changed-files** compromise (March 2025, CVE-2025-30066) where a mutable tag on a transitive action (`reviewdog/action-setup`) poisoned thousands of pipelines ([Wiz](https://www.wiz.io/blog/github-actions-security-guide), [Unit42](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)). The lesson for review: **mutable references and broad-scope tokens are the dominant attack vector.**

### 1. Dockerfile Review Checklist

| Check | Bad | Good |
|---|---|---|
| Non-root user | runs as root (default) | `USER 10001` (numeric UID) + chown app files |
| Base image pinning | `FROM node:20` | `FROM node:20.18.1-slim@sha256:<digest>` (digest, not tag) |
| Build-time secrets | `ARG TOKEN` / `ENV API_KEY=...` / `COPY .env .` | `RUN --mount=type=secret,id=npmrc ...` (BuildKit tmpfs, never layered) |
| Minimal final image | single-stage with build tools shipped | multi-stage; final = `distroless`/`alpine`/`chainguard` |
| Layer secret leakage | `COPY` key then `RUN rm key` (still in layer) | secret only in discarded intermediate stage |
| `.dockerignore` | absent → `.git`, `.env`, `node_modules` copied in | excludes `.env`, `.git`, secrets, `*.pem`, `node_modules` |
| `latest` tag | `FROM x:latest` | explicit version + digest |
| `ADD` from URL | `ADD https://... /` (no checksum, auto-extract) | `COPY` for local; `ADD --checksum=sha256:...` if remote |
| HEALTHCHECK / `--no-install-recommends` | missing | present; pin apt/apk package versions |

**Key facts:** Secrets copied into any intermediate layer persist even after `rm` — the August 2025 XZ backdoor lingered in dozens of Debian-based Docker Hub images because teams pinned mutable tags; digest-pinners caught it immediately ([BellSoft](https://bell-sw.com/blog/docker-image-security-best-practices-for-production/), [Sysdig](https://www.sysdig.com/learn-cloud-native/dockerfile-best-practices)). BuildKit `RUN --mount=type=secret` mounts to `/run/secrets/<id>` via tmpfs for one RUN only ([Docker Docs](https://docs.docker.com/build/building/secrets/)).

**Tools:** `hadolint Dockerfile` (linter), `trivy image --scanners vuln,secret,misconfig <img>`, `dockle <img>` (CIS), `docker scout cves <img>`, `grype <img>`.

### 2. Kubernetes / Helm Misconfiguration

Flag in manifests/charts: `privileged: true`, `hostPID/hostIPC/hostNetwork: true`, `hostPath` volumes, missing `runAsNonRoot: true`, missing `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation` not false, dropped capabilities absent (`capabilities.drop: ["ALL"]`), no `resources.limits` (DoS), `automountServiceAccountToken: true` when unused, secrets in `values.yaml` plaintext, wildcard RBAC (`verbs: ["*"]`/`resources: ["*"]`), `:latest` image tags, and `Pod Security Standards` below **Restricted** for app workloads ([k8s PSS](https://kubernetes.io/docs/concepts/security/pod-security-standards/), [Wiz](https://www.wiz.io/academy/container-security/kubernetes-security-context-best-practices)).

**Helm caveat (2026):** Scanning *raw* templates with Go placeholders yields false positives and misses conditional misconfigs. **Render first, then scan:** `helm template . -f values.yaml | trivy config -` or pipe to checkov/kubescape, and scan per-environment values ([AquilaX](https://aquilax.ai/blog/helm-chart-security-misconfigurations)).

**Tools:** `trivy config <dir>` (manifests + Helm), `kubescape scan` (KSPM, NSA/CIS frameworks), `checkov -d . --framework kubernetes helm`, `kube-bench` (CIS host).

### 3. Terraform / IaC Scanning — 2026 Tool Status

| Tool | 2026 Status | Command |
|---|---|---|
| **Trivy** v0.70.0 (Aqua) | Active; absorbed all tfsec checks; `AVD-` IDs carry over | `trivy config .` |
| **Checkov** v3.2.5xx (Palo Alto) | Active; 1,000+ policies inc. 800 graph/cross-resource; compliance (CIS/SOC2/HIPAA/PCI/NIST) | `checkov -d . --framework terraform` |
| **tfsec** | **Deprecated** — merged into Trivy (2024); no new checks; migrate to `trivy config` | (legacy only) |
| **Terrascan** | **Archived** by Tenable Nov 2025 — no CVE fixes; do not adopt | (avoid) |
| **KICS** (Checkmarx) | Active alternative, multi-IaC | `kics scan -p .` |

Recommendation: run **Trivy + Checkov** as parallel CI jobs — Trivy for unified code-to-cluster, Checkov for cross-resource graph analysis and compliance reports ([env0](https://www.env0.com/blog/best-iac-scan-tool-comparing-checkov-vs-tfsec-vs-terrascan), [Spacelift](https://spacelift.io/blog/terraform-scanning-tools)). Also flag: hardcoded secrets in `.tf`/`.tfvars`, public S3/storage, `0.0.0.0/0` ingress, unencrypted volumes/DBs, IAM `*:*`, state files in VCS.

### 4. CI/CD — GitHub Actions Security

**Review checklist:**
- **Pin every action to a full 40-char commit SHA**, not `@v4`/`@main` — the only immutable reference. Include transitive actions (the tj-actions vector). Use Dependabot/Renovate to bump SHAs.
- **Least-privilege `permissions:`** — set top-level `permissions: contents: read`, escalate per-job only as needed. Flag workflows with no `permissions` block or `write-all`.
- **`pull_request_target` / `workflow_run`** = pwn-request risk: they run with secrets + write token in the *base* repo context. Flag any that **checkout/build/execute untrusted PR head code**. Prefer `pull_request` (no secrets for forks).
- **Script injection**: never interpolate `${{ github.event.* }}` (PR title, body, branch name, comments) directly in `run:` — route through `env:` vars then reference `"$VAR"`.
- **OIDC over long-lived secrets**: cloud auth via `id-token: write` + short-lived federated tokens (AWS/GCP/Azure), not stored access keys.
- **Secret hygiene**: no `echo` of secrets; mask non-GitHub secrets with `::add-mask::`; never store JSON/YAML blobs as one secret; restrict `pull_request` from forks from accessing secrets; review for exfiltration to unexpected hosts.
- **`self-hosted` runners on public repos** = RCE risk from fork PRs — flag.

**2026 GitHub roadmap (review-relevant):** *Workflow dependency locking* (a `dependencies:` lockfile pinning direct+transitive SHAs, like `go.sum`; preview 3-6mo, GA ~6mo), *immutable action releases*, *scoped secrets* (bind creds to repo/branch/env/identity), *policy-driven execution* (ruleset actor/event rules), and a *native L7 egress firewall* for GitHub-hosted runners (preview 6-9mo) ([GitHub Blog](https://github.blog/news-insights/product-news/whats-coming-to-our-github-actions-2026-security-roadmap/), [GitHub Docs](https://docs.github.com/en/actions/reference/security/secure-use)).

**Tools:** `zizmor` (GH Actions static analyzer, 2026 standard), `actionlint`, `octoscan`, Trivy/`pinact` for SHA pinning, `gitleaks`/`trufflehog` for secret scanning, `poutine` (CI/CD pipeline scanner).

### 5. SLSA / Provenance, Sigstore/Cosign, SBOM

**SLSA** current spec is **v1.0** (with v1.1 in progress); Build Track L0–L3: L1 basic (may be unsigned) provenance, L2 hosted build + platform-signed provenance, L3 hardened/isolated build with strong tamper protection. GitHub's built-in attestations + slsa-github-generator reach **L2 quickly** ([slsa.dev](https://slsa.dev/spec/v1.0/levels), [AquilaX](https://aquilax.ai/blog/supply-chain-artifact-signing-slsa)).

**Sigstore** = Cosign (sign/verify) + Fulcio (short-lived OIDC certs) + Rekor (transparency log) → **keyless signing** (no long-lived keys). Review for:
- Releases/images **signed** and **verified at deploy/admission** (Kyverno/cosign policy), not just signed.
- **Provenance attestation** present (proves *how/where* built) in addition to SBOM (lists *what's inside*).
- **SBOM generated and attested**: `syft <img> -o cyclonedx-json` (or SPDX) → attest with `actions/attest-sbom` (now wrapped by `actions/attest`) and `actions/attest-build-provenance`. Verify: `cosign verify-attestation --type cyclonedx <img>` / `cosign verify <img> --certificate-identity ... --certificate-oidc-issuer https://token.actions.githubusercontent.com`. Scan SBOMs continuously: `grype sbom:sbom.json` ([Chainguard](https://edu.chainguard.dev/open-source/sigstore/cosign/how-to-sign-an-sbom-with-cosign/), [actions/attest-sbom](https://github.com/actions/attest-sbom), [Anchore](https://anchore.com/sbom/creating-sbom-attestations-using-syft-and-sigstore/)).

### Quick "tools to run" summary
```
hadolint Dockerfile                       # Dockerfile lint
trivy image --scanners vuln,secret,misconfig <img>
trivy config .                            # IaC + Helm + k8s (tfsec successor)
checkov -d . --framework terraform kubernetes
helm template . -f values.yaml | trivy config -   # render then scan
kubescape scan                            # KSPM
zizmor / actionlint .github/workflows     # CI/CD
gitleaks detect / trufflehog filesystem . # secret scan
syft <img> -o cyclonedx-json | grype      # SBOM + vuln
cosign verify-attestation / cosign verify # provenance/signature
```


## Key takeaways

- Mutable references are the #1 supply-chain vector in 2026: pin Docker base images by sha256 digest and pin every GitHub Action (including transitive ones) to a full commit SHA — driven by tj-actions (CVE-2025-30066) and the XZ-backdoored Docker Hub images.
- Self-replicating npm/PyPI worms (Shai-Hulud Sept 2025, 2.0 Nov 2025, Mini May 2026) steal npm tokens and GitHub PATs to auto-republish — flag long-lived publish tokens, broad-scope PATs, and missing 2FA/provenance on packages.
- Dockerfile review essentials: non-root numeric USER, multi-stage builds, BuildKit RUN --mount=type=secret (never ARG/ENV/COPY .env), a .dockerignore excluding secrets, and no secret left in any intermediate layer.
- IaC tool landscape changed: tfsec is deprecated (merged into Trivy, AVD- IDs carry over via `trivy config`), Terrascan was archived by Tenable Nov 2025 — recommend Trivy + Checkov in parallel; Checkov adds graph/cross-resource and compliance checks.
- Kubernetes/Helm: enforce Pod Security Standards 'Restricted', flag privileged/hostPath/hostNetwork/hostPID, missing runAsNonRoot+readOnlyRootFilesystem, no resource limits, wildcard RBAC, and secrets in values.yaml.
- Always render Helm before scanning (`helm template | trivy config -`) — scanning raw Go-template charts produces false positives and misses conditional misconfigs.
- GitHub Actions code-review must-haves: top-level least-privilege permissions (contents: read), OIDC instead of long-lived cloud keys, and treating pull_request_target/workflow_run that checkout untrusted PR code as critical pwn-request findings.
- Script injection: never interpolate ${{ github.event.* }} (PR title/body/branch) directly in run: blocks — route through env: and quote the variable.
- 2026 GitHub roadmap adds workflow dependency lockfiles (SHA-pinned, go.sum-style), immutable actions, scoped secrets, policy-driven execution, and a native egress firewall — agents should recommend these as they GA.
- Supply-chain provenance is now table stakes: SLSA L2 is achievable quickly with GitHub attestations + slsa-github-generator; verify signatures/provenance at deploy time (not just sign), distinguishing SBOM (what) from provenance (how/where).
- Sigstore keyless signing (Cosign + Fulcio + Rekor) avoids long-lived keys; review should check artifacts are signed AND verified via admission policy (Kyverno/cosign), with attestations recorded in Rekor.
- SBOM generation should be in CI for every artifact (syft -> CycloneDX/SPDX, attested via actions/attest) and continuously scanned (grype) — language-agnostic across TS/Go/Python/Java.
- Toolbelt to run generically: hadolint, trivy (image+config), checkov, kubescape, zizmor/actionlint, gitleaks/trufflehog, syft+grype, cosign — these cover Dockerfiles, IaC, k8s/Helm, CI/CD, secrets, and SBOM/provenance across all stacks.

## Sources

- https://bell-sw.com/blog/docker-image-security-best-practices-for-production/
- https://www.sysdig.com/learn-cloud-native/dockerfile-best-practices
- https://docs.docker.com/build/building/secrets/
- https://zeonedge.com/blog/docker-security-best-practices-2026-hardening-containers-build-runtime
- https://www.env0.com/blog/best-iac-scan-tool-comparing-checkov-vs-tfsec-vs-terrascan
- https://spacelift.io/blog/terraform-scanning-tools
- https://kubernetes.io/docs/concepts/security/pod-security-standards/
- https://www.wiz.io/academy/container-security/kubernetes-security-context-best-practices
- https://aquilax.ai/blog/helm-chart-security-misconfigurations
- https://spacelift.io/blog/kubernetes-security-tools
- https://docs.github.com/en/actions/reference/security/secure-use
- https://www.wiz.io/blog/github-actions-security-guide
- https://github.blog/news-insights/product-news/whats-coming-to-our-github-actions-2026-security-roadmap/
- https://securebin.ai/blog/github-actions-pwn-request-attack/
- https://unit42.paloaltonetworks.com/npm-supply-chain-attack/
- https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/
- https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
- https://slsa.dev/spec/v1.0/levels
- https://aquilax.ai/blog/supply-chain-artifact-signing-slsa
- https://edu.chainguard.dev/open-source/sigstore/cosign/how-to-sign-an-sbom-with-cosign/
- https://github.com/actions/attest-sbom
- https://anchore.com/sbom/creating-sbom-attestations-using-syft-and-sigstore/

