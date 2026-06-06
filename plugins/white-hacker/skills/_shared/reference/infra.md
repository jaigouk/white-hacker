# infra — IaC / container / CI sinks & secure patterns

> Loaded on demand when `SCAN-PLAN.json` reports infra (`docker`, `github-actions`, k8s, Terraform).
> Pattern-first; the IaC capability runs **only when infra is present** (else the stage skips cleanly).
> Tools (Trivy `config`, Checkov, hadolint, zizmor/actionlint) are illustrative — the capability is the
> contract (see [`tool-registry.md`](tool-registry.md)).

## Dockerfile
- **Run as non-root** with a numeric UID (`USER 10001`), not root and not a name that may map to 0.
- **Multi-stage** builds; copy only artifacts into a minimal final image (distroless/slim).
- **Build secrets:** `RUN --mount=type=secret …` — never `COPY`/`ARG` a secret (it persists in layers).
- `.dockerignore` to keep `.git`, `.env`, keys out of the build context.
- **Pin the base image by digest** (`FROM img@sha256:…`), not a floating tag.
```dockerfile
# DANGEROUS                          # SAFE
FROM node:latest                     FROM node:22-slim@sha256:<digest>
USER root                            RUN useradd -u 10001 app
ARG NPM_TOKEN=...                    USER 10001
```

## Kubernetes / Helm
- Enforce **Pod Security Standards "Restricted"**: `runAsNonRoot`, drop `ALL` capabilities,
  `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, no `hostPath`/`hostNetwork`/privileged.
- Render before scanning: `helm template . | trivy config -` (scan the *rendered* manifests).
- No secrets in `ConfigMap`/plain manifests; use a secret store / sealed secrets.

## GitHub Actions / CI
- **Least privilege:** top-level `permissions: contents: read`; widen per-job only as needed; prefer
  OIDC over long-lived cloud creds.
- **`pull_request_target` pwn-requests:** never check out + run untrusted PR code with secrets in scope.
- **No `${{ github.event.* }}` interpolated into `run:`** (script injection) — pass via `env:` and quote.
- **Pin Actions to a full commit SHA**, not a tag (the official Trivy action was compromised twice in
  March 2026). Tools: `zizmor` / `actionlint`.

## Supply chain / provenance
- **SLSA** build provenance (aim L2+ attestations); **Sigstore** keyless signing (`cosign`) + verify on
  pull. Pin tool binaries/images by digest or version; **never auto-install unpinned** (ADR-006); run
  scanners offline where possible (e.g. Trivy `--skip-db-update`).

## What to grep for
`FROM .*:latest` / `USER root` / `ARG .*(TOKEN|SECRET|KEY)` · k8s `privileged: true` / `hostPath` /
missing `runAsNonRoot` · Actions `pull_request_target` + `actions/checkout` of the PR head · `${{
github.event` inside `run:` · `uses: .*@v[0-9]` (tag, not SHA) · base images without `@sha256:`.
