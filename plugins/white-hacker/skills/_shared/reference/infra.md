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

> **Why these hardening checks matter — shared-kernel → host escape** (spike-10): a container is **not**
> a VM. Every container on a host **shares the one host kernel**, so a single kernel CVE turns a
> weakly-confined container into a **host escape** — the 2024–2026 LPE wave repeatedly demonstrated
> "kernel bug ⇒ container breakout." The checklist above (run as non-root + numeric UID, drop `ALL`
> capabilities, no `--privileged` / `CAP_SYS_ADMIN`, no `hostPID`/`hostNetwork`/`hostPath`,
> `allowPrivilegeEscalation: false`, digest-pinned base image) **is** the mitigation: it shrinks the
> kernel-syscall attack surface a compromised container can reach. A container that runs `--privileged`
> or adds `CAP_SYS_ADMIN` effectively re-shares the host kernel with near-root reach — that is the case
> where the kernel-adjacency advisory note (below) matters most. **Out of scope:** auditing the host
> kernel itself, eBPF bytecode verifier-safety, or kernel memory-safety (Rule 5 — fuzzer/specialist work;
> use `kernel-hardening-checker`/KSPP for host config, syzkaller/Buzzer for kernel/eBPF bugs).

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

### Kernel/container trust-boundary markers (ADVISORY only — spike-10, ADR-018)
`sec-detect` surfaces these as `kernel_adjacency` in `SCAN-PLAN.json`; they drive an **informational
trust-boundary note**, NOT a finding (no CVSS, never a `VULN-FINDINGS.json` entry). When present, the
code crosses into kernel-execution / elevated-privilege territory — verifier-safety and kernel
memory-safety are **out of this review's scope** (Rule 5); point the developer at specialist tooling.
- **eBPF** — `*.bpf.c` programs · `libbpf` / `cilium/ebpf` / `aquasecurity/libbpfgo` / `bpf2go` in
  `go.mod` · `bpftrace` (`*.bt`) scripts. (These load programs that run **in-kernel** with
  `CAP_BPF`/`CAP_SYS_ADMIN`.) Specialist: syzkaller/Buzzer.
- **kernel-module / driver / DKMS** — `Kbuild` · `obj-m` in a `Makefile` · `*.ko` · `dkms.conf`.
  Specialist: kernel review + the SCA pin-and-verify path for out-of-tree module/DKMS sources (ADR-006).
- **privileged-container** — compose `privileged:` · k8s `privileged: true` / `hostPID` / `hostNetwork`
  / `hostPath` / `CAP_SYS_ADMIN`. (This is the shared-kernel → host-escape case above.)

The **in-scope** review for these is ordinary **privilege/authorization review of the *userspace*
loader code** (which capabilities are requested, whether program/module loading is gated by untrusted
input, whether maps/volumes are over-exposed) — the marker just *routes attention*; it does not add a
verdict type or a memory-safety audit.
