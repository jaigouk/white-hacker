# research:trivy-deep

> Source: workflow `white-hacker-research` (wycjclbk6), agent `research:trivy-deep`

## Trivy Deep-Dive (as of 2026-06-06)

Trivy (by [Aqua Security](https://github.com/aquasecurity/trivy)) remains the dominant open-source all-in-one security scanner in 2026: one CLI for vulnerabilities (SCA + OS packages), IaC/misconfiguration, secrets, licenses, and SBOM generation across container images, filesystems, git repos, VM images, Kubernetes, and cloud accounts.

### Current version & capabilities

- **Latest stable: `v0.71.0`** (released **2026-06-01**). Recent line: v0.70.0 (2026-04-17), v0.69.3 (2026-03-03), v0.69.2 (2026-03-01). Releases are GPG-signed (key `B5690EEEBB952194`). Source: [Trivy releases](https://github.com/aquasecurity/trivy/releases).
- **Scan targets:** container image, filesystem, remote git repository, VM image, Kubernetes cluster, and cloud (AWS/Azure/GCP).
- **Scanners (selectable via `--scanners`):** `vuln` (CVEs in OS packages + language deps / SCA), `misconfig` (IaC: Terraform, CloudFormation, Kubernetes manifests, Dockerfile, Helm), `secret` (hardcoded credentials), `license`.
- **SBOM:** generates and scans CycloneDX and SPDX; can scan an existing SBOM as input.

### Exact commands (copy-pasteable)

```bash
# Container image scan (SCA + OS CVEs)
trivy image python:3.12
trivy image --severity HIGH,CRITICAL --ignore-unfixed nginx:latest

# Filesystem / local project scan, choosing scanners explicitly
trivy fs --scanners vuln,secret,misconfig,license ./myproject

# IaC / misconfiguration only (Terraform, K8s, Dockerfile, Helm, CFN)
trivy config ./infra
trivy config --severity HIGH,CRITICAL ./terraform

# Remote git repository
trivy repo https://github.com/aquasecurity/trivy-ci-test

# Kubernetes cluster
trivy k8s --report summary cluster
trivy k8s --report all namespace/default

# SBOM: generate, then scan
trivy image --format cyclonedx --output sbom.cdx.json python:3.12
trivy sbom sbom.cdx.json

# Common output / CI flags
trivy image --format json --output report.json myimg:tag
trivy fs --exit-code 1 --severity CRITICAL .        # fail CI on CRITICAL
```

`trivy fs` and `trivy repo` are functionally the local-vs-remote pair; `trivy config` is the dedicated misconfig/IaC entry point (a focused subset of what `--scanners misconfig` does in `fs`).

### Install methods

```bash
# macOS / Linuxbrew
brew install trivy

# Docker (pin a digest in CI; see incident note below)
docker run --rm -v "$PWD":/work aquasec/trivy:0.71.0 fs /work
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.71.0 image python:3.12

# Install script (binary)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.71.0

# Debian/Ubuntu and RPM repos also available; or download a pinned binary
# from the GitHub releases page and verify the GPG signature.
```

### The official Trivy MCP server (this is real in 2026)

Yes — there is an **official Aqua Security MCP server**: [`aquasecurity/trivy-mcp`](https://github.com/aquasecurity/trivy-mcp), shipped as a **Trivy plugin**, not a standalone binary. Latest plugin release **v0.0.20** (2025-12-17). It supports **stdio, streamable-HTTP, and SSE** transports.

**Exact tool names exposed** (confirmed from source `pkg/tools/*`): the MCP registers **6 tools** — note these are the *base* names; in Claude Code they surface namespaced as `mcp__trivy__<name>` (the profile's `mcp__trivy__*` references map onto these):

| MCP tool | Maps to | Purpose |
|---|---|---|
| `scan_filesystem` | `mcp__trivy__scan_filesystem` | Scan a local project for vuln/misconfig/secret/license |
| `scan_image` | `mcp__trivy__scan_image` | Scan a container image |
| `scan_repository` | `mcp__trivy__scan_repository` | Scan a remote git repo |
| `trivy_version` | `mcp__trivy__trivy_version` | Report embedded/binary Trivy version |
| `findings_list` | `mcp__trivy__findings_list` | List findings from a prior scan |
| `findings_get` | `mcp__trivy__findings_get` | Fetch a single finding by ID |

**CLI flags for `trivy mcp`:** `--transport/-t` (`stdio`|`streamable-http`|`sse`, default `stdio`), `--host/-H` (default `localhost`), `--port/-p` (default `23456`), `--trivy-binary <path>`, `--use-aqua-platform/-a`, `--debug`. Aqua Platform mode authenticates via `AQUA_KEY`/`AQUA_SECRET` env vars (plus region/auth config) for assurance-policy compliance; it is optional and the OSS scanning path needs no credentials.

#### Setup in Claude Code (copy-pasteable)

```bash
# 1. Install Trivy (see above), then the MCP plugin:
trivy plugin install mcp
trivy mcp --help          # verify the plugin loaded

# 2a. Add to Claude Code via CLI (stdio):
claude mcp add trivy -- trivy mcp

# 2b. Or add manually to .mcp.json / settings (project or ~/.claude):
```
```json
{
  "mcpServers": {
    "trivy": {
      "command": "trivy",
      "args": ["mcp"]
    }
  }
}
```

For Aqua Platform features, use `"args": ["mcp", "--use-aqua-platform"]` and supply `AQUA_KEY`/`AQUA_SECRET` via an `"env"` block. The same `command`/`args` JSON works for Claude Desktop (`claude_desktop_config.json`). Note the MCP must run in **Agent mode** (not Ask mode) to invoke tools.

### CRITICAL 2026 supply-chain incident (must inform any agent that installs Trivy)

In **March 2026 Trivy was compromised twice** via a stolen GitHub Actions token ([Aqua advisory](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/), [StepSecurity](https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release), [Palo Alto Unit 42](https://www.paloaltonetworks.com/blog/cloud-security/trivy-supply-chain-attack/)):

- **Malicious:** binary **`v0.69.4`**; Docker images **`0.69.5`/`0.69.6`**; **`trivy-action`** (76 of 77 tags, all except `v0.35.0`); **`setup-trivy`** (multiple tags). Malware harvested AWS/GCP/Azure creds, SSH keys, K8s/Docker config, and git credentials from CI.
- **Safe:** binary **`v0.69.2`–`v0.69.3`** (and all later clean releases, i.e. **v0.70.0 / v0.71.0**); `trivy-action` **`v0.35.0`**; `setup-trivy` **`v0.2.6`**.
- **Guidance:** upgrade to **v0.71.0**; **pin GitHub Actions to full commit SHAs**, not tags; **pin Docker images by digest**; verify GPG signatures on downloaded binaries; rotate any secrets exposed to compromised versions between Mar 19–22, 2026. Aqua's commercial platform was unaffected.

### When Trivy is the right tool vs alternatives (2026 view)

- **Use Trivy** as the default for container images, filesystems, IaC/misconfig, secrets, and SBOM — broadest single-tool coverage, runs in seconds in CI. Trade-off: more aggressive inclusion = higher recall but more false positives on backport-patched distro packages. ([Luca Berton](https://lucaberton.com/blog/trivy-vs-grype-2026/), [Safeguard](https://safeguard.sh/resources/blog/trivy-vs-grype-buyer-comparison-2026))
- **Prefer Grype (+ Syft)** when you want a cleaner SBOM-driven pipeline and quieter results on Red Hat/Ubuntu base images (better distro patch-metadata handling). ([AppSec Santa](https://appsecsanta.com/sca-tools/osv-scanner-vs-grype))
- **Prefer osv-scanner** for lockfile/manifest-first language-ecosystem SCA in CI — OSV.dev aggregates 20+ curated advisory sources.
- **Use Semgrep for SAST** — Trivy has **no SAST**; it only finds known CVEs in deps, IaC misconfig, and secrets, not code-level logic flaws. The widely recommended zero-cost OSS stack in 2026 is **Trivy + Semgrep** (Trivy = containers/IaC/SCA, Semgrep = custom code rules), optionally adding Grype+Syft, osv-scanner, and TruffleHog. ([Scopir](https://scopir.com/posts/vulnerability-scanning-tools-devops-2026/))

## Key takeaways

- Trivy latest stable is v0.71.0 (2026-06-01); always pin/verify versions because of the March 2026 supply-chain compromise.
- CRITICAL: avoid Trivy binary v0.69.4 and Docker images 0.69.5/0.69.6 (malicious); safe = v0.69.2/0.69.3 and later clean releases (v0.70.0, v0.71.0). For CI, pin actions to commit SHAs and Docker images to digests, and verify GPG signatures.
- An official Trivy MCP server exists: aquasecurity/trivy-mcp, installed as a Trivy plugin (`trivy plugin install mcp`), started with `trivy mcp` (stdio default; also streamable-http/sse). Latest v0.0.20.
- The MCP exposes exactly 6 tools: scan_filesystem, scan_image, scan_repository, trivy_version, findings_list, findings_get — surfacing in Claude Code as mcp__trivy__<name>, matching the profile's mcp__trivy__* references.
- Claude Code setup is copy-pasteable: `claude mcp add trivy -- trivy mcp`, or an mcpServers JSON block with command `trivy` / args `["mcp"]`; Aqua Platform features need --use-aqua-platform plus AQUA_KEY/AQUA_SECRET and are optional.
- A generic review agent should call Trivy via four core commands: `trivy fs` (local project), `trivy image` (containers), `trivy config` (IaC/misconfig), `trivy repo` (remote git) — language-agnostic, covering TS/Go/Python/Java equally.
- Use `--scanners vuln,misconfig,secret,license` to control scope, `--severity HIGH,CRITICAL` and `--ignore-unfixed` to cut noise, and `--exit-code 1` to gate CI; `--format json` for machine-readable output.
- Trivy is SCA + IaC/misconfig + secrets + SBOM + license — it has NO SAST. Pair with Semgrep for code-level logic flaws; an agent must not treat a clean Trivy run as full coverage of an app's source.
- Tool selection: Trivy = best default breadth (containers/IaC/SCA); Grype+Syft = cleaner SBOM pipeline and quieter on RHEL/Ubuntu; osv-scanner = lockfile/manifest-first language SCA; Semgrep = SAST; TruffleHog = deep secrets.
- Trivy's higher recall means more false positives on backport-patched distro packages — an agent should expect and triage these, not surface raw counts as definitive.
- Trivy covers AI/backend/frontend repos uniformly: it detects vulnerable npm/pip/Go/Maven deps, Dockerfile and Kubernetes/Terraform misconfig, and leaked API keys/tokens (relevant to AI projects with model/cloud credentials).
- Don't auto-install Trivy from unpinned sources inside an agent; prefer brew or a digest-pinned binary/image with signature verification, given the 2026 incident history.

## Sources

- https://github.com/aquasecurity/trivy
- https://github.com/aquasecurity/trivy/releases
- https://github.com/aquasecurity/trivy-mcp
- https://github.com/aquasecurity/trivy-mcp/blob/main/docs/ide/claude.md
- https://github.com/aquasecurity/trivy-mcp/blob/main/docs/configuration.md
- https://github.com/aquasecurity/trivy-mcp/blob/main/docs/quickstart.md
- https://raw.githubusercontent.com/aquasecurity/trivy-mcp/main/pkg/tools/scan/scan.go
- https://raw.githubusercontent.com/aquasecurity/trivy-mcp/main/pkg/tools/result/findings.go
- https://raw.githubusercontent.com/aquasecurity/trivy-mcp/main/pkg/tools/version/version.go
- https://raw.githubusercontent.com/aquasecurity/trivy-mcp/main/pkg/tools/tool.go
- https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/
- https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release
- https://www.paloaltonetworks.com/blog/cloud-security/trivy-supply-chain-attack/
- https://lucaberton.com/blog/trivy-vs-grype-2026/
- https://safeguard.sh/resources/blog/trivy-vs-grype-buyer-comparison-2026
- https://appsecsanta.com/sca-tools/osv-scanner-vs-grype
- https://scopir.com/posts/vulnerability-scanning-tools-devops-2026/

