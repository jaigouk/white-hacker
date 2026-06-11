# Spike S-01 — Does a Trivy MCP server exist & should we depend on it? (2026)

- **Status:** ✅ RESOLVED
- **Date:** 2026-06-06
- **Confidence:** High (hands-on + official source verified)

## Question / assumption under test

The legacy alto `white-hacker.md` hard-codes MCP tools `mcp__trivy__scan_filesystem`,
`mcp__trivy__scan_image`, `mcp__trivy__findings_list`, `mcp__trivy__findings_get`.
**Assumption:** a real, maintained Trivy MCP server exists in 2026 and these tool names are correct.
The answer decides whether tool integration is **MCP-based** or **CLI-via-Bash**.

## What was checked (evidence)

1. **Local binary (hands-on):** `trivy --version` → **Version 0.69.0**, vuln DB updated 2026-02-05.
   Trivy is available as a local binary.
2. **Official MCP plugin exists:** [`aquasecurity/trivy-mcp`](https://github.com/aquasecurity/trivy-mcp)
   — official Aqua Security plugin that starts an MCP server. Confirmed via the Aqua blog
   ["Security That Speaks Your Language: Trivy MCP Server"](https://www.aquasec.com/blog/security-that-speaks-your-language-trivy-mcp-server/)
   and listings on PulseMCP / Glama / mcp.so.
3. **Install:** `trivy plugin install mcp` (per [installation docs](https://github.com/aquasecurity/trivy-mcp/blob/main/docs/installation.md)).
4. **Claude config (verbatim, from [docs/ide/claude.md](https://github.com/aquasecurity/trivy-mcp/blob/main/docs/ide/claude.md)):**
   ```json
   { "mcpServers": { "trivy": { "command": "trivy", "args": ["mcp"] } } }
   ```
5. **Transports / flags (verified, [configuration.md](https://github.com/aquasecurity/trivy-mcp/blob/main/docs/configuration.md)):**
   `--transport stdio|streamable-http|sse` (default `stdio`), `--host`, `--port 23456`,
   `--trivy-binary`, `--use-aqua-platform`, `--debug`.
6. **Scan capabilities:** filesystem (local project), container image, remote repository.
7. **NOT a managed connector:** the connected MCP registry returned **0 results** for trivy —
   it must be installed manually as a Trivy plugin; it is not one-click in this environment.

## Residual uncertainty

- **Exact MCP tool names are NOT documented** in the public docs (README/installation/configuration
  do not enumerate them). The legacy `mcp__trivy__scan_filesystem` etc. are **plausible but unverified**.
  → Low risk: tool names are discoverable at runtime once the server is registered (the tool list
  surfaces in-session). The profile must **not hard-code** them; it should discover/degrade.

## Decision

- **Do NOT hard-depend on the Trivy MCP server.** Treat Trivy as a **CLI-first** tool invoked via Bash
  (`trivy fs`, `trivy image`, `trivy config`, `trivy repo`), with the **MCP server as an optional
  enhancement** the user can enable.
- The white-hacker agent must **detect** whether `trivy` (CLI) and/or the MCP tools are present and
  **gracefully degrade** (verified: only `trivy` + `govulncheck` are installed locally; semgrep,
  osv-scanner, grype, gitleaks, trufflehog, bandit, gosec are absent).
- Document the optional MCP setup snippet in the README, but never assume `mcp__trivy__*` exists.
- This becomes **ADR-002** (Trivy via CLI-first, MCP optional) and **ADR-003** (tool graceful degradation).

## Follow-ups

- When building, add a `scripts/detect_tools.*` that probes available scanners (with tests).
  → DONE as [poc-tool-detection](poc-tool-detection/README.md) (12/12 tests pass).
- Optionally verify exact MCP tool names by registering the server once and listing tools.

## Addendum (2026-06-06) — corroborating second source + supply-chain note

The foundation research (`wycjclbk6`, agent `research:trivy-deep`/`synth:tool-matrix`) provides a
**second source** on the previously-unknown tool names:

- **Trivy MCP plugin v0.0.20 (Dec 2025)** reportedly exposes **6 tools** surfacing as `mcp__trivy__*`:
  `scan_filesystem`, `scan_image`, `scan_repository`, `trivy_version`, `findings_list`, `findings_get`.
  (Two sources now agree these exist; still verify by listing tools at runtime before hard-referencing.)
- **Supply-chain hygiene (NEW, verify before relying):** latest stable **Trivy v0.71.0 (2026-06-01)**.
  Research flags **malicious binary v0.69.4 and Docker images 0.69.5 / 0.69.6**; safe = v0.69.2/0.69.3
  and v0.70.0+. The official Trivy GitHub Action was reportedly compromised twice in March 2026.
  → **Decision:** pin Trivy to a known-good version, install via brew or a digest/GPG-verified artifact,
  never auto-install from unpinned sources. Locally installed **v0.69.0** is not in the malicious set but
  should be upgraded to v0.71.0. This strengthens **ADR-002** and adds an ADR on tool supply-chain pinning.
- **Coverage caveat:** Trivy has **no SAST** — a clean Trivy run ≠ full source coverage; always pair with
  Opengrep/Semgrep. (Verified locally: opengrep/semgrep are *not* installed → degradation applies.)
