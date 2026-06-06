# Tool registry — capability → tools (extensible, self-updating)

> **The concept owns this file, not any vendor.** Tools below are *illustrative defaults*, not
> requirements. The agent depends on a **capability**, discovers what is installed at runtime,
> maps it here, and **degrades to the Read/Grep/Glob floor** when a capability has no tool
> (ADR-003, ADR-015). New/unknown tools are added here by `/sec-learn` and `/sec-kb-refresh`
> as reviewable, dated diffs — there will always be tools not yet listed.

## How to read this
- **Capability** = what the agent needs (the durable interface).
- **Floor** = the zero-install fallback that always works.
- Each tool entry should carry: `tool · cost · langs/ecosystems · invoke · notes · added(date,source)`.
- Prefer whatever the **repo or user already has**; do not install without need + pinning (ADR-006).
- **Executable twin:** the runtime selection *order* lives in
  `.claude/skills/sec-detect/scripts/detect_tools.py::SCANNER_PREFERENCE` (the capability→ordered-tools
  map `sec-detect` actually binds, including the `ai-redteam` capability added in Phase 2). Keep this
  doc and that map in sync — `_shared/scripts/tests/test_registry_lock.py` fails if a capability in the
  code is missing here.

## Capabilities

### SAST (code-level taint/pattern analysis)
- **Floor:** Read/Grep/Glob heuristic pass (confidence capped).
- Examples (today): Opengrep · Semgrep CE · CodeQL (public/OSS) · per-language linters
  (gosec, ruff `-S` / bandit, eslint-plugin-security, spotbugs+find-sec-bugs).

### SCA (dependency / lockfile CVEs)
- **Floor:** read manifests/lockfiles, grep pinned versions, reason from known-bad ranges.
- Examples: native gates first (govulncheck, pip-audit, npm/pnpm audit, cargo-audit) → then
  OSV-Scanner / Trivy / Grype+Syft as cross-language fallback.

### Secrets
- **Floor:** grep high-entropy + known key patterns.
- Examples: gitleaks (fast) · trufflehog `--results=verified` (live verification) · detect-secrets.

### IaC / container / CI
- **Floor:** read Dockerfile / manifests / workflows and apply `reference/infra.md`.
- Examples: Trivy `config` · Checkov · hadolint (Dockerfile) · zizmor/actionlint (GH Actions).

### AI-redteam (behavioral, for running LLM/agent apps)
- **Floor:** static `reference/ai-llm.md` + KB technique patterns over the code.
- Examples: promptfoo redteam · garak.

### (add new capabilities here as discovered)

## Pinning & supply-chain hygiene (ADR-006 — non-negotiable)
The reviewer must not become a supply-chain vector itself. Never auto-install from unpinned sources;
prefer a tool the repo/user already has, else a digest-pinned binary/image with signature/GPG
verification.
- **Trivy:** safe stable = **v0.71.0 / v0.70.0+**. **Avoid binary v0.69.4 and images
  v0.69.5–v0.69.6 (malicious set);** v0.69.2/0.69.3 are safe. Run offline with `--skip-db-update`
  against the cached DB (matches the "no network during scanning" posture). Trivy = SCA + IaC +
  secrets + SBOM, **no SAST** — pair with a SAST engine for source coverage.
- **Actions/CI tools:** pin GitHub Actions to a commit SHA (the official Trivy action was
  compromised twice in March 2026); pin Docker base images by digest.
- New/updated tools are added **only** as reviewable, dated change-log entries below (ADR-015).

## Change log
> Append dated entries when a tool/capability is added or retired. Format:
> `YYYY-MM-DD · +/- · capability · tool · source · rationale`
- 2026-06-06 · seed · initial registry from research (`docs/research/fnd-tool-matrix.md`).
