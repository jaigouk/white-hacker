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

## Change log
> Append dated entries when a tool/capability is added or retired. Format:
> `YYYY-MM-DD · +/- · capability · tool · source · rationale`
- 2026-06-06 · seed · initial registry from research (`docs/research/fnd-tool-matrix.md`).
