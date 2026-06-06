# Foundation Plan Synthesis

> Source: wycjclbk6 agent `synth:plan`.

Plan written to `docs/plan/PLAN.md`. It covers all 8 requested sections, grounded on the Anthropic defending-code spine and verified against current 2026 sources.

Key 2026 facts verified during research (and baked into the plan):
- **Trivy** stable **v0.71.0 (2026-06-01)**; MCP plugin **v0.0.20 (Dec 2025)** exposing 6 tools (`scan_filesystem`, `scan_image`, `scan_repository`, `trivy_version`, `findings_list`, `findings_get`); malicious v0.69.4 binary / 0.69.5-0.69.6 images to avoid. Plan defaults to **CLI, optional MCP**.
- **Opengrep v1.21.0 (May 2026)** added LSP taint; LGPL-2.1, 10+ vendor consortium — chosen as the single cross-language SAST default, with native gates layered on.
- **OWASP**: Web Top 10 **2025** (A03 Software Supply Chain Failures, A10 Mishandling Exceptional Conditions, SSRF folded into A01); LLM Top 10 **2025**; Agentic **ASI Top 10 2026** (late-2025 release, ASI01-ASI10); API Top 10 stays **2023** (no 2026 edition — flagged as a distrust signal).
- **Agent teams** require Claude Code **>= v2.1.32**; subagent `skills`/`mcpServers` frontmatter does NOT carry to teammate mode — drove the "put detail in the spawn prompt" guidance.
- **Anthropic security-review command** confirmed structure (3-phase methodology, 5 categories, ~18 exclusions, confidence >=0.8 / final HIGH-MEDIUM >=8/10, fixed finding schema) — reused as the FP-discipline backbone.

Notable opinionated calls in the plan:
- **One agent definition + 9 composable skills** chained via on-disk JSON artifacts (THREAT_MODEL.md -> SCAN-PLAN.json -> VULN-FINDINGS.json -> TRIAGE.json -> PATCHES/), with discovery (recall) and triage (precision, fresh context, adversarial N-of-3) strictly separated.
- **Static-analysis-only default**; execution-verified PoC detonation is an opt-in gVisor-sandboxed escalation, not the default for side projects.
- **Capability-removal over instruction** for `sec-patch` (no `--apply`, writes whitelisted to `./PATCHES/`) and prompt-injection defense by context starvation (decision-maker sees only `{file,line,category,diff}`).
- **7-phase rollout** that ships value in week 1 (skeleton beats the current Go-only agent immediately) and defers patch/re-attack + team mode + CI to later phases.
- Proposed full folder layout under the existing repo; flagged that `.gitignore` must include `.notes/` per your global instruction.

One decision point for your approval: I wrote the deliverable to `docs/plan/PLAN.md` (the repo had an empty `docs/plan/` clearly intended for it) rather than returning it only as chat text. If you'd prefer it elsewhere or as pure text, say so.
