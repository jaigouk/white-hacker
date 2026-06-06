# Phase 3 — Tooling as a swappable capability layer (+ degradation)

> **Theme:** wire the enhancer capabilities on top of the floor — **secrets**, **SCA**, **SAST**,
> **IaC** — each as a *capability with degradation*, never a hard tool dependency (ADR-015). Ship
> `secrets-scan` and `deps-scan`, and make discovery prefer installed tools while always degrading to
> the Read/Grep/Glob floor. The tool registry is itself part of the self-improving loop.
> **Maps to:** PLAN §8.1 P3, §4 (tool strategy), §3.3 (scanner selection); ADR-002, ADR-003, ADR-006,
> ADR-011, **ADR-015**.
>
> **Loop position:** INNER. Enhancers raise recall/precision but the value floor stands without them.
> **Exit condition:** on a host with a given capability present, the matching skill uses it and emits
> schema-valid findings; on a host without it, the same skill degrades, marks `tool_assisted:false`,
> caps confidence, and lists the capability under `tools_unavailable` — **no skill ever blocks**.

Every task here reads as **"wire capability X + degradation"**, not "install tool Y". Named tools
(Opengrep, OSV-Scanner, Trivy, gitleaks, trufflehog, govulncheck/pip-audit/npm audit) are illustrative
defaults the registry lists; an equivalent tool plugs in behind the same capability.

---

### T-3.1 · Populate `_shared/reference/tool-registry.md` as the capability→tool map
- **Goal:** the registry documents each capability (SAST · SCA · secrets · IaC · AI-redteam) with its
  ordered illustrative tools, the floor fallback, the runtime-discovery rule, the pinning/hygiene rule
  (ADR-006), and an explicit note that `sec-learn`/`sec-kb-refresh` may add new tools (ADR-015).
- **Artifact:** `.claude/skills/_shared/reference/tool-registry.md`
- **Depends on:** —
- **Verification criteria:**
  - [ ] All five capabilities appear with ≥ 1 illustrative tool and a floor fallback each — `for c in sast sca secret iac redteam; do grep -qi "$c" .claude/skills/_shared/reference/tool-registry.md || echo MISSING:$c; done` prints nothing
  - [ ] States "illustrative default, not a requirement" and the self-updating-registry rule — `grep -qi 'illustrative' .claude/skills/_shared/reference/tool-registry.md && grep -qi 'sec-learn\|sec-kb-refresh' .claude/skills/_shared/reference/tool-registry.md`
  - [ ] States pinning/hygiene (ADR-006: no unpinned auto-install; verify version/signature) — `grep -qi 'pin' .claude/skills/_shared/reference/tool-registry.md`
- **Status:** todo

### T-3.2 · Implement `secrets-scan` (secrets capability + degradation)
- **Goal:** `secrets-scan/SKILL.md` documents a fast pattern pass + a verified pass behind the **secrets
  capability** (illustrative: gitleaks fast, trufflehog `--results=verified`), degrading to a Read/Grep
  entropy/pattern heuristic when no tool is present; emits findings merged into `VULN-FINDINGS.json`;
  **never writes secret values** anywhere.
- **Artifact:** `.claude/skills/secrets-scan/SKILL.md` (+ `scripts/` if a redaction/normalize helper is
  needed, with tests)
- **Depends on:** T-1.1, T-3.1
- **Verification criteria:**
  - [ ] Body documents fast + verified passes behind a capability and the degradation fallback — `grep -qi 'verified' .claude/skills/secrets-scan/SKILL.md && grep -qi 'degrad\|fallback\|floor' .claude/skills/secrets-scan/SKILL.md`
  - [ ] Explicit "no secret value in output" rule — `grep -qi 'never.*secret value\|redact\|no secret' .claude/skills/secrets-scan/SKILL.md`
  - [ ] If a redaction helper exists, its tests pass and a known secret string is redacted — `uv run pytest .claude/skills/secrets-scan/scripts/tests/` (skip if no script)
  - [ ] `STATUS: STUB` gone; output validates against T-1.1 — `! grep -q 'STATUS: STUB' .claude/skills/secrets-scan/SKILL.md`
- **Status:** todo

### T-3.3 · Implement `deps-scan` (SCA capability + native-gate-first + degradation)
- **Goal:** `deps-scan/SKILL.md` documents native low-FP gates first (govulncheck/pip-audit/npm audit
  by language), then a cross-language fallback (OSV-Scanner/Trivy), then floor (lockfile read + advisory
  match) — all behind the **SCA capability**; emits findings into `VULN-FINDINGS.json`. Validated against
  the Trivy SCA PoC fixture already on disk.
- **Artifact:** `.claude/skills/deps-scan/SKILL.md` (+ `scripts/` for SARIF/JSON normalization, with tests)
- **Depends on:** T-1.1, T-2.2, T-3.1
- **Verification criteria:**
  - [ ] Body documents the native-gate-first → fallback → floor ladder behind the SCA capability — `grep -qi 'govulncheck\|pip-audit\|npm audit' .claude/skills/deps-scan/SKILL.md && grep -qi 'osv\|trivy' .claude/skills/deps-scan/SKILL.md && grep -qi 'floor\|lockfile' .claude/skills/deps-scan/SKILL.md`
  - [ ] A normalizer turns the on-disk Trivy SCA output into schema-valid findings — `uv run pytest .claude/skills/deps-scan/scripts/tests/` (fixture: `docs/research/poc-trivy-sca/trivy-output.json`)
  - [ ] When no SCA tool is on PATH the skill still emits a (degraded, `tool_assisted:false`) result — test with injected empty `which`
  - [ ] `STATUS: STUB` gone — `! grep -q 'STATUS: STUB' .claude/skills/deps-scan/SKILL.md`
- **Status:** todo

### T-3.4 · Wire the SAST capability into `sec-vuln-scan` (+ degradation)
- **Goal:** `sec-vuln-scan` prefers an installed SAST engine (illustrative: Opengrep, Semgrep-compatible
  rules) and per-language linters when present, else runs the Read/Grep/Glob heuristic floor — selecting
  via `SCAN-PLAN.json`'s capability map; tool-derived findings carry `tool_assisted:true`.
- **Artifact:** `.claude/skills/sec-vuln-scan/SKILL.md` (SAST section) + `reference/` if needed
- **Depends on:** T-1.2, T-2.2, T-3.1
- **Verification criteria:**
  - [ ] Section documents capability-based SAST selection from `SCAN-PLAN.json` + floor fallback — `grep -qi 'opengrep\|sast' .claude/skills/sec-vuln-scan/SKILL.md && grep -qi 'SCAN-PLAN.json' .claude/skills/sec-vuln-scan/SKILL.md && grep -qi 'floor\|degrad' .claude/skills/sec-vuln-scan/SKILL.md`
  - [ ] On a host with SAST present, a run on the Phase-0 fixture flags planted vulns with `tool_assisted:true`; on a host without, with `tool_assisted:false` (both logged in `poc-floor-review/README.md`)
  - [ ] "SCA/IaC tools have no SAST — combine capabilities for coverage" caveat present (PLAN §4.3) — `grep -qi 'no SAST\|combine' .claude/skills/sec-vuln-scan/SKILL.md`
- **Status:** todo

### T-3.5 · Wire the IaC capability + supply-chain hygiene (+ degradation)
- **Goal:** when `SCAN-PLAN.json` reports infra (Dockerfile / k8s / GitHub Actions / Terraform), discovery
  runs an IaC capability (illustrative: Trivy `config`/Checkov/hadolint/zizmor) else a floor heuristic;
  the `infra.md` appendix is filled (PLAN §5.5) and the tool-pinning hygiene (ADR-006) is enforced in how
  the skill invokes any tool.
- **Artifact:** `.claude/skills/_shared/reference/infra.md` + IaC section in `sec-vuln-scan/SKILL.md`
- **Depends on:** T-3.1, T-2.3
- **Verification criteria:**
  - [ ] `infra.md` covers Dockerfile, k8s/Helm, GitHub Actions, SLSA/Sigstore and is de-stubbed — `for k in 'Dockerfile' 'k8s\|kubernetes\|helm' 'github\|actions' 'slsa\|sigstore'; do grep -qiE "$k" .claude/skills/_shared/reference/infra.md || echo MISSING:"$k"; done` prints nothing; `! grep -q 'STATUS: STUB' .claude/skills/_shared/reference/infra.md`
  - [ ] Discovery runs IaC only when `SCAN-PLAN.json` infra is non-empty, else skips cleanly — manual demo on an infra fixture vs a no-infra fixture, logged
  - [ ] Tool invocations honor ADR-006 pinning (no unpinned auto-install) — `grep -qi 'pin\|--skip-db-update\|digest\|signature' .claude/skills/_shared/reference/infra.md` or the SKILL section
- **Status:** todo

### T-3.6 · Capability-degradation integration test
- **Goal:** a single test proves the whole degradation contract: with all capabilities absent the
  pipeline still completes, emits `tools_unavailable`, caps confidences, and never raises — and with a
  capability injected as present it switches to `tool_assisted:true`.
- **Artifact:** `.claude/skills/_shared/scripts/tests/test_degradation.py` (drives `detect_tools` +
  normalizers with an injected `which`)
- **Depends on:** T-2.2, T-3.2, T-3.3, T-3.4
- **Verification criteria:**
  - [ ] With `which` returning None for all tools, the run completes and `tools_unavailable` is non-empty — `uv run pytest .claude/skills/_shared/scripts/tests/test_degradation.py::test_floor_only`
  - [ ] With a SAST/SCA/secrets tool injected present, findings flip to `tool_assisted:true` and the capability leaves `tools_unavailable` — `uv run pytest .claude/skills/_shared/scripts/tests/test_degradation.py::test_tool_present`
  - [ ] No exception path blocks on a missing tool (asserted; ADR-003) — `uv run pytest .claude/skills/_shared/scripts/tests/test_degradation.py` (all green)
- **Status:** todo
