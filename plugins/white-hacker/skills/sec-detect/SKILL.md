---
name: sec-detect
description: Auto-detect languages/frameworks from manifest files, map needed capabilities (SAST/SCA/secrets/IaC/AI-redteam) to whatever tools are installed, and emit SCAN-PLAN.json with graceful degradation to the Read/Grep/Glob floor. Use right after threat-model to plan the scan.
---

# sec-detect — language/framework/tool detection → `SCAN-PLAN.json`

Make the review **language-agnostic and tool-agnostic**. Detect what the repo *is*, pick the
right capabilities for it, bind each capability to whatever tool is actually installed, and
**degrade gracefully** to the Read/Grep/Glob floor when a capability has no tool (ADR-003,
ADR-015). The output, `SCAN-PLAN.json`, is what `sec-vuln-scan` partitions and `sec-triage`
calibrates against.

> Runs right after `sec-threat-model`. Read-only: manifest reads + `which`/version probes only.
> No install, no network, never blocks on a missing tool.

## Inputs / Outputs
- **Reads:** repo-root manifests (`go.mod`, `package.json`+`tsconfig.json`, `pyproject.toml`/
  `requirements.txt`/`Pipfile`/`uv.lock`, `pom.xml`/`build.gradle*`, `Cargo.toml`), infra signals
  (`Dockerfile`, `.github/workflows/`), and `PATH` (which scanners exist).
- **Writes:** `SCAN-PLAN.json` (schema: [`scan-plan-schema.json`](scan-plan-schema.json)).

## Method — two-layer detect, then capability binding

### 1. Ecosystem manifest → language
Set-based detection from manifest *names* (`scripts/detect_tools.py::detect_languages`). A repo can
be polyglot — emit **all** detected languages. `package.json` + `tsconfig.json` ⇒ `typescript`
(never plain `javascript`). IaC/CI layers (`Dockerfile`, GitHub Actions) are always in scope when
present.

### 2. Framework fingerprint (read manifest *contents*)
`scripts/detect_tools.py::detect_frameworks` reads the manifest text and matches dependency tokens:
- **TS/JS:** `next`, `react`, `vue`, `angular`, `express`, `fastify`, `nestjs`.
- **Python:** `django`, `flask`, `fastapi`.
- **Go:** `gin`, `chi`, `echo` (module import paths in `go.mod`).
- **Java:** `spring-boot`, `spring-security` (incl. the `spring-boot-starter-security` coordinate),
  `jackson`.

The fingerprint drives **which per-language reference appendix** gets loaded on demand
(`reference/lang-*.md`) and whether the **API appendix** applies (any web/backend framework →
`api.md`).

### 3. AI-pass trigger (the framework→AI link)
AI/LLM dependencies — `langchain`, `transformers`, `torch`, `openai`, `anthropic` — flip
**`ai_pass: true`** for *any* stack (e.g. a TypeScript app importing `@anthropic-ai/sdk`, not only
Python). `ai_pass` does three things: pulls in the `reference/ai-llm.md` appendix, signals the
orchestrator to run the **`ai-llm-review`** skill, and makes the **`ai-redteam`** capability
relevant in the tool map (see §4). This is the contract point with the AI/LLM phase (Phase 4).

### 4. Capability → tool binding (depend on interfaces, not brands)
Each capability is an interface; `scripts/detect_tools.py::SCANNER_PREFERENCE` lists *ordered,
illustrative* tool preferences (best signal first) — see
[`_shared/reference/tool-registry.md`](../_shared/reference/tool-registry.md). For each applicable
capability, bind the first installed preferred tool; if none is installed, record the capability in
`degraded` and fall back to the floor.

| Capability | Floor (always works) | Conditional on |
|------------|----------------------|----------------|
| `sast` | Read/Grep/Glob heuristic + `lang-*.md` | always |
| `sca` | read lockfiles, reason from known-bad ranges | always |
| `secrets` | grep high-entropy + key patterns | always |
| `iac` | read Dockerfile/manifests/workflows + `infra.md` | infra present |
| `ai-redteam` | static `ai-llm.md` + KB patterns over code | `ai_pass` |

`iac` is only emitted when infra is present; `ai-redteam` only when `ai_pass`. A bound tool must
also *serve* the detected stack (e.g. `govulncheck` only serves Go) or it doesn't count.

### 5. Graceful degradation (never block)
A missing tool is never fatal. The skill records `degraded: [<capabilities>]` and a `fallback`
note; downstream marks those findings `tool_assisted:false` and **caps confidence** (ADR-003,
matches the finding schema's `tool_assisted` field). The agent reports `tools_unavailable` rather
than failing.

## Emitting & validating the plan
```bash
# emit
uv run --with jsonschema python scripts/detect_tools.py <repo-root> > SCAN-PLAN.json
# validate (CI-gateable; same pattern as _shared/scripts/validate_findings.py)
uv run --with jsonschema python scripts/validate_scan_plan.py SCAN-PLAN.json
```
`SCAN-PLAN.json` shape: `{schema_version, languages, infra, frameworks, available_tools, ai_pass,
category_tool{capability→tool|null}, degraded[capability], reference_appendices, fallback}`. The
schema is derived from the emitter and locked by `tests/test_scan_plan_schema.py` so the two can't
drift.

## Where it sits in the loop
`sec-threat-model → **sec-detect** → sec-vuln-scan (recall) → sec-triage (precision) → sec-report`.
See `docs/ARCHITECTURE.md` and the white-hacker agent definition.

### 6. AI-agent-infra advisory (wh-7u7)
`scripts/detect_tools.py::detect_ai_agent_infra` does a **bounded, pruned tree walk** (depth cap 5;
prunes `.venv`, `node_modules`, `.git`, `__pycache__`, `dist`, `build`) and emits sorted marker classes:

| Marker | Signal |
|--------|--------|
| `.claude` | `.claude/` directory at root |
| `agents` | `agents/` directory at root |
| `mcp.json` | `mcp.json` file at root |
| `skill` | any `*.skill` file in the bounded walk |
| `nested-ai-manifest` | non-root `pyproject.toml`/`requirements.txt`/`Pipfile`/`package.json` containing an AI-SDK token |

These populate `ai_agent_infra` on `ScanPlan` and `to_dict()`.  A derived `ai_pass_advisory` boolean
is emitted in `to_dict()` only: `(not ai_pass) and bool(ai_agent_infra)`.  **`ai_pass` itself is
unchanged** (manifest-driven, root-only).  Neither field is a finding — ADVISORY altitude only,
no CVSS.

## Verification criteria (definition of done for this skill)
- [x] `description` ≤ 1,536 chars (ADR-005).
- [x] Ported PoC tests pass (≥12) + framework/`ai_pass`/appendix tests — `uv run --with jsonschema --with pytest pytest .claude/skills/sec-detect/scripts/`.
- [x] CLI emits a `SCAN-PLAN.json` validating against `scan-plan-schema.json`.
- [x] Framework fingerprint sets `ai_pass` when AI deps present; `ai-redteam` capability appears only then.
- [x] Degrades gracefully (records `degraded`, never blocks); no secret values written.
