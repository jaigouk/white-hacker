---
name: sec-init
description: Onboard the white-hacker agent to a repo. Runs detection (sec-detect) plus a threat-model seed once and writes a gated, project-scope companion profile (.white-hacker/project-profile.json) the generic agent consumes — detected languages/frameworks, present capabilities, tools_unavailable, language appendices to load, the AI-pass flag, a threat-model seed, and a (human-confirmed) scoring standard. It never edits the shipped agent identity. Generated strings are factual, not imperative.
when_to_use: Run once when first adding white-hacker to a project, or to refresh the companion after the stack or installed tools change. Not part of the per-review loop (sec-detect runs each review).
---

# sec-init — project-detecting onboarding → a gated project-scope companion

Onboarding is **detection plus a threat-model seed, run once, persisted** as a committed,
**project-scope companion** the generic white-hacker agent reads. It specializes *facts about
this repo* only. It **never** rewrites the shipped agent identity (ADR-004, ADR-017,
[spike-07](../../../../docs/research/spike-07-agent-distribution-and-init-2026-06.md) F4).

> Read-only detection: manifest reads + `which`/version probes (reused from `sec-detect`).
> Writes exactly one file: `<repo>/.white-hacker/project-profile.json`. Never installs, never
> networks, never blocks on a missing tool.

## Why a companion, not a profile rewrite

The shipped identity (senior-security-engineer persona, posture, review-loop stages, FP
discipline, severity-by-preconditions, the JSON output contract, tool scoping) lives in the
agent `.md` + skills and is **off-limits** to init. There is no built-in identity-drift guard in
Claude Code, and a plugin-root `CLAUDE.md` is not loaded — so the safe shape is: ship a generic
base, and have init emit a *project-scope companion layer* the generic agent consumes. The
companion **specializes**, it does not **override**.

The schema enforces this structurally: `project_profile_schema.json` sets
`"additionalProperties": false` at the top level and allows ONLY these keys —

| key | meaning |
|-----|---------|
| `schema_version` | profile schema version |
| `generated_note` | factual provenance one-liner |
| `detected_langs` | languages from manifest fingerprint |
| `frameworks` | app + AI frameworks fingerprinted |
| `present_capabilities` | sast/sca/secrets/iac/ai-redteam backed by an installed tool |
| `tools_unavailable` | capabilities with no tool (agent degrades to the Read/Grep/Glob floor) |
| `load_appendices` | per-language appendices (lang-go/lang-python/lang-typescript/lang-java) |
| `ai_pass` | true when LLM/AI deps are present (the AI/LLM review pass applies) |
| `scoring_standard` | severity standard — **null by default ("ask"); human-confirmed, never inferred** |
| `threat_model_seed` | `{assets, entry_points, trust_boundaries}` lists (may be empty/derived) |

Any shipped-identity key (`posture`, `tools`, tool-scope, output-contract, review-stages) is
**rejected by validation** — `additionalProperties:false` guarantees init cannot smuggle in an
identity override.

## Injection-safety: factual statements, never imperatives

This profile may later feed a `SessionStart` `additionalContext` (T-10.6). The Anthropic hooks
docs warn that **imperative** `additionalContext` can trip Claude's prompt-injection defenses —
and white-hacker is itself an injection target (Agents Rule of Two). So every generated string is
a **factual statement**. `is_factual()` rejects text beginning with imperative markers
(`always` / `never` / `you must` / `ignore` / `disregard` / `do not`), and `write_profile()`
**refuses** (raises `ValueError`) to write a non-factual or schema-invalid profile.

## Reuse, don't reinvent

Detection is **imported from `sec-detect`** (`detect_tools.build_scan_plan`) — languages,
frameworks, the `ai_pass` trigger, and installed-tools→capabilities all come from the existing
detector. `sec-init` only *shapes and persists* the result; it adds no new detection subsystem.
Per-review `sec-detect` still runs each review — the companion is the onboarding snapshot, not a
replacement for it.

## Gating (Phase-9 keep-or-revert + size caps)

Every generated companion is subject to the **Phase-9 keep-or-revert corpus gate** and the
**size caps** that govern all auto-generated artifacts (ADR-017): a generated profile is only kept
if it does not regress the frozen eval corpus, and the JSON stays well under the 10k-char
`SessionStart` `additionalContext` cap (the size test asserts `< 8000` bytes, leaving margin).

## Usage

```sh
# build + validate + write the companion for a repo (defaults to cwd)
uv run --project plugins/white-hacker/skills/sec-init/scripts \
  python plugins/white-hacker/skills/sec-init/scripts/init_profile.py <repo_root>
# → prints <repo_root>/.white-hacker/project-profile.json on success (exit 0)
```

After generation, **a human confirms `scoring_standard`** (CVSS vs an org bug-bar) and reviews
the `threat_model_seed` — these are policy decisions the agent seeds but does not decide.

## Alternative carrier: the `--init-only` Setup hook

`/sec-init` is the discoverable, user-invoked onboarding surface. The same generator can also run
as a **`Setup` hook**, which fires only on `claude --init-only` (also `-p --init` /
`-p --maintenance`) — the native one-time "install/CI prep" event. `claude --init-only` runs the
`Setup` + `SessionStart` hooks and exits, scaffolding the project-scope companion in CI or at
first checkout without a special launch flow. Either carrier writes the same gated companion file;
neither touches the shipped identity. (Honor anthropics/claude-code#16538: keep any SessionStart
context at **project scope**, not plugin scope.)

## Inputs / Outputs

- **Reads:** repo-root manifests (via `sec-detect`) and `PATH` (which scanners exist).
- **Writes:** `<repo>/.white-hacker/project-profile.json` (pretty JSON), schema-valid + factual.
- **Consumed by:** the generic white-hacker agent (which appendices to load, which capabilities
  are present, whether the AI pass applies) and, optionally, the T-10.6 SessionStart hook.
