<div align="center">

<img src="docs/assets/white-hacker-logo.png" alt="white-hacker logo" width="100">

# white-hacker

**A generic, self-improving white-hat security reviewer for Claude Code.**

Finds real, high-confidence, *exploitable* bugs in any TypeScript · Go · Python · Java repo —
backend, frontend, or AI/LLM/agent framework — and keeps its AI-attack knowledge current over time.

[![CI](https://github.com/jaigouk/white-hacker/actions/workflows/ci.yml/badge.svg)](https://github.com/jaigouk/white-hacker/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
![Claude Code plugin](https://img.shields.io/badge/Claude_Code-plugin-d97757.svg)
![version](https://img.shields.io/badge/version-0.2.0-informational.svg)
![AI-aware](https://img.shields.io/badge/AI--aware-LLM_MCP_Agentic-8A2BE2.svg)

</div>

---

## What it is

white-hacker is a security-review agent that runs **inside Claude Code**. Point it at a diff or a
path; it threat-models the target, hunts for vulnerabilities, then **adversarially re-checks each one
in a fresh context** — so you get a short list of *exploitable* findings instead of a wall of false
positives. It is **AI-aware** (OWASP LLM / MCP / Agentic), treats all reviewed code as untrusted (the
reviewer is itself an injection target), and **proposes fixes but never pushes** — the write
capability is removed, not just discouraged.

> **Status.** The **inner review loop works today.** The self-improvement *outer loop* (which keeps
> the AI-attack knowledge base current) is designed and partly built — its currency arm is
> **human-triggered today, not yet autonomous.**

## Features

- 🎯 **High signal, not noise.** Discovery (recall) and triage (precision) are *separate* stages;
  triage assumes every finding is a false positive and tries to refute it (adversarial N-of-N). The
  threat model is the top precision lever — ~90% exploitable findings when it is well-defined.
- 🧩 **Any stack, zero install.** A built-in Read/Grep/Glob *floor* produces value with no external
  tools; installed scanners (SAST · SCA · secrets · IaC) are auto-discovered and used when present —
  **never required** — and it degrades gracefully when they are missing.
- 🤖 **AI-native.** First-class OWASP **LLM** (2025), **MCP** (beta), and **Agentic/ASI** (2026)
  coverage — prompt injection, the lethal trifecta, tool poisoning, excessive agency, insecure output
  handling — grounded in a living, dated, source-linked knowledge base.
- 🔌 **One agent, three carriers.** The same definition runs as a `/security-review` slash command, a
  delegated subagent, or a teammate on a TL / QA / Dev team.
- 🔒 **Safe by construction.** Read-only and static-analysis-only by default; Agents Rule of Two; the
  triage decision-maker sees only `{file, line, category, diff}` — context starvation that also
  defeats prompt injection.
- ♻️ **Self-improving without retraining.** Every learning is a reviewable text diff behind a
  deterministic eval gate (keep-or-revert) — and **never auto-merged.**

## Quick start

> **Requirements:** Claude Code. Your **Pro/Max subscription works as-is — no `ANTHROPIC_API_KEY`
> needed** for local use. (A key/token is only required for the optional headless CI action.)

**1. Install** — manual, from this repo (no marketplace listing yet):

```bash
# pinned vendor install — run inside your target project:
curl -fsSL https://raw.githubusercontent.com/jaigouk/white-hacker/HEAD/install.sh | bash
```

<details>
<summary>…or register this repo as a local plugin instead</summary>

```bash
git clone https://github.com/jaigouk/white-hacker
/plugin marketplace add ./white-hacker
/plugin install white-hacker@white-hacker-marketplace
```
</details>

**2. Onboard once per repo** — detects languages, frameworks, installed scanners, and whether the
repo has an AI/LLM/MCP surface:

```
/white-hacker:sec-init
```

**3. Review:**

```
/white-hacker:security-review                 # review your working-tree diff
/white-hacker:security-review path/to/subdir  # audit a path
```

You get back **only triaged findings** plus a `SECURITY-REPORT.md`. CI gates on `counts.high == 0`.

> **Building the plugin itself?** Load it live from the working tree with
> `claude --plugin-dir ./plugins/white-hacker` — see **[docs/plugin-loading.md](docs/plugin-loading.md)**.

## How it works

Two nested loops over plain-text artifacts behind open interfaces (Agent Skills, MCP):

- **Inner loop — one review:** threat-model → discovery (recall) → verification + triage (precision,
  *fresh context*) → report → patch (opt-in). Stages chain through on-disk JSON, so a run is resumable
  and CI-gateable:

  ```
  THREAT_MODEL.md → SCAN-PLAN.json → VULN-FINDINGS.json → TRIAGE.json → SECURITY-REPORT.md → PATCHES/
  ```

- **Outer loop — across reviews:** trace → reflect → propose text diffs → deterministic eval gate →
  human-reviewed PR. **The inner loop *consumes* the knowledge base; the outer loop *edits* it.** No
  model retraining — all durable learning is a git diff.

<details>
<summary><b>Tooling is a swappable capability layer — not a fixed list</b></summary>

The agent depends on a *capability* (SAST · SCA · secrets · IaC · AI-redteam), **never a brand**. It
detects which tools are installed at runtime, maps them to capabilities, and falls back to the
built-in Read/Grep/Glob floor when none exist — marking findings `tool_assisted:false` and capping
confidence rather than blocking. New tools are added to the registry through the same gated loop that
adds new attack techniques. See
[`tool-registry.md`](plugins/white-hacker/skills/_shared/reference/tool-registry.md).
</details>

## Documentation

| Doc | What it covers |
|-----|----------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | the *what & how* — components, the two loops, trust model |
| [docs/ARD.md](docs/ARD.md) | Architecture Decision Records — the *why* |
| [docs/DDD.md](docs/DDD.md) | domain model (ubiquitous language, bounded contexts) |
| [docs/PRD.md](docs/PRD.md) | product requirements (FR / NFR + verification) |
| [docs/plugin-loading.md](docs/plugin-loading.md) | loading the plugin for dev / dogfood (live vs snapshot) |
| [docs/team-mode.md](docs/team-mode.md) | agent-team (multi-agent) mode |

## Security & license

- **Authorized targets only**, read-only by default. The agent reviews your *own* working tree / diff,
  treats all reviewed content as untrusted, and **proposes patches to `PATCHES/` — it never pushes or
  applies them** (the capability is removed, not merely instructed).
- Licensed under **Apache-2.0**.
