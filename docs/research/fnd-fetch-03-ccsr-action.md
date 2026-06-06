# fetch:ccsr-action

> Source: workflow `white-hacker-research` (wycjclbk6), agent `fetch:ccsr-action`

## Anthropic `claude-code-security-review` GitHub Action

The [`anthropics/claude-code-security-review`](https://github.com/anthropics/claude-code-security-review) repository is an open-source, AI-powered SAST GitHub Action that uses Claude (via the Claude Code CLI) to perform **diff-aware, context-aware security review** of pull requests. Unlike pattern/regex SAST tools (Semgrep, CodeQL), it reasons semantically over changed code and is **language-agnostic**. It is published as a **composite action** (`action.yml` runs a multi-step shell+Python workflow).

### What it does on a PR

On a `pull_request` event it: (1) fetches the PR **diff** and changed files; (2) runs a Python driver (`claudecode/github_action_audit.py`) that installs `@anthropic-ai/claude-code` (`npm install -g @anthropic-ai/claude-code`, unpinned/latest) and invokes Claude with a security-audit prompt; (3) Claude does multi-phase analysis (context research → comparative analysis vs. existing patterns → vulnerability assessment / data-flow tracing); (4) findings are generated with severity + confidence + remediation; (5) a **false-positive filtering** pass removes low-signal items; (6) surviving findings are posted as **inline PR review comments** on the affected lines, and results are uploaded as a JSON artifact. Outputs are `findings-count` and `results-file`.

### How it invokes Claude (diff-aware)

The prompt logic lives in [`claudecode/prompts.py`](https://github.com/anthropics/claude-code-security-review/blob/main/claudecode/prompts.py). Claude is framed as a **"senior security engineer"** told to do a **"focused security review"** of only the PR diff, flagging **"HIGH-CONFIDENCE security vulnerabilities ... with real exploitation potential."** It is given the diff plus repo context so it can compare new code against the project's existing secure patterns. The model is selected via the `claude-model` input; the README documents the default as `claude-opus-4-1-20250805`, though `action.yml` ships `default: ''` (empty string → the driver's internal fallback). Note current Claude Code now defaults to **Opus 4.8** generally, so pin `claude-model` explicitly for reproducibility.

### Output schema, severity, confidence

Claude must return JSON (one finding object per issue):

```json
{
  "findings": [{
    "file": "path", "line": 0,
    "severity": "HIGH|MEDIUM|LOW",
    "category": "string",
    "description": "string",
    "exploit_scenario": "string",
    "recommendation": "string",
    "confidence": 0.0
  }],
  "analysis_summary": { "files_reviewed": 0, "high_severity": 0, "medium_severity": 0, "low_severity": 0, "review_completed": true }
}
```

- **HIGH** = directly exploitable (RCE, data breach, auth bypass); **MEDIUM** = significant impact under specific conditions; **LOW** = defense-in-depth / low impact.
- **Confidence bands**: 0.9–1.0 certain exploit path; 0.8–0.9 clear pattern; 0.7–0.8 suspicious; **<0.7 not reported**. The instruction is explicit: **"MINIMIZE FALSE POSITIVES: Only flag issues where you're >80% confident of actual exploitability."** A final filter keeps only confidence ≥8/10.

### Categories it flags

- **Input validation / injection**: SQL, command, LDAP, XPath, NoSQL, XXE, template injection, path traversal.
- **Authentication & authorization**: auth bypass, privilege escalation, session flaws, JWT issues.
- **Crypto & secrets**: hardcoded credentials, weak algorithms, improper key storage, cert-validation bypass.
- **Code execution**: insecure deserialization (pickle/YAML), `eval` injection, RCE.
- **XSS variants** and **data exposure**: sensitive logging, PII leakage, API/debug exposure.
- **Configuration & supply-chain** risks.

### False-positive filtering (the core differentiator)

A dedicated filtering stage drops noisy, low-impact classes. The prompt's **"DO NOT REPORT"** list includes: Denial-of-Service / resource exhaustion (even if service disruption is possible); secrets/sensitive data stored on disk ("handled by other processes"); rate-limiting concerns; memory/CPU exhaustion; generic input-validation gaps on non-critical fields without proven security impact; open redirects; memory-safety issues; **test files**; log spoofing; regex injection; client-side permission checks. This is the main reason it produces fewer false alarms than grep-style scanners.

### Configuration (`action.yml` inputs)

| Input | Required | Default | Purpose |
|---|---|---|---|
| `claude-api-key` | **Yes** | — | Anthropic key; must be enabled for both Claude API **and** Claude Code usage |
| `comment-pr` | No | `true` | Post findings as PR comments |
| `upload-results` | No | `true` | Upload results JSON as artifact |
| `exclude-directories` | No | `''` | Comma-separated dirs to skip |
| `claudecode-timeout` | No | `20` | Analysis timeout (minutes) |
| `claude-model` | No | `''` | Model id (e.g. `claude-sonnet-4-20250514`); README default `claude-opus-4-1-20250805` |
| `run-every-commit` | No | `false` | Skip cache, run on every commit |
| `false-positive-filtering-instructions` | No | `''` | Path to a custom FP-filtering text file |
| `custom-security-scan-instructions` | No | `''` | Path to text appended to the audit prompt |

Customization paths: copy `.claude/commands/security-review.md` into your repo's `.claude/commands/`, or point the two `*-instructions` inputs at project-specific text files to tune categories/exclusions to your threat model.

### Security advisory — read before adopting (June 2026)

Microsoft Threat Intelligence published a [case study (2026-06-05)](https://www.microsoft.com/en-us/security/blog/2026/06/05/securing-ci-cd-in-agentic-world-claude-code-github-action-case/) on a **prompt-injection → secret-exfiltration** chain in Claude Code GitHub workflows. Malicious instructions hidden in **untrusted GitHub content** (issue bodies, PR descriptions, comments) coerced the agent into reading `/proc/self/environ` to steal `ANTHROPIC_API_KEY`. The **Read tool lacked the Bash tool's Bubblewrap sandbox / env-scrubbing**; the attack also evaded GitHub Secret Scanning by instructing the model to truncate the key. **Anthropic mitigated this in Claude Code 2.1.128 on May 5, 2026** by unconditionally rejecting many `/proc/` files. Operational guidance: only review **trusted** PRs (enable "Require approval for all external contributors"), enforce least-privilege tokens, treat all GitHub content as untrusted in the system prompt, and apply the **"Agents Rule of Two"** — never let one agent simultaneously (a) ingest untrusted input, (b) hold secrets, and (c) talk to the outside.

### Adapting the approach into a local Claude Code security agent/skill

The repo is itself the blueprint — the same prompt also ships as the `/security-review` slash command. To build a generic, local white-hat reviewer:

1. **Reuse the slash-command pattern**: drop a `security-review.md` into `.claude/commands/` (or author a Skill) that encodes the three-phase methodology: *(a) repo context research → (b) compare diff against existing secure patterns → (c) data-flow / injection-point assessment*.
2. **Scope to the diff**: feed `git diff <base>...HEAD` (or staged changes) so the agent reviews only changed lines but reads surrounding files for context — keeps cost/noise down across TS/Go/Python/Java and backend/frontend/AI code.
3. **Port the FP discipline verbatim**: the `>80% confidence` gate, the confidence bands, and the "DO NOT REPORT" exclusion list are the highest-leverage piece to copy; without them an LLM SAST drowns users in noise.
4. **Keep the JSON schema** (file/line/severity/category/exploit_scenario/recommendation/confidence) for machine-readable, post-processable output, then render to markdown for humans.
5. **Make categories + exclusions config-driven** (mirror `custom-security-scan-instructions` / `false-positive-filtering-instructions`) so a project can add domain rules (e.g. AI/LLM prompt-injection, SSRF in agent tools) without forking the prompt.
6. **Harden the agent itself**: run with least-privilege file access, treat any reviewed content as untrusted, and avoid giving the same agent secrets + network egress (Rule of Two).

Sources: [README](https://github.com/anthropics/claude-code-security-review/blob/main/README.md), [action.yml](https://github.com/anthropics/claude-code-security-review/blob/main/action.yml), [prompts.py](https://github.com/anthropics/claude-code-security-review/blob/main/claudecode/prompts.py), [security-review.md](https://github.com/anthropics/claude-code-security-review/blob/main/.claude/commands/security-review.md), [Microsoft Security blog](https://www.microsoft.com/en-us/security/blog/2026/06/05/securing-ci-cd-in-agentic-world-claude-code-github-action-case/).

## Key takeaways

- Diff-aware + context-aware is the core idea: review only changed lines but read surrounding repo files for context, and compare new code against the project's existing secure patterns — works language-agnostically (TS/Go/Python/Java, backend/frontend/AI).
- The single highest-leverage element to copy is the false-positive discipline: a >80% exploitability confidence gate, explicit confidence bands (report only >=0.7, final filter >=8/10), and a hard 'DO NOT REPORT' exclusion list (DoS, rate-limiting, memory exhaustion, test files, on-disk secrets, log spoofing, regex injection, client-side permission checks, generic input-validation without proven impact).
- Use a structured JSON finding schema (file, line, severity HIGH/MEDIUM/LOW, category, exploit_scenario, recommendation, confidence) plus a summary block; render to markdown for humans. Machine-readable output enables thresholding and CI gating.
- Frame the agent as a 'senior security engineer' doing a 'focused' review of high-confidence, real-exploitation findings — altitude/persona framing measurably reduces noise.
- Categories to cover generically: injection (SQL/command/LDAP/XPath/NoSQL/XXE/template/path-traversal), authn/authz bypass + privilege escalation + JWT/session, crypto & secrets (hardcoded creds, weak algos, cert-validation bypass), insecure deserialization/RCE (pickle/YAML/eval), XSS, data exposure (logging/PII/debug), config and supply-chain.
- Make categories AND exclusions config-driven (mirror the action's custom-security-scan-instructions and false-positive-filtering-instructions file inputs) so each project tunes to its own threat model without forking the prompt.
- Ship it two ways like Anthropic does: a CI GitHub Action for PRs AND a local /security-review slash command (or Skill) sharing one prompt — the .claude/commands/security-review.md is directly reusable as a skill template.
- Three-phase methodology to encode: (1) repo context research (frameworks, sanitizers, secure patterns), (2) comparative analysis of the diff vs. those patterns, (3) data-flow / injection-point tracing.
- CRITICAL security hardening for any agentic reviewer: it is vulnerable to prompt injection from untrusted input. Microsoft (2026-06-05) showed PR/issue/comment text coercing the agent to read /proc/self/environ and exfiltrate ANTHROPIC_API_KEY; fixed in Claude Code 2.1.128 (2026-05-05).
- Apply the 'Agents Rule of Two': never let one agent simultaneously ingest untrusted input, hold secrets, and have external egress. Enforce least-privilege tokens, sandbox file/Bash access, and treat all reviewed content as untrusted in the system prompt.
- Only auto-review trusted PRs (enable 'Require approval for all external contributors'); for a local agent, the analog is reviewing the developer's own working tree/diff rather than arbitrary fetched branches.
- Pin the model explicitly (e.g. claude-opus or a dated sonnet id) rather than relying on defaults — the action's action.yml default is an empty string and the platform default has moved to Opus 4.8 (May 2026), so unpinned behavior drifts; also pin the npm @anthropic-ai/claude-code version which the action currently installs unpinned.

## Sources

- https://github.com/anthropics/claude-code-security-review
- https://github.com/anthropics/claude-code-security-review/blob/main/README.md
- https://github.com/anthropics/claude-code-security-review/blob/main/action.yml
- https://github.com/anthropics/claude-code-security-review/blob/main/claudecode/prompts.py
- https://github.com/anthropics/claude-code-security-review/blob/main/.claude/commands/security-review.md
- https://www.microsoft.com/en-us/security/blog/2026/06/05/securing-ci-cd-in-agentic-world-claude-code-github-action-case/

