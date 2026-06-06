# THREAT_MODEL — floor-review polyglot fixture

> Produced by executing the `sec-threat-model` method (`.claude/skills/sec-threat-model/SKILL.md`)
> against this mini-repo. No prior `THREAT_MODEL.md` existed → **synthesized** from code structure
> (no docs / no git history for the fixture). Run with `--auto` semantics (non-interactive).

## 1. Assets
- **App data** behind the HTTP services (the `users` table read by the Python service).
- **Host command execution context** — two services shell out to OS commands; the shell is an
  asset an attacker wants to reach.
- (No credentials/secrets, no model/system prompts, no multi-tenant data in this fixture.)

## 2. Entry points (untrusted-input surfaces — discovery partitions by these)
| Entry point | Handler (file:symbol) | Untrusted input | Stack |
|-------------|-----------------------|-----------------|-------|
| `GET /ping` | `go-vuln/main.go:pingHandler` (:13) | `?host=` query param | Go / net/http |
| `GET /user` | `py-vuln/app.py:get_user` (:14) | `?id=` query param | Python / Flask |
| `GET /greet` | `ts-vuln/handler.ts` (:10) | `?name=` query param | TS / express |
| `go-clean/ py-clean/ ts-clean/` | safe look-alike handlers | same params | — |

## 3. Trust boundaries
- **Internet → service**: each handler accepts an unauthenticated remote request (no auth layer in
  front). Required access = `unauth-remote` ⇒ severity ceiling is HIGH (see severity-rubric).
- **Service → OS shell** (Go, TS): user input crossing into a shell-interpreted string.
- **Service → SQL store** (Python): user input crossing into a query string.

## 4. In-scope vuln classes
From [`core-checklist.md`](../../../../.claude/skills/_shared/reference/core-checklist.md): **Injection**
(command + SQL) is primary; output-handling and config secondary. Per-language sinks loaded from the
appendices named by `SCAN-PLAN.json` (`lang-go.md`, `lang-python.md`, `lang-typescript.md`) plus
`api.md` (express + flask ⇒ OWASP API Top 10 in scope). **Out of scope** (this engagement): the
exclusion list (`exclusion-rules.md`) — e.g. volumetric DoS, memory-safety in memory-safe langs.

## 5. Scoring standard
**CVSS 4.0** (`--auto` default; no CI policy stated otherwise). Severity is still derived in triage
from preconditions + required access (precondition counting), labelled under CVSS 4.0.

## Assumptions & drift
- Synthesized — every item above is **assumed** from code structure (the fixture has no docs/history).
- No authentication/session layer observed ⇒ all entry points treated as `unauth-remote`.
- `SCAN-PLAN.json` (same `run/` dir) reports `ai_pass:false` ⇒ AI/LLM classes are out of scope here.
