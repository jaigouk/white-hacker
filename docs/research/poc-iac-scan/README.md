# PoC — IaC capability via Trivy `config` (T-3.5), offline

- **Status:** ✅ PASS
- **Date:** 2026-06-06
- **Verifies:** the **IaC capability** runs a real misconfig scanner against infra-as-code, **offline**,
  and that the capability is invoked **only when infra is present** (no-infra repos skip cleanly).

## Fixture
`fixture-infra/Dockerfile` — deliberately misconfigured: `FROM python:latest` (floating tag),
`USER root`, no `HEALTHCHECK`.

## Run (offline — note `--skip-check-update`, not `--skip-db-update`)
```bash
trivy config --skip-check-update --quiet --format json \
  docs/research/poc-iac-scan/fixture-infra > docs/research/poc-iac-scan/trivy-config-output.json
```
> `trivy config` uses `--skip-check-update` (the misconfig *checks* bundle), **not** the `--skip-db-update`
> flag that `trivy fs`/`image` use for the vuln DB. Confirmed on the host's Trivy **v0.69.0**.

## Result (verified)
- **exit 0**, **3 misconfigurations** found, mapping cleanly to `reference/infra.md` guidance:

| ID | Severity | Title | infra.md rule |
|----|----------|-------|---------------|
| DS-0002 | HIGH | Image user should not be 'root' | run as non-root numeric UID |
| DS-0001 | MEDIUM | ':latest' tag used | pin base image by digest, not a floating tag |
| DS-0026 | LOW | No HEALTHCHECK defined | image hygiene |

## No-infra skip (verified)
`detect_tools.py` on a repo with only `go.mod` (no Dockerfile/Actions) → `infra: []` and **`iac`
absent from `category_tool`** — the IaC capability is never invoked. The capability is assembled only
when `SCAN-PLAN.json` reports infra (mirrors how `ai-redteam` only appears when `ai_pass`).

## Conclusion
The IaC capability is real and offline-capable on this host (Trivy present); ADR-006 pinning hygiene
is documented in `infra.md` + `tool-registry.md`. On a host without any IaC tool, the stage degrades
to applying `infra.md` over the files on the floor (`tool_assisted:false`) and never blocks.
