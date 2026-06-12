# Tool registry — capability → tools (extensible, self-updating)

> **The concept owns this file, not any vendor.** Tools below are *illustrative defaults*, not
> requirements. The agent depends on a **capability**, discovers what is installed at runtime,
> maps it here, and **degrades to the Read/Grep/Glob floor** when a capability has no tool
> (ADR-003, ADR-015). New/unknown tools are added here by `/sec-learn` and `/sec-kb-refresh`
> as reviewable, dated diffs — there will always be tools not yet listed.

> **Admissibility (ADR-025) governs which tools may be listed.** Two deterministic gates decide
> membership *before* a tool is pinned: a **License-gate** (`license ∈ {MIT, Apache-2.0}` only —
> reject BSD/LGPL/GPL/AGPL/MPL/any copyleft/proprietary; a dual offering one of them *at the
> user's option* passes) and an **Egress-gate** (the DEFAULT invocation runs local/offline, uploads
> no source, sends no telemetry — a telemetry-on-by-default tool is admissible ONLY with its disable
> flag pinned). Each admitted row carries `license` / `data_egress` / `gdpr` (admissibility evidence
> inline); rejected tools live in the two **Rejected** subsections with their SPDX + reason.
> Admissibility **composes with** the ADR-024 §5 artifact-provenance **admission** arm (pin to an
> immutable ref + verify checksum/cosign/SLSA at execution — *not re-derived here*); ADR-027
> permanently removes Trivy (TeamPCP — license-clean ≠ admissible).

## How to read this
- **Capability** = what the agent needs (the durable interface).
- **Floor** = the zero-install fallback that always works.
- Each tool entry should carry: `tool · license · data_egress · gdpr · langs/ecosystems · invoke ·
  pin+verify · added(date,source)`.
- **`license`** = the upstream SPDX id; must ∈ {MIT, Apache-2.0} (or a dual offering one) for an
  admitted row (ADR-025).
- **`data_egress`** = `local` | `local+db-fetch` (DB-backed; fetch network-on, analyze network-off —
  ADR-024 §2) | `telemetry-off-flag` (admitted only with the pinned flag) | `upload` (rejected).
- **`gdpr`** = whether the tool, in its admitted invocation, sends data off-host (`none` for fully
  local tools; the flag-gated note where relevant). The *tool's* data-flow only — the agent's own
  model-call PII posture is wh-81y, not this column.
- Prefer whatever the **repo or user already has**; do not install without need + pinning (ADR-006).
- **Executable twin:** the runtime selection *order* lives in
  `plugins/white-hacker/skills/sec-detect/scripts/detect_tools.py::SCANNER_PREFERENCE` (the
  capability→ordered-tools map `sec-detect` actually binds, including the `ai-redteam` capability
  added in Phase 2). Keep this doc and that map in sync — `_shared/scripts/tests/test_registry_lock.py`
  fails if a capability in the code is missing here, and pins per-tool present/absent (admitted tools
  PRESENT, rejected tools ABSENT).

## Capabilities

### SAST (code-level taint/pattern analysis)
- **Floor:** Read/Grep/Glob heuristic pass (confidence capped). **PRIMARY** for cross-language taint
  **and Java** — no admissible cross-language taint engine (Opengrep/Semgrep are LGPL-2.1) and no
  admissible Java SAST (find-sec-bugs/SpotBugs are LGPL) remain after the License-gate (ADR-025 §3).
  ADR-011's cross-language Opengrep default is **superseded** by floor + per-language linters
  (ADR-025 §4 — a precision DOWNGRADE, measured before KEEP, not asserted; the live SAST-default flip
  is a gated follow-up, NOT wired in `SCANNER_PREFERENCE` here).
- Admitted (per-language, MIT/Apache):

  | tool | license | data_egress | gdpr | langs | invoke | pin+verify |
  | --- | --- | --- | --- | --- | --- | --- |
  | **gosec** | Apache-2.0 | local | none | Go | `gosec ./...` | release binary; pin version + sha256 |
  | **bandit** | Apache-2.0 | local | none | Python | `bandit -r .` | PyPI; `pip install bandit==<ver> --require-hashes` |
  | **ruff** (`-S`/bandit rules) | MIT | local | none | Python | `ruff check --select S` | PyPI; `--require-hashes` |
  | **eslint-plugin-security** | Apache-2.0 | local | none | JS/TS | eslint plugin | npm; lockfile-pinned + integrity hash |

  - Java taint → **floor only** (ADR-025 §3 exception; track an MIT cross-language taint engine via
    `sec-kb-refresh`).

### SCA (dependency / lockfile CVEs)
- **Floor:** read manifests/lockfiles, grep pinned versions, reason from known-bad ranges.
- Admitted:

  | tool | license | data_egress | gdpr | langs | invoke | pin+verify |
  | --- | --- | --- | --- | --- | --- | --- |
  | **OSV-Scanner** | Apache-2.0 | local+db-fetch | none | * (cross-language) | `osv-scanner -r .` | Action `google/osv-scanner-action@9a498708959aeaef5ef730655706c5a1df1edbc2 # v2.3.8` (composite); binary verify = **SLSA provenance** `slsa-verifier verify-artifact <bin> --provenance-path multiple.intoto.jsonl --source-uri github.com/google/osv-scanner` + `osv-scanner_SHA256SUMS` |
  | **Grype** | Apache-2.0 | local+db-fetch | none | * (image/dir) | `grype dir:.` (`GRYPE_DB_AUTO_UPDATE=false` + pre-seeded DB; fetch/analyze split, ADR-024 §2) | Action `anchore/scan-action@e1165082ffb1fe366ebaf02d8526e7c4989ea9d2 # v7.4.0`; binary verify = **cosign keyless** `cosign verify-blob --certificate <.pem> --signature <.sig> --certificate-identity-regexp 'https://github.com/anchore/grype' --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt` then sha256 the binary |
  | **pip-audit** | Apache-2.0 | local+db-fetch | none | Python | `pip-audit` | PyPI; `--require-hashes` |
  | **cargo-audit** | MIT OR Apache-2.0 (dual — elect permissive) | local+db-fetch | none | Rust | `cargo audit` | crates.io; pin + checksum |

- **Note (ADR-007):** Grype is **registry-listed but never auto-selected** by the static filesystem
  default (`SCANNER_PREFERENCE`) — no surprise image/DB pull; use it for explicit image/dir scope.

### Container image + SBOM
- **Floor:** read the Dockerfile / lockfiles and apply `reference/infra.md`.
- Admitted (explicit image/SBOM scope only — **never auto-selected** by `SCANNER_PREFERENCE`, ADR-007):

  | tool | license | data_egress | gdpr | langs | invoke | pin+verify |
  | --- | --- | --- | --- | --- | --- | --- |
  | **Grype** | Apache-2.0 | local+db-fetch | none | image/dir CVE | `grype <image>` | as SCA row above (cosign keyless) |
  | **Syft** | Apache-2.0 | local | none | SBOM | `syft <image>` | Action `anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610 # v0.24.0`; binary verify = **cosign keyless** (identity `anchore/syft`, `checksums.txt`+`.pem`+`.sig`) |

### Secrets
- **Floor:** grep high-entropy + known key patterns.
- Admitted:

  | tool | license | data_egress | gdpr | langs | invoke | pin+verify |
  | --- | --- | --- | --- | --- | --- | --- |
  | **gitleaks** | MIT | local | none | * | `gitleaks detect` | Action `gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e # v3.0.0` (node20); binary = **checksum-only, NO upstream signature** → pin the **expected binary sha256 VALUE in our own pin file** (`reference/pins/gitleaks.sha256`, reviewed once at admission via human PR), then verify the download against the in-repo value. The upstream `checksums.txt` ships from the SAME release as the binary, so it does NOT defeat a publisher/release compromise (the TeamPCP vector re-published binary + metadata); the in-repo value makes the trust root our git history (ADR-024 §5 admission checksum — its trust-root location, not a second mechanism). **Recorded gap:** no upstream signature; weakest primitive of the set. **Bus-factor caveat:** single-maintainer, feature-complete (security patches only; maintainer → "Betterleaks" — by Zach Rice, the original gitleaks author [primary-sourced: github.com/betterleaks/betterleaks; HelpNetSecurity 2026-03-19]) — track Betterleaks via `sec-kb-refresh` (re-runs the same admissibility + admission gates) |
  | **detect-secrets** | Apache-2.0 | local | none | * | `detect-secrets scan` | PyPI; `--require-hashes` |

### IaC / container / CI
- **Floor:** read Dockerfile / manifests / workflows and apply `reference/infra.md`.
- Admitted:

  | tool | license | data_egress | gdpr | langs | invoke | pin+verify |
  | --- | --- | --- | --- | --- | --- | --- |
  | **Checkov** | Apache-2.0 | local | none | IaC (incl. Dockerfile — fills hadolint's slot) | `checkov -d .` | **prefer the binary/pip path** — `pip install checkov==<ver> --require-hashes` OR a **digest**-pinned image `ghcr.io/bridgecrewio/checkov@sha256:…`. The Docker `checkov-action@a6a5c23963b9d127020ae43a959cd5d8eefc94c7 # v12.3106.0` is `using: docker` over a **mutable `:3.3.0` image tag** (a SHA-pinned wrapper over a tag-pinned payload — the `trivy-action` trap class), so pinning the Action's SHA does NOT pin the scanner binary; prefer binary/digest |
  | **actionlint** | MIT | local | none | GitHub Actions | `actionlint` | release binary; pin + sha256 |
  | **zizmor** | MIT | local | none | GitHub Actions | `zizmor .github/workflows` | PyPI/crates; pin + checksum |
  | **kube-linter** (optional EXTEND — k8s second-source) | Apache-2.0 | local | none | Kubernetes | `kube-linter lint .` | Action `stackrox/kube-linter-action@87802a2f4e01abebb3ee3c67a3002fea71f6eae5 # v1.0.7` (composite); binary verify = **cosign Sigstore bundle** `cosign verify-blob --bundle kube-linter-linux.sigstore.json --certificate-identity-regexp 'stackrox/kube-linter' --certificate-oidc-issuer https://token.actions.githubusercontent.com kube-linter-linux` (the *tool* tag v0.8.3 is annotated → deref to commit `10ae003038c81855aca8489df5e35da150f4dc2e`) |

### AI-redteam (behavioral, for running LLM/agent apps)
- **Floor:** static `reference/ai-llm.md` + KB technique patterns over the code.
- Admitted:

  | tool | license | data_egress | gdpr | langs | invoke | pin+verify |
  | --- | --- | --- | --- | --- | --- | --- |
  | **promptfoo** | MIT | telemetry-off-flag (`PROMPTFOO_DISABLE_TELEMETRY=1`) | flag-gated: with the env var set, sends no prompts/outputs/configs | * | `promptfoo redteam` | npm; lockfile-pinned + integrity. **Admit ONLY with `PROMPTFOO_DISABLE_TELEMETRY=1` pinned** (telemetry on by default; re-verify the flag at version bump — R4) |
  | **garak** | Apache-2.0 | local | none | * | `garak` | PyPI; `--require-hashes` |

### (add new capabilities here as discovered)

## Rejected (License-gate) — fail `license ∈ {MIT, Apache-2.0}` (ADR-025 §2)
> Copyleft / proprietary / BSD-3 tools are NOT admissible regardless of capability fit; the floor +
> the admitted per-capability tools cover their slots. Each SPDX is upstream-verified 2026-06-10.

| tool | SPDX | capability it would serve | reason (rejected) |
| --- | --- | --- | --- |
| **Opengrep** | LGPL-2.1 | SAST (cross-language) | copyleft; superseded as the SAST default by floor + per-language linters (ADR-011 → ADR-025 §4) |
| **Semgrep CE** | LGPL-2.1 | SAST (cross-language) | copyleft |
| **CodeQL CLI** | proprietary | SAST | proprietary GitHub terms; ALSO forbids private-repo/CI analysis without paid GHAS (double fail w/ egress) |
| **govulncheck** | BSD-3-Clause (DB data CC-BY-4.0) | SCA (Go) | BSD-3 — exactly the psutil precedent (ADR-023); the bar is MIT/Apache-2.0, not "permissive" |
| **trufflehog** | AGPL-3.0 | secrets | network-copyleft; ALSO `--results=verified` = egress |
| **hadolint** | GPL-3.0 | IaC (Dockerfile) | copyleft (Checkov covers Dockerfile misconfig in its place) |
| **find-sec-bugs** | LGPL-3.0 | SAST (Java) | copyleft — leaves Java taint floor-only (ADR-025 §3) |

## Rejected (integrity/TeamPCP) — license-clean but compromised (ADR-027 §1)
> A category DISTINCT from the License-gate: these tools pass the license rule but are
> integrity-compromised (the TeamPCP campaign). Admissibility composes with admission/integrity —
> license-clean ≠ admissible.

| tool | SPDX | capability it served | reason (rejected) |
| --- | --- | --- | --- |
| **Trivy** | Apache-2.0 | SCA · IaC · image · secrets · SBOM | **TeamPCP — CVE-2026-33634 / GHSA-69fq-xp46-6x23**: `trivy-action`/`setup-trivy` tags force-pushed, malicious binary v0.69.4 + images v0.69.5–.6 published. **Permanently removed (ADR-027 §1) — does not return**; replaced by Grype+Syft · Checkov · OSV-Scanner · gitleaks |
| **KICS** | Apache-2.0 | IaC/misconfig | same TeamPCP campaign (`20260609_trivy_teampcp_supply_chain.md:44`) — re-introduces a compromised-vendor surface |

## Pinning & supply-chain hygiene (ADR-006 — non-negotiable)
The reviewer must not become a supply-chain vector itself. Never auto-install from unpinned sources;
prefer a tool the repo/user already has, else a digest-pinned binary/image with signature/checksum
verification. **The resolved Action-SHAs above are point-in-time (2026-06-10) — re-resolve + re-verify
at the actual pin commit** (a version tag is a mutable ref; the `trivy-action` 76/77 tag force-push is
the precedent that **only a full commit-SHA is immutable**, ADR-024 §5).
- **Actions/CI tools:** pin GitHub Actions to a **full commit-SHA** (the official Trivy action was
  compromised twice in March 2026); pin Docker base images **by digest**, never a mutable image tag
  (the checkov-action `:3.3.0` case above).
- **Wrapper-shape check before pinning (ADR-027 §4):** confirm each Action's `action.yml` is
  `using: composite` or `using: node20` — NOT `using: docker` over a mutable `image:` tag (that is the
  trivy-action / checkov-action trap; route such wrappers to the binary/digest-pinned path).
- **DB-backed tools (Grype, OSV-Scanner, pip-audit, cargo-audit) use the fetch/analyze split**
  (ADR-024 §2): FETCH network-on, then ANALYZE network-off — never ambient egress during a scan.
- New/updated tools are added **only** as reviewable, dated change-log entries below (ADR-015), after
  passing the ADR-025 admissibility gates.

## Change log
> Append dated entries when a tool/capability is added or retired. Format:
> `YYYY-MM-DD · +/- · capability · tool · source · rationale`
- 2026-06-06 · seed · initial registry from research (`docs/research/fnd-tool-matrix.md`).
- 2026-06-09 · - · iac · trivy · CVE-2026-33634/GHSA-69fq-xp46-6x23 · TeamPCP compromise — demoted below checkov, interim quarantine (wh-d5b), permanent removal wh-nvk
- 2026-06-10 · - · sca+iac · trivy · permanent removal (wh-nvk / ADR-027) — TeamPCP integrity compromise; replaced by Grype+Syft / Checkov / OSV-Scanner / gitleaks (each pinned-to-SHA + verified, ADR-024 §5). Supersedes the 2026-06-09 *interim* quarantine framing — Trivy does not return.
- 2026-06-10 · + · admissibility · license/data_egress/gdpr columns · ADR-025 (wh-xn0) — two-gate admissibility (MIT/Apache-2.0-only + local/no-default-telemetry); License-gate violators (Opengrep/Semgrep/CodeQL/govulncheck/trufflehog/hadolint/find-sec-bugs) moved to Rejected (License-gate); admitted replacement rows (Grype/Syft/Checkov/OSV-Scanner/gitleaks/cargo-audit/detect-secrets + kube-linter opt) installed with per-tool pin+verify (ADR-024 §5).
