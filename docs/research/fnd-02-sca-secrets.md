# research:sca-secrets

> Source: workflow `white-hacker-research` (wycjclbk6), agent `research:sca-secrets`

## SCA & Secret Scanning Tools (2026 Landscape)

This survey covers Software Composition Analysis (dependency CVE scanning) and secret scanning tools as of mid-2026, with install/run commands, ecosystem coverage, licensing, false-positive behavior, and CI usage. It closes with a recommended minimal cross-language default set for a white-hacker agent.

### Software Composition Analysis (SCA)

#### Multi-ecosystem scanners

| Tool | Install | Run | Ecosystems | License | FP behavior |
|---|---|---|---|---|---|
| **Trivy** (Aqua) | `brew install trivy` / apt repo / `aquasec/trivy` Docker image | `trivy fs .`, `trivy image <img>`, `trivy repo <url>` | OS packages (Alpine/Debian/Ubuntu/RHEL/Amazon), npm, pip, Go, Maven, Cargo, NuGet, Composer, Ruby + IaC + secrets + SBOM | Apache-2.0 (OSS); Aqua paid platform for mgmt | Presence-based (reports any vuln in lockfile), so more noise than reachability tools; supports `.trivyignore` and VEX |
| **Grype** (Anchore) | `curl -sSfL .../grype/main/install.sh \| sh -s -- -b /usr/local/bin` / `brew install grype` | `grype dir:.`, `grype <img>`, `grype sbom:./sbom.json` | OS packages + Ruby, Java, JS, Python, .NET, Go, PHP, Rust; consumes CycloneDX/SPDX/Syft SBOMs | Apache-2.0 (OSS) | Presence-based; pairs with Syft for SBOM-first workflow (generate once, rescan as DB updates); ignore rules via config |
| **OSV-Scanner** (Google/OSV) | `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest` / brew / binary | `osv-scanner scan -r .`, `osv-scanner scan image <img>`, `osv-scanner fix -M package.json -L package-lock.json` | 11+ languages, 19+ lockfiles: npm, pip, Maven, Go, Cargo, gem, Composer, NuGet, etc.; v2.3.5 (Mar 2026) adds transitive scanning for Python requirements.txt via deps.dev | Apache-2.0 (OSS); free OSV.dev backend | Uses normalized OSV.dev data (aggregates NVD, GHSA, ecosystem advisories); v2 adds guided remediation + interactive HTML reports |
| **Snyk Open Source** | `npm i -g snyk` then `snyk auth` | `snyk test`, `snyk monitor` | npm, Maven/Gradle, pip/Poetry, Go, .NET, Composer, RubyGems, Cargo, etc. | Proprietary; free tier = 200 OSS tests/month for individuals; Team ~$25/dev/mo, Enterprise $67k–90k/yr for 100 devs | Best FP reduction via **reachability analysis** (Java + JS) tracing call paths to vulnerable function; curated Snyk DB |
| **GitHub Dependabot** | Built into GitHub; enable in repo settings / `dependabot.yml` | Auto alerts + security/version-update PRs | All GitHub-supported ecosystems (npm, pip, Maven, Gradle, Go, Cargo, NuGet, Composer, etc.) | Free for all repos (public + private), no usage limits | No reachability; uses GitHub Advisory DB + compatibility scores; PR-native, low setup |

Two 2026 supply-chain notes for Trivy: v0.70.0 (Apr 17 2026) rotated GPG signing keys for the deb/rpm repos after a security incident (re-import the new key before apt/yum updates), and the official **Trivy GitHub Action was compromised twice in March 2026** by the "TeamPCP" campaign — pin Actions to a commit SHA, never to `@v1`/`@master`. ([Trivy 2026 overview](https://appsecsanta.com/trivy), [Trivy install docs](https://trivy.dev/docs/latest/getting-started/installation/))

#### Language-native scanners (lowest-friction, run in their own toolchain)

| Tool | Lang | Install | Run | FP / reachability |
|---|---|---|---|---|
| **npm audit** | JS/TS | bundled with npm | `npm audit`, `npm audit fix`, `--audit-level=high` | Known for noisy transitive/dev-dep alerts; GHSA-backed |
| **pnpm audit** | JS/TS | bundled with pnpm | `pnpm audit`, `pnpm audit --prod` | Since pnpm 11 queries NPM bulk advisories filtered by GHSA; ignore via `auditConfig.ignoreGhsas` |
| **pip-audit** (PyPA) | Python | `python -m pip install pip-audit` / `uv tool install pip-audit` | `pip-audit`, `pip-audit -r requirements.txt`, `--fix` | Uses PyPA Advisory DB + PyPI JSON; presence-based |
| **govulncheck** (Go team) | Go | `go install golang.org/x/vuln/cmd/govulncheck@latest` | `govulncheck ./...` | **Symbol-level reachability via call-graph** — reports only when vulnerable symbol is actually reachable, drastically cutting FPs (caveat: binary mode loses call graph, may over-report) |
| **OWASP Dependency-Check** | Java (+JS, .NET, etc.) | Maven/Gradle plugin or CLI | `mvn org.owasp:dependency-check-maven:check`; CLI `dependency-check.sh --scan .` | Higher FP rate (CPE matching); needs manual review and `suppression.xml`; NVD-backed; needs NVD API key in 2026 |
| **cargo-audit** | Rust | `cargo install cargo-audit` | `cargo audit`, `cargo audit fix` (experimental) | RustSec Advisory DB; low FP for the small Rust advisory set |

For Java, the Maven/Gradle path is OWASP Dependency-Check (or Trivy/OSV against the lockfile). govulncheck and cargo-audit are notable for being reachability/curated-DB–aware, so they produce the cleanest signal in their ecosystems. ([pip-audit](https://github.com/pypa/pip-audit), [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck), [cargo-audit](https://crates.io/crates/cargo-audit), [OWASP DC node analyzer](https://dependency-check.github.io/DependencyCheck/analyzers/node-audit-analyzer.html))

### Secret Scanning

| Tool | Install | Run | Scope | License | FP / key feature |
|---|---|---|---|---|---|
| **Gitleaks** | `brew install gitleaks` / Docker / Go | `gitleaks detect` (history), `gitleaks dir .`, pre-commit hook, gitleaks-action | Git history, uncommitted changes, files/dirs; regex + entropy rules | MIT (OSS) | Fast (ms-scale pre-commit); **feature-complete as of 2026 — security patches only** (latest v8.30.1, Mar 2026); no live verification → more raw matches; tune via `.gitleaks.toml` |
| **TruffleHog** (Truffle Security) | `brew install trufflehog` / install script / Docker | `trufflehog git <url>`, `trufflehog filesystem .`, `--results=verified` | Git, S3, Docker images, Slack, filesystems; 800+ credential detectors | AGPL/OSS core; paid enterprise | **Live credential verification** — makes API calls to confirm a secret is active; `--results=verified` collapses FPs to confirmed-live creds. Best in CI. |
| **detect-secrets** (Yelp) | `pip install detect-secrets` / `brew install detect-secrets` | `detect-secrets scan > .secrets.baseline`, `detect-secrets-hook` (pre-commit), `detect-secrets audit` | Staged changes / repo; 27 detectors (regex, Shannon entropy, keyword) | Apache-2.0 (OSS) | **Baseline model** (`.secrets.baseline`) accepts existing secrets, blocks new ones — strong for brownfield repos; tune `--base64-limit`/`--hex-limit`; no verification |

The well-established 2026 pattern: **Gitleaks at pre-commit** (speed, block before push) + **TruffleHog in CI with `--results=verified`** (depth + live verification so the security team only sees confirmed-live credentials). detect-secrets is the enterprise choice when you need a baseline to onboard a repo with legacy secrets without drowning in alerts. ([Gitleaks vs TruffleHog 2026](https://appsecsanta.com/secret-scanning-tools/gitleaks-vs-trufflehog), [detect-secrets 2026](https://appsecsanta.com/detect-secrets))

### CI usage in 2026

- **Trivy/Grype/OSV-Scanner**: single static binary, no runtime deps — drop into any CI; emit SARIF for GitHub code-scanning. Pin GitHub Actions to SHAs after the 2026 Trivy-action compromises.
- **Snyk/Dependabot**: Dependabot is GitHub-native (PR-driven, zero infra, free); Snyk CLI acts as a build gate (`snyk test --severity-threshold=high`) across all CI platforms.
- **Language-native** (govulncheck, pip-audit, cargo-audit, npm/pnpm audit): cheapest to add because they run inside the existing toolchain step; ideal as a fast pre-merge gate.
- **Secrets**: Gitleaks pre-commit + TruffleHog/Gitleaks in CI; note GitHub Actions runner default moves to **Node 24 on June 2, 2026** (older actions pinned to Node 20 will warn).

### Recommended minimal cross-language default set

For a generic white-hat agent that must work across TS/Go/Python/Java and backend/frontend/AI repos, standardize on **two OSS, vendor-neutral, single-binary tools plus opportunistic native scanners**:

1. **SCA core: OSV-Scanner** — broadest lockfile/ecosystem coverage (TS, Go, Python, Java/Maven, Rust, etc.), Apache-2.0, no account, normalized OSV.dev data, SARIF output, and built-in `fix` remediation. **Trivy** is the equally valid alternative/complement when container images, IaC, and SBOM also matter (one binary covers deps + misconfig + secrets).
2. **Secrets core: Gitleaks** (pre-commit/fast pass) **+ TruffleHog `--results=verified`** (CI verification pass). This two-tool combo is the de-facto 2026 standard and cleanly separates "fast block" from "confirmed-live triage."
3. **Reachability boosters where the toolchain exists**: run **govulncheck** for Go and **cargo-audit** for Rust as native gates (call-graph / curated DB → low FP); use **pip-audit** for Python and **npm/pnpm audit** for JS as zero-install fallbacks already present in the repo's package manager.
4. **For Java**, prefer OSV-Scanner/Trivy against the build lockfile over OWASP Dependency-Check unless a Maven/Gradle-plugin integration is required, due to Dependency-Check's higher CPE-matching FP rate.

This gives the agent a **default trio of OSV-Scanner + Gitleaks + TruffleHog** (all OSS, all single-purpose, all language-agnostic), augmented by language-native reachability scanners when the project's toolchain makes them free to run.


## Key takeaways

- Default cross-language trio for the agent: OSV-Scanner (SCA) + Gitleaks (fast secret pass) + TruffleHog --results=verified (CI verification). All OSS, single-purpose, language-agnostic.
- OSV-Scanner v2 (v2.3.5, Mar 2026) is the best vendor-neutral SCA: 11+ languages / 19+ lockfiles, Apache-2.0, OSV.dev data, SARIF, built-in `fix`; v2 added transitive Python requirements.txt scanning. Install: `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`.
- Trivy is the strongest single-binary all-rounder (deps + IaC + secrets + SBOM, OS + app packages) and a valid SCA core when containers/IaC matter; use it OR OSV-Scanner, not necessarily both.
- Reachability beats presence for false positives: govulncheck (Go, call-graph) and Snyk (Java/JS) report only reachable vulnerable symbols; prefer govulncheck/cargo-audit as native low-FP gates where the toolchain exists.
- Language-native scanners are near-zero-cost gates already in the toolchain: govulncheck (`go install golang.org/x/vuln/cmd/govulncheck@latest`), pip-audit (`pip install pip-audit`), cargo-audit (`cargo install cargo-audit`), npm/pnpm audit (bundled).
- Gitleaks is MIT, fast, ideal for pre-commit, but is now FEATURE-COMPLETE as of 2026 (security patches only, latest v8.30.1) and has no live verification.
- TruffleHog's differentiator is live credential verification across 800+ detectors and non-git sources (S3, Docker, Slack); `--results=verified` collapses noise to confirmed-active creds — best run in CI.
- detect-secrets (Yelp, Apache-2.0) uses a baseline (.secrets.baseline) model to onboard brownfield repos without alert floods; pick it when legacy secrets exist in history.
- Snyk is proprietary with a tight free tier (200 OSS tests/month); Dependabot is fully free and GitHub-native but has no reachability — neither is a good vendor-neutral default for a portable agent.
- OWASP Dependency-Check (Java/Maven/Gradle) has a higher CPE-matching false-positive rate and needs suppression files + an NVD API key in 2026; prefer OSV-Scanner/Trivy against the lockfile unless a Maven plugin is mandatory.
- CI/supply-chain hygiene for 2026: PIN GitHub Actions to commit SHAs — the official Trivy action was compromised twice in March 2026 (TeamPCP); Trivy also rotated deb/rpm GPG keys in v0.70.0; GitHub runners default to Node 24 on June 2, 2026.
- All four single-binary scanners (Trivy, Grype, OSV-Scanner) and secret tools emit SARIF for GitHub code-scanning and run as static binaries with no runtime dependencies, making them trivial to standardize across heterogeneous repos.

## Sources

- https://github.com/aquasecurity/trivy
- https://trivy.dev/docs/latest/getting-started/installation/
- https://appsecsanta.com/trivy
- https://github.com/anchore/grype
- https://oss.anchore.com/docs/guides/vulnerability/getting-started/
- https://appsecsanta.com/grype
- https://github.com/google/osv-scanner
- https://google.github.io/osv-scanner/installation/
- https://appsecsanta.com/osv-scanner
- https://pypi.org/project/pip-audit/
- https://github.com/pypa/pip-audit
- https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
- https://go.dev/doc/tutorial/govulncheck
- https://crates.io/crates/cargo-audit
- https://pnpm.io/cli/audit
- https://dependency-check.github.io/DependencyCheck/analyzers/node-audit-analyzer.html
- https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities/
- https://appsecsanta.com/sca-tools/snyk-vs-dependabot
- https://snykpricing.com/
- https://github.com/trufflesecurity/trufflehog
- https://appsecsanta.com/secret-scanning-tools/gitleaks-vs-trufflehog
- https://github.com/gitleaks/gitleaks
- https://gitleaks.io/
- https://appsecsanta.com/gitleaks
- https://github.com/Yelp/detect-secrets
- https://appsecsanta.com/detect-secrets

