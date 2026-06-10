# Trivy permanent removal + the diversified multi-vendor SCA/IaC replacement set

**Spike:** wh-nvk (epic wh-hxt — supply-chain-resilient tooling) · **Date:** 2026-06-09
(Action-SHA + kube-linter upstream verification 2026-06-10) · **Status:** RESOLVED → ADR text below
(`## ADR text — TL appends serially`); the ADR number is assigned at append time (TL-serialized after
wh-562's ADR in this wave).

> **The drop-Trivy decision is SETTLED — this spike does NOT re-debate it.** Drivers are FINAL in
> `docs/research/20260609_trivy_teampcp_supply_chain.md` (RQ1 verification + RQ2 exposure): the
> `trivy-action`/`setup-trivy` tags were **force-pushed** by **TeamPCP** (CVE-2026-33634 /
> GHSA-69fq-xp46-6x23), a malicious binary (v0.69.4) + images (v0.69.5–.6) were published, and the
> user has decided Trivy does not return. This spike grounds the **permanent removal** + the
> **diversified replacement set**, and wires per-tool pin+verify into ADR-024's admission arm.

> **Subordination to ADR-024 (CONTAIN-primary) — read first.** Per ADR-024 §1
> (`docs/ARD.md:300`), DIVERSIFY is **demoted from "the security answer" to blast-radius reduction**:
> security comes from **containment** (every tool runs offline + no-creds + sandboxed +
> provenance-verified), not from picking a "more trustworthy" tool. Mini Shai-Hulud victims carried
> **valid SLSA L3 provenance** and were still compromised; the only control that stopped it in flight
> was an **egress allowlist**. This report AGREES with that framing throughout: swapping Trivy for
> Grype+Syft+Checkov+… does NOT make us safe — **CONTAIN makes any tool (Trivy, its replacement, or
> one not yet picked) inert if compromised.** Diversity here buys *blast-radius reduction* (no single
> maintainer compromise takes out the whole pipeline) **and raises the count of supply-chain
> surfaces** — so every replacement must pass the same admissibility (ADR-025) + admission (ADR-024)
> gates. Diversity is a defense-in-depth multiplier UNDER containment, never a substitute for it.

---

## 1. RQ1 — capabilities-to-replace map (what Trivy covered; what remains to remove)

Trivy was a do-everything tool. Mapping each capability it served to its replacement, with the
**CURRENT** code/registry state cited (the GROOM 2026-06-10 correction binds: `iac` is ALREADY
checkov-first via wh-d5b; the ticket body's "iac lead `(trivy,*)`" is STALE):

| Capability Trivy covered | Scope | Replacement (this spike) | Current state in code/registry |
| --- | --- | --- | --- |
| **SCA (dependency/lockfile CVE)** | multi-ecosystem (npm, PyPI, Go, Maven, RubyGems, Cargo, …) | **OSV-Scanner** (cross-language) + **Grype** (also image/OCI) — native gates (pip-audit/cargo-audit) lead per-language where present | `SCANNER_PREFERENCE["sca"]` = `[("govulncheck","go"),("pip-audit","python"),("osv-scanner","*"),("trivy","*")]` — **Trivy still listed LAST** (`detect_tools.py:113-114`); registry SCA examples name Trivy (`tool-registry.md:30`) |
| **IaC / misconfig** | Dockerfile · k8s · Helm · Terraform · CloudFormation · ARM | **Checkov** (all of the above incl. Dockerfile — fills hadolint's GPL-rejected slot) + **kube-linter** (k8s second-source, optional) | `SCANNER_PREFERENCE["iac"]` = `[("checkov","*"),("trivy","*"),("hadolint","docker")]` — **Checkov ALREADY leads**, Trivy demoted to 2nd via wh-d5b (`detect_tools.py:116`); registry IaC examples Checkov-led (`tool-registry.md:38`) |
| **Container-image CVE** | OS pkgs + language deps in an OCI image | **Grype** (image/dir/SBOM scanner; Anchore) + **Syft** (SBOM generation feeding Grype) | not in `SCANNER_PREFERENCE` (the agent's static-default review is filesystem, not image-pull — ADR-007); registry SCA line (`tool-registry.md:30`) |
| **Secrets** | regex/entropy scan of a tree | **gitleaks** (already the secrets lead) | `SCANNER_PREFERENCE["secrets"]` = `[("gitleaks","*"),("trufflehog","*")]` (`detect_tools.py:115`) — gitleaks already leads; Trivy never the secrets default here |
| **SBOM** | CycloneDX/SPDX generation | **Syft** (purpose-built; Grype consumes it) | registry SCA line (`tool-registry.md:30`) |

**What REMAINS to do (the impl delta — RQ6 specifies it as ONE coordinated change):**
1. **Remove `("trivy","*")` from `SCANNER_PREFERENCE["sca"]`** (`detect_tools.py:114`) — the last Trivy
   reference in the executable preference map (the iac demotion already landed via wh-d5b; iac still
   lists `("trivy","*")` 2nd at `:116`, also to be removed).
2. **Retire the Trivy pin/COMPROMISED block** in `tool-registry.md:50-57` and the SCA/IaC example lines
   (`:30`, `:38`) that name Trivy; add the replacement rows with ADR-025's `license`/`data_egress`/`gdpr`
   columns.
3. **Remove/replace the `r"0\.7[01]"` assertion** at `test_registry_lock.py:51` — it asserts "registry
   must carry the safe Trivy version line"; once the Trivy pin line is gone, the lock goes RED unless the
   assertion is removed/repurposed (CONFIRMED present, GROOM 2026-06-10).

→ **Authoritative "what must be covered" list:** SCA multi-ecosystem · IaC/misconfig (Dockerfile, k8s,
Helm, Terraform, CloudFormation) · container-image CVE · secrets · SBOM. **No silent gap:** the
coverage-parity column in §2(e) shows each is covered by a replacement.

## 2. RQ2 — the scorecard (5 tools × 5 dimensions → GO / EXTEND / REJECT)

License + data-egress verdicts are **CITED from wh-xn0's upstream-verified matrix** (§3b/§5 of
`docs/research/20260609_tool_admissibility_license_gdpr.md`, each row carrying a raw-LICENSE /
GitHub-License-API URL, verified 2026-06-10) — **NOT re-derived here** (override #3). The ONE tool not
in the xn0 matrix — **kube-linter** — I verified upstream myself (GitHub License API + Releases API,
2026-06-10; URLs in §2.3). CI-pinnability (d) is RQ5's resolved Action-SHA + release-artifact facts.

| Tool | (a) License | (b) Maintenance / bus-factor | (c) Data-egress | (d) CI pinnability | (e) Coverage parity vs RQ1 | **Verdict** |
| --- | --- | --- | --- | --- | --- | --- |
| **Grype** (Anchore) | **Apache-2.0** (xn0 §3b, License API `anchore/grype`) | Active; vendor-backed (Anchore); latest **v0.114.0**; frequent releases | **PASS** — local; DB auto-update OFF + fetch/analyze split (xn0 §5: `GRYPE_DB_AUTO_UPDATE=false`) | **cosign-keyless** signed (`checksums.txt` + `.pem` + `.sig`); official Action `anchore/scan-action` (§5) | container-image CVE + dir SCA + SBOM-consume | **GO** |
| **Syft** (Anchore) | **Apache-2.0** (xn0 §3b, License API `anchore/syft`) | Active; vendor-backed; latest **v1.45.1** | **PASS** — fully local (xn0 §5) | **cosign-keyless** signed (same triple); official Action `anchore/sbom-action` (§5) | SBOM generation (feeds Grype) | **GO** |
| **Checkov** (Palo Alto / Prisma) | **Apache-2.0** (xn0 §3b, License API `bridgecrewio/checkov`) | Very active; latest **3.2.534** (2026-06-09); ~daily cadence (corroborates digest "~2-4d") | **PASS only offline** — does NOT upload source by default; the `--bc-api-key` Prisma enrich is **opt-in push** → run **without `--bc-api-key`** (xn0 §5 Egress-gate PASS) | binary path = `pip install checkov==<ver>` (cleaner pin); official Action is **Docker-based** (pins `:3.3.0` image tag — see §5 caveat) | IaC/misconfig: Dockerfile + k8s + Helm + Terraform + CloudFormation (covers hadolint's GPL-rejected slot) | **GO** |
| **kube-linter** (Red Hat / StackRox) | **Apache-2.0** (verified upstream by me — §2.3) | Maintained; vendor-backed (Red Hat/StackRox); latest **v0.8.3** (2026-03-10); ~**quarterly** cadence (slower) | **PASS** — fully local; sigstore-bundle releases (§5) | **Sigstore bundle** (`.sigstore.json` per asset); official Action `stackrox/kube-linter-action` (§5) | k8s **second-source** only (overlaps Checkov k8s) — not a sole capability | **EXTEND (optional)** |
| **gitleaks** (independent) | **MIT** (xn0 §3b, License API `gitleaks/gitleaks`) | latest **v8.30.1** (2026-03-21); prior v8.30.0 was 2025-11-26 → **feature-complete, security-patch-only cadence**; **single-maintainer / bus-factor risk** (xn0 R2) | **PASS** — fully local; no telemetry (xn0 §5) | **checksum-only** (`checksums.txt`, **no signature**) — see §5; official Action `gitleaks/gitleaks-action` | secrets (already the lead) | **GO + bus-factor caveat** |
| **OSV-Scanner** (Google) | **Apache-2.0** (xn0 §3b, License API `google/osv-scanner`) | Active; vendor-backed (Google); latest **v2.3.8** | **PASS** — local scan; queries OSV.dev DB → fetch/analyze split for full offline (xn0 §5) | **SLSA provenance** (`multiple.intoto.jsonl`) + `SHA256SUMS`; official Action `google/osv-scanner-action` (composite) | SCA cross-language dependency-vuln (cross-check vs native gates) | **GO** |

**Per-tool verdicts:** Grype **GO** · Syft **GO** · Checkov **GO** · kube-linter **EXTEND (optional
k8s second-source)** · gitleaks **GO + bus-factor caveat** · OSV-Scanner **GO**.

### 2.1 The VALIDATION DIGEST (ticket body, verified 2026-06-09) — confirmed + one drift note

The ticket's VALIDATION DIGEST is **CONFIRMED** against current upstream (2026-06-10), with two
expected version drifts from the daily/frequent release cadences (not contradictions):

- **Grype** digest said v0.110.0 → upstream latest is now **v0.114.0** (Anchore releases frequently;
  cosign-signed CONFIRMED via the `checksums.txt.{pem,sig}` assets). Verdict unchanged (GO).
- **Checkov** digest said 3.2.533 → upstream latest is now **3.2.534** (2026-06-09 — one patch newer;
  the ~daily cadence is exactly why). Offline-without-`--bc-api-key` Egress-gate PASS unchanged (GO).
- Syft v1.45.1, kube-linter v0.8.3, gitleaks v8.30.1, OSV-Scanner v2.3.8 — **all match the digest.**
- **KICS REJECT** (TeamPCP) and **trufflehog = AGPL License-gate fail** — both confirmed (KICS in the
  same campaign per `20260609_trivy_teampcp_supply_chain.md:44`; trufflehog AGPL-3.0 per xn0 §3a).

### 2.2 Rigorous honesty — the two load-bearing caveats (user-stated)

- **gitleaks bus-factor (xn0 R2, confirmed by cadence here).** gitleaks is single-maintainer and
  declared **feature-complete** (security patches only — the v8.30.0→v8.30.1 gap of ~4 months confirms
  it); the author signaled a move to **"Betterleaks"**. It remains **admissible** (MIT, patched, mature
  domain — secrets regex/entropy is stable) and is **GO** today, but the **staleness arm tracks
  Betterleaks via `sec-kb-refresh`** (the staleness/monitor surface; the ticket cites this as
  wh-hxt.1). Any successor faces the same admissibility (ADR-025) + admission (ADR-024) gates.
  **trufflehog is NOT the fallback** — it is AGPL-3.0 (License-gate fail, xn0 §3a), and
  `--results=verified` makes live HTTP calls (Egress-gate fail). detect-secrets (Apache-2.0, xn0 §3b)
  is the admissible second secrets tool if a second source is wanted.
- **Checkov Prisma / `--bc-api-key` posture.** Checkov does NOT upload source by default; the
  Prisma-Cloud enrichment is **opt-in** via `--bc-api-key`. The **exact offline invocation** is:
  `checkov -d . --compact --quiet` (or `-f <file>`) **WITHOUT `--bc-api-key`** and without
  `BC_API_KEY` in env — this keeps the Egress-gate PASS (no source upload / no Prisma enrich; xn0 §5).
  Pin this in the capability invocation.

### 2.3 kube-linter — the ONE tool I verified upstream myself (not in the xn0 matrix)

- **License:** **Apache-2.0** — GitHub License API `GET /repos/stackrox/kube-linter/license` →
  `{"spdx_id":"Apache-2.0","name":"Apache License 2.0","path":"LICENSE"}` (verified 2026-06-10).
  Source: https://github.com/stackrox/kube-linter/blob/main/LICENSE. → **License-gate PASS.**
- **Latest release:** **v0.8.3**, published **2026-03-10**. Source:
  https://github.com/stackrox/kube-linter/releases/tag/v0.8.3 (GitHub Releases API
  `repos/stackrox/kube-linter/releases`).
- **Cadence / maintainer health:** ~**quarterly** (recent: v0.8.3 2026-03-10, v0.8.1 2025-12-19,
  v0.8.0 2025-12-17, v0.7.6 2025-09-12, v0.7.5 2025-08-04, v0.7.4 2025-06-18). Slower than Checkov but
  **actively maintained and vendor-backed** (Red Hat / StackRox). Not abandoned.
- **Data-egress:** fully local; releases ship **Sigstore bundles** (`kube-linter-*.sigstore.json` per
  asset — confirmed in the v0.8.3 release assets). → **Egress-gate PASS.**
- **Verdict: EXTEND (optional).** It is a **k8s second-source** that overlaps Checkov's k8s coverage —
  valuable for blast-radius reduction (a second vendor for the highest-value IaC target) but NOT a sole
  capability. Admit it as an optional EXTEND, not a required default.

## 3. RQ3 — gaps + the diversity thesis (subordinated to ADR-024)

### 3.1 The multi-vendor diversity thesis — VALIDATED, with the bus-factor caveat, UNDER containment

The thesis ("a diversified multi-vendor set is more resilient than one do-everything tool") is
**VALID as blast-radius reduction** — but it is **NOT the security control**. ADR-024 §1/§8
(`docs/ARD.md:300,308`) is explicit and this report does not re-elevate diversity above it:

- **What diversity buys:** no single maintainer/vendor compromise takes out the whole pipeline. With
  Trivy, one compromised vendor (Aqua) removed SCA + IaC + secrets + SBOM at once. Splitting across
  Anchore (Grype/Syft), Palo Alto (Checkov), Google (OSV-Scanner), independent (gitleaks), Red Hat
  (kube-linter) means a compromise of any ONE degrades at most one capability — the others (and the
  ADR-003 floor) keep working.
- **The bus-factor caveat (the honest cost):** more vendors = **more supply-chain surfaces**. Six tools
  = six artifact-provenance attack surfaces instead of one. Diversity therefore **raises** the count of
  things that must pass the **same admissibility (ADR-025) + admission (ADR-024) pin+verify gate**. It is
  not free. (This is the exact tension ADR-024 §1 names: "DIVERSIFY … also raises the count of
  supply-chain surfaces.")
- **Why it is still subordinate, not the answer:** Mini Shai-Hulud (ADR-024 context, `:298`) compromised
  victims that had **valid SLSA L3 provenance** — selection-by-trust was defeated. The control that
  stopped it was an **egress allowlist** (CONTAIN), and tool *diversity* is cited as the fix in **zero**
  2026 postmortems. So the security argument for this set is: **every tool runs in CONTAIN (offline +
  no-creds + sandboxed + provenance-verified), so a compromise of any of them is inert** — diversity
  then *additionally* reduces blast radius. Containment first; diversity as defense-in-depth under it.

### 3.2 Gaps + adjacent coverage (no silent gap)

- **GH-Actions hardening:** **actionlint** (MIT) + **zizmor** (MIT) — already registry-listed (xn0 §3b;
  `tool-registry.md:38`). **KEEP.** Trivy never did Actions-workflow security lint, so this is not a
  Trivy gap — it is existing complementary coverage.
- **Dockerfile:** **hadolint is GPL-3.0** (License-gate REJECT, xn0 §3a) → **Checkov covers Dockerfile
  misconfig** in its place (xn0 §4 IaC row explicitly: "Checkov covers Dockerfile misconfig in
  hadolint's place"). No gap.
- **Terraform / CloudFormation:** **Checkov** (its core strength). No gap.
- **k8s second-source:** **kube-linter** (optional EXTEND, §2.3) — overlaps Checkov; blast-radius
  reduction for the highest-value IaC target.
- **EXCLUSIONS (flag loud):**
  - **Checkmarx KICS — EXPLICITLY EXCLUDED.** Same TeamPCP campaign
    (`20260609_trivy_teampcp_supply_chain.md:44`: "the same actor also hit Checkmarx KICS"). Adding KICS
    would re-introduce a compromised-vendor surface — it is not a candidate, full stop.
  - **trufflehog — License-gate fail, NOT a swap.** AGPL-3.0 (xn0 §3a). It is removed by the ADR-025
    re-audit, independent of this spike; do not treat it as a secrets alternative.

→ **Final set:** **Grype (+Syft) · Checkov · OSV-Scanner · gitleaks** (required), with **kube-linter**
(k8s second-source) + **actionlint/zizmor** (GH-Actions) as EXTEND/keep. KICS excluded; trufflehog
license-failed.

## 4. RQ4 — CLI-first / no-MCP for every replacement

Each replacement plugs behind its capability port as a **pinned, checksum/signature-verified binary
(or pip package) invoked as a CLI** — **NO MCP wrapper for any of them** (ADR-002 CLI-first/MCP-optional
`docs/ARD.md:28`; ADR-015 capability layer `:149`; ADR-006 pin+verify `:66`).

- **The trivy-mcp trap is the argument.** The `trivy-mcp` wrapper was a 3rd-party MCP server that was
  **unmaintained and pinned a stale Trivy binary** — exactly the indirection that (a) hid which binary
  ran and (b) decoupled the version from our pin. A 3rd-party MCP layer over any of these tools would
  recreate that trap: an extra, separately-maintained supply-chain hop that obscures the pinned
  artifact. We invoke the tool's own CLI directly behind the capability interface, so the artifact we
  pin+verify (RQ5) IS the artifact that runs.
- **Capability-not-brand (ADR-015):** none of these is hard-depended-on. Each sits behind a capability
  (SCA / IaC / secrets / SBOM), is detected at runtime (`detect_tools.py`), and **degrades to the
  Read/Grep/Glob floor** (ADR-003) when absent — `tool_assisted:false`, confidence capped,
  `tools_unavailable` listed. No replacement is a new coupling.

## 5. RQ5 — per-tool CI pinning spec (Action SHA + release-artifact verification)

Wired through **ADR-024 §5's artifact-provenance admission arm** (`docs/ARD.md:304`): pin to an
**immutable ref** (full commit-SHA for Actions; version + checksum/signature for binaries) and
**VERIFY checksum/cosign/SLSA at admission** — **NOT a second mechanism.** The `trivy-action` 76/77
**tag force-push** is the precedent that **only a full commit-SHA is immutable** (a version tag is a
mutable ref). All SHAs resolved 2026-06-10 via the GitHub Git-refs API (tag→commit, annotated tags
dereferenced to the underlying commit); release-artifact facts from the GitHub Releases API.

### 5.1 Official GitHub Actions — tag → full commit-SHA (pin to the SHA, comment the tag)

| Tool | Official Action | Current release tag | **Full commit-SHA to pin** | Source |
| --- | --- | --- | --- | --- |
| **Grype** | `anchore/scan-action` | **v7.4.0** | `e1165082ffb1fe366ebaf02d8526e7c4989ea9d2` | https://github.com/anchore/scan-action/releases/tag/v7.4.0 |
| **Syft** | `anchore/sbom-action` | **v0.24.0** | `e22c389904149dbc22b58101806040fa8d37a610` | https://github.com/anchore/sbom-action/releases/tag/v0.24.0 |
| **gitleaks** | `gitleaks/gitleaks-action` | **v3.0.0** | `e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e` | https://github.com/gitleaks/gitleaks-action/releases/tag/v3.0.0 |
| **OSV-Scanner** | `google/osv-scanner-action` | **v2.3.8** | `9a498708959aeaef5ef730655706c5a1df1edbc2` | https://github.com/google/osv-scanner-action/releases/tag/v2.3.8 |
| **Checkov** | `bridgecrewio/checkov-action` | **v12.3106.0** | `a6a5c23963b9d127020ae43a959cd5d8eefc94c7` | https://github.com/bridgecrewio/checkov-action/releases/tag/v12.3106.0 |
| **kube-linter** | `stackrox/kube-linter-action` | **v1.0.7** | `87802a2f4e01abebb3ee3c67a3002fea71f6eae5` | https://github.com/stackrox/kube-linter-action/releases/tag/v1.0.7 |

Pin form (every Action): `uses: anchore/scan-action@e1165082ffb1fe366ebaf02d8526e7c4989ea9d2 # v7.4.0`.

**Verification / sourcing notes that bind the impl (flag loud — these are NOT cosmetic):**
- **gitleaks-action: the digest's/body's "v2.3.9" is STALE.** The actual current release is **v3.0.0**
  (published 2026-05-30); `gitleaks/gitleaks-action/releases/latest` → `v3.0.0`. Pin v3.0.0's SHA above,
  not a v2.x SHA.
- **checkov-action latest tag needs care.** `releases/latest` returns a **mis-sorted stale `v12.1347.0`
  (2022)** because of the unusual `v12.XXXX.0` scheme; the true newest full-semver tag is **v12.3106.0**,
  and the moving `v12` major tag resolves to the **same commit** (`a6a5c23…`) — confirming v12.3106.0 is
  the current head of v12. Pin the full-SHA, never `@v12` (mutable).
- All six current tags resolved as **lightweight** except **kube-linter v0.8.3** (the *tool* repo) which
  is **annotated** — for the tool, deref to commit `10ae003038c81855aca8489df5e35da150f4dc2e`; the
  *Action* `kube-linter-action@v1.0.7` is lightweight (`87802a2…`).

### 5.2 Release-artifact verification (the binary/image path — ADR-024 §5 "verify at admission")

The agent runs the **CLI binary** (ADR-002), so the **binary path is load-bearing** (`--skip-db-update`
stops a poisoned DB but NOT a poisoned local binary — `20260609_trivy_teampcp_supply_chain.md:24,51`).
Per-tool verification primitive available **at the source**:

| Tool | Distribution | Verification artifact present (from release assets) | Verify-at-install primitive |
| --- | --- | --- | --- |
| **Grype** v0.114.0 | GitHub binary (GoReleaser) | `grype_*_checksums.txt` **+ `.txt.pem` + `.txt.sig`** | **cosign keyless** — `cosign verify-blob --certificate <.pem> --signature <.sig> --certificate-identity-regexp 'https://github.com/anchore/grype' --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt`, then sha256 the binary against the verified `checksums.txt` |
| **Syft** v1.45.1 | GitHub binary (GoReleaser) | `syft_*_checksums.txt` **+ `.txt.pem` + `.txt.sig`** | **cosign keyless** (same pattern, identity `anchore/syft`) |
| **OSV-Scanner** v2.3.8 | GitHub binary | `osv-scanner_SHA256SUMS` **+ `multiple.intoto.jsonl`** | **SLSA provenance** — verify with `slsa-verifier verify-artifact <bin> --provenance-path multiple.intoto.jsonl --source-uri github.com/google/osv-scanner`, plus the SHA256SUMS check |
| **kube-linter** v0.8.3 | GitHub binary | per-asset **`*.sigstore.json`** (Sigstore bundle) | **cosign bundle** — `cosign verify-blob --bundle kube-linter-linux.sigstore.json --certificate-identity-regexp 'stackrox/kube-linter' --certificate-oidc-issuer https://token.actions.githubusercontent.com kube-linter-linux` |
| **gitleaks** v8.30.1 | GitHub binary | **`gitleaks_*_checksums.txt` ONLY — no `.sig`/`.pem`** | **checksum-only, pinned in OUR repo** — sha256 the binary against `checksums.txt`, BUT pin the **expected checksum VALUE in our own registry row / a committed pin file** (reviewed once at admission via human PR). **NO signature available**, so the upstream `checksums.txt` shares the release's trust root: under a publisher/release compromise (the TeamPCP vector — aqua-bot re-published the binary AND its metadata) an attacker substitutes BOTH and an in-release checksum check still passes. Pinning the value in our git history makes the trust root **our reviewed commit**, independent of any future release compromise. This is WHERE ADR-024 §5's admission checksum lives for gitleaks (not a second mechanism). Record the no-signature gap in the registry `data_egress`/notes; it is the weakest verification of the set and reinforces the bus-factor caveat |
| **Checkov** 3.2.534 | **PyPI `checkov` + container image** | PyPI release (pip hash-pinning); image by digest | **pip hash-pin** — `pip install checkov==3.2.534 --require-hashes` (or a digest-pinned `ghcr.io/bridgecrewio/checkov@sha256:…`); see §5.3 caveat |

### 5.3 Critical RQ5 caveats (flag loud)

- **The checkov-action is a DOCKER action that pins a MUTABLE image tag.** Its `action.yml` is
  `using: 'docker'`, `image: 'docker://ghcr.io/bridgecrewio/checkov:3.3.0'` — so even pinning the
  *Action* to the full commit-SHA (`a6a5c23…`) does **NOT** pin the scanner binary: the `:3.3.0` image
  tag is mutable (the exact trivy-action trap class — a SHA-pinned wrapper over a tag-pinned payload).
  **Recommendation: prefer the binary path** (`pip install checkov==<ver> --require-hashes`, or a
  **digest-pinned** image `ghcr.io/bridgecrewio/checkov@sha256:…`) over the Docker Action for Checkov.
- **gitleaks has no signed releases — checksum-only, so pin the checksum VALUE in our repo.** Weakest
  verification primitive of the set; pair with the bus-factor caveat (§2.2). Be precise about what the
  in-release `checksums.txt` does and does NOT defeat: sha256-against-`checksums.txt` defeats **in-transit
  substitution** (a tampered download), but it does **NOT** defeat **release substitution** — because the
  checksum file ships from the SAME release as the binary, a publisher/release compromise (the exact
  TeamPCP vector: aqua-bot re-published the binary AND its metadata) substitutes both and the check still
  passes. **Compensating control:** pin the expected gitleaks checksum **value in our own registry row / a
  committed pin file**, reviewed once at admission via human PR, so the trust root is **our git history**
  (not the upstream release) and is independent of any future release compromise. This is the admission
  checksum of ADR-024 §5 for gitleaks — *where its trust root lives*, not a second mechanism. Record the
  absence of an upstream signature in the registry notes.
- **No tool in this set LACKS an official Action** — all six have one (a positive: the binary-only
  fallback is never the *only* path). The composite `osv-scanner-action` and the Anchore actions ship no
  binary assets of their own (they wrap the tool), so the binary-path verification in §5.2 is the
  load-bearing one regardless of Action vs CLI.
- **DB-backed tools use the fetch/analyze split (ADR-024 §2), not ambient egress.** Grype
  (`GRYPE_DB_AUTO_UPDATE=false` + pre-seeded DB) and OSV-Scanner (local DB) FETCH network-on, then
  ANALYZE network-off — they never run with ambient egress to "satisfy" a scan (xn0 §5; ADR-024 §2).

## 6. RQ6 — the impl spec (DRAFT ticket section for /design-ticket post-wave)

> **This EXTENDS wh-xn0 §11's shared registry-rewrite draft** (`20260609_tool_admissibility_license_gdpr.md:283`)
> into ONE coordinated change — it does NOT redo it. The combined ticket = ADR-025's columns +
> wh-nvk's replacement rows + the lock-regex fix + the SCANNER_PREFERENCE edits. **Never two
> uncoordinated writers** to `tool-registry.md` + `detect_tools.py` (xn0 R3).

- **Title:** Registry rewrite — admissibility columns + Trivy-replacement rows + SCANNER_PREFERENCE sync
  (wh-xn0 ∪ wh-nvk)
- **Goal:** Make `tool-registry.md` + `detect_tools.py:SCANNER_PREFERENCE` reflect the ADR-025 admissible
  set AND the permanent Trivy removal: add `license`/`data_egress`/`gdpr` columns (xn0), install the
  Grype/Syft/Checkov/OSV-Scanner/gitleaks (+ kube-linter optional) rows with per-tool pin+verify notes
  (this spike), drop every License-gate violator AND Trivy, retire the `r"0\.7[01]"` lock assertion, keep
  the doc↔code lock green.
- **Files (the SAME two-plus files xn0 §11 names — one writer):**
  - `plugins/white-hacker/skills/_shared/reference/tool-registry.md` — add the three columns; **delete
    the Trivy pin/COMPROMISED block (`:50-57`)** and the SCA/IaC example lines naming Trivy (`:30`,
    `:38`); add replacement rows (each with `license`/`data_egress`/`gdpr` + the §5.2 verify primitive +
    the §5.1 Action SHA); move License-gate violators (Opengrep/Semgrep/CodeQL/govulncheck/trufflehog/
    hadolint/find-sec-bugs) to the "Rejected (License-gate)" subsection (xn0); a changelog entry
    "`- 2026-06-10 · - · sca+iac · trivy · permanent removal (wh-nvk) — TeamPCP; replaced by
    Grype+Syft/Checkov/OSV-Scanner`".
  - `plugins/white-hacker/skills/sec-detect/scripts/detect_tools.py` — `SCANNER_PREFERENCE`: **`sca` →
    drop `("trivy","*")`** (`:114`); **`iac` → drop `("trivy","*")`** (`:116`, keep checkov-first + drop
    hadolint per xn0); plus the xn0 SAST/secrets edits (SAST → per-language linters, drop opengrep/semgrep;
    secrets → drop trufflehog). (Grype/Syft are image/SBOM tools the static-default filesystem review
    doesn't auto-select via `SCANNER_PREFERENCE` — they live in the registry; do not add an image-pull
    default, ADR-007.)
  - `plugins/white-hacker/skills/_shared/scripts/tests/test_registry_lock.py:51` — **remove/replace the
    `re.search(r"0\.7[01]", text)` assertion** (it asserts the safe-Trivy line; retiring the pin line
    trips the lock RED). Replace with a neutral pinning-discipline assertion if one is wanted (e.g. assert
    a generic "pin" string already covered by `test_registry_states_illustrative_and_pinning`'s
    `assert "pin" in text`) — but the Trivy-specific regex MUST go.
- **ACs:**
  1. `SCANNER_PREFERENCE` contains **ZERO `trivy`** entries (sca + iac); zero License-gate violators
     (xn0); admitted tools present (Policy 9: pin both present-and-absent in the per-tool TDD).
  2. Every admitted registry row carries `license ∈ {MIT, Apache-2.0}` + `data_egress` + `gdpr`; every
     rejected tool (incl. Trivy as "Rejected (integrity/TeamPCP)", distinct from the License-gate
     subsection) has a reason; per-tool rows carry the §5.1 Action SHA + §5.2 verify primitive.
  3. `test_registry_lock.py` GREEN (capability-level) **with the `r"0\.7[01]"` assertion gone**; new
     per-tool tests GREEN; `nice -n 10 uv run --with pytest pytest .../tests -q` passes.
  4. ADR cross-refs reflected: the registry header cites ADR-025 (admissibility) + ADR-024 (admission)
     + this ADR (Trivy removal + diversified set).
  5. **gitleaks checksum trust root pinned in OUR repo (SEC-Q10).** Because gitleaks ships no signature,
     the impl pins the **expected gitleaks binary checksum VALUE** in our own registry row / a committed
     pin file (reviewed once at admission via human PR) — NOT merely "sha256 against the upstream
     `checksums.txt`" (which shares the release's trust root and so does not defeat a publisher/release
     compromise — the TeamPCP vector). Verification at install compares the downloaded binary against the
     in-repo pinned value, so the trust root is our git history. (This IS the ADR-024 §5 admission
     checksum for gitleaks — its trust-root location, not a second mechanism.)
  6. **Wrapper-shape check before pinning each Action (SEC-Q9).** Before pinning, the impl asserts for
     EACH of the other five official Actions — `anchore/scan-action`, `anchore/sbom-action`,
     `gitleaks/gitleaks-action`, `google/osv-scanner-action`, `stackrox/kube-linter-action` — that its
     `action.yml` is `using: composite` or `using: node20` and is **NOT** `using: docker` over a mutable
     `image:` tag. (The checkov-action case proves this shape exists in this very set, §5.3; only
     checkov-action was inspected this wave, so the other five are asserted-but-unchecked wrappers — the
     impl performs the check. Any Action found to be a docker-over-mutable-image wrapper gets the same
     binary/digest-pinned-path recommendation as Checkov.)
  7. **GATING AC (lens-5, carried from the wave-1b-completion condition — BINDS):** the **SAST default
     does NOT flip live** until `evals/score.py` runs the Opengrep-on baseline vs linters+floor
     before/after measurement **GREEN on a RE-BASELINED corpus that INCLUDES JAVA cases**. The stale
     **32-vs-103 baseline must be re-baselined first** (drift-guard `baseline.n_cases == len(corpus)`).
     Rationale: after find-sec-bugs (LGPL-3.0) drops, **Java taint is floor-only** (no per-language Java
     linter backstop — xn0 §4a), so the measurement is **blind where the loss is worst** unless Java
     cases are in the corpus. (This gates the SAST arm of the SHARED rewrite; the Trivy/SCA/IaC row
     changes are not blocked by it.)
- **Depends-on / coordination:**
  - The per-tool **pin+verify** (§5) plugs into **ADR-024 §5's artifact-provenance admission arm** — do
    NOT invent a second mechanism.
  - **Watchlist-entry effects** (the shared Trivy known-compromised watchlist entry — wh-k6l's
    instantiation) are validated by **the Gate-2 validator (wh-562, this wave)** — a DATA gate, a
    different object kind from this tool/registry change. If the impl must cross-reference wh-562's
    sibling ADR: it was assigned **ADR-026** at append (2026-06-10).
  - The RQ5 admissibility *screen* (the pure-function `admit_tool`) is **wh-hxt.4**, separate.
  - The eval re-baseline (32→103, Java-inclusive) precedes the SAST measurement.

## 7. Risk & open questions

- **R1 — SAST recall regression (gated, not this spike).** Carried from xn0 R1 / lens-5: the SAST-default
  flip is gated on the Java-inclusive eval measurement. **Open for triage:** the eval re-baseline + the
  before/after run (a `docs/qa/<YYYYMMDD>/` cycle on the subscription) — not run in this wave.
- **R2 — gitleaks bus-factor + no signature.** Single-maintainer, feature-complete, **checksum-only**
  (no cosign). Admissible today; **track Betterleaks via the staleness arm** (`sec-kb-refresh`); record
  the missing-signature gap in the registry notes. **Open:** when Betterleaks matures, re-run it through
  ADR-025 admissibility + ADR-024 admission.
- **R3 — checkov-action Docker tag-pin.** The official Action pins a mutable image tag (`:3.3.0`);
  prefer the binary path (`pip install checkov==<ver> --require-hashes`) or a digest-pinned image. **Open:**
  the impl picks the Checkov invocation form (recommend binary/pip path).
- **R4 — version drift at pin time.** Grype (v0.114.0) and Checkov (3.2.534) move fast; the §5 SHAs/versions
  are 2026-06-10 snapshots — **re-resolve the SHA + re-verify the signature at the actual pin commit**
  (ADR-006 pin-and-verify). The *method* is stable; the specific SHA is a point-in-time value.
- **R5 — registry double-writer.** The rewrite is shared with wh-xn0 — **ONE coordinated impl ticket**
  (xn0 R3). Surfaced, not averaged: this is a hard sequencing constraint, not a preference.

## 8. Conflicts found with reference docs (surface, don't average — Policy 7)

1. **Ticket body "iac lead `(trivy,*)`" is STALE.** Current `detect_tools.py:116` is checkov-first
   (`[("checkov","*"),("trivy","*"),("hadolint","docker")]`) — wh-d5b already demoted Trivy. The GROOM
   2026-06-10 correction is authoritative; this report cites the CURRENT code. (Source wins: the live
   repo state over the ticket prose.)
2. **Ticket body / VALIDATION DIGEST "last written ADR-023" is STALE.** `docs/ARD.md` now has **ADR-024
   and ADR-025 written** (`:296`, `:313`); the next ADR number is assigned at append time (TL-serialized
   after wh-562's). The GROOM correction (point 4) is authoritative.
3. **gitleaks-ACTION "v2.3.9" (implied by the digest's v8.30.1 era) is STALE.** The current
   gitleaks-action release is **v3.0.0** (2026-05-30) — a major bump. RQ5 pins v3.0.0's SHA. (The *tool*
   gitleaks v8.30.1 is correct; the *Action* is on its own v3 line.)
4. **Grype/Checkov version drift from the digest** (v0.110.0→v0.114.0; 3.2.533→3.2.534) — expected from
   the frequent/daily cadences, NOT contradictions; verdicts unchanged. Recorded in §2.1.
5. **NOT a conflict, an alignment note:** this report deliberately **agrees with ADR-024's demotion of
   DIVERSIFY** (§Subordination + §3.1). The user's "diversity is a security upgrade" framing in the
   ticket body is re-scoped to "blast-radius reduction under CONTAIN-primary" — surfaced explicitly so it
   is not silently averaged.

## 9. Evidence artifacts

No PoC code (this spike produces a replacement spec + the ADR text + a SHARED-ticket impl draft, not
runnable code). All facts are cited inline: license/egress verdicts to **wh-xn0's upstream-verified
matrix** (§3b/§5, raw-LICENSE / GitHub-License-API URLs, verified 2026-06-10); kube-linter's license +
release facts verified upstream by me (GitHub License API + Releases API, 2026-06-10, URLs in §2.3); the
compromise facts to `20260609_trivy_teampcp_supply_chain.md` (RQ1/RQ2 FINAL); the Action-SHAs + release
artifacts to the GitHub Git-refs / Releases API (URLs in §5, resolved 2026-06-10); code/registry anchors
to the live repo (`detect_tools.py:110-119`, `tool-registry.md:30,38,50-57`, `test_registry_lock.py:51`).

## 10. References

**Reference docs (cite, don't re-derive):**
- `docs/research/20260609_trivy_teampcp_supply_chain.md` — TeamPCP compromise (RQ1 verification + RQ2
  exposure FINAL); the offline≠binary-verify scorecard.
- `docs/research/20260609_tool_admissibility_license_gdpr.md` — wh-xn0 admissibility matrix (§3b license,
  §5 egress — every SPDX upstream-cited); §6 eval-measurement plan; §11 the SHARED registry-rewrite draft
  this RQ6 extends.
- `docs/research/20260609_supply_chain_tooling_strategy.md` + `docs/research/20260610_contain_primary_control.md`
  — CONTAIN-primary framing; DIVERSIFY = blast-radius reduction.

**ADRs (`docs/ARD.md`):** ADR-002 (`:28`, CLI-first/MCP-optional) · ADR-003 (`:39`, degrade-to-floor) ·
ADR-006 (`:66`, pin+verify) · ADR-015 (`:149`, capability-not-brand) · **ADR-024** (`:296-311`, CONTAIN
primary; §5 the artifact-provenance admission arm this RQ5 plugs into; the three-gates-three-objects
rule) · **ADR-025** (`:313-326`, admissibility = License-gate + Egress-gate; the re-audited admissible
set; the SAST supersession with the measured-not-asserted rule; the registry-schema columns this RQ6
consumes).

**Upstream sources verified 2026-06-10 (the web access granted to this spike):** kube-linter license =
GitHub License API `repos/stackrox/kube-linter/license` → `Apache-2.0`
(https://github.com/stackrox/kube-linter/blob/main/LICENSE); kube-linter releases =
`repos/stackrox/kube-linter/releases` (v0.8.3, 2026-03-10); the six Action tag→commit-SHA mappings +
release-artifact (cosign/SLSA/sigstore/checksum) facts = GitHub Git-refs / Releases API per §5
(scan-action v7.4.0, sbom-action v0.24.0, gitleaks-action v3.0.0, osv-scanner-action v2.3.8,
checkov-action v12.3106.0, kube-linter-action v1.0.7).

---

## ADR text — TL appends serially

> **Appended 2026-06-10 as ADR-027** (TL-serialized, after wh-562's ADR-026). Mirrors the ADR-024/025
> house format; the ARD copy is identical except internal blank lines tightened to the house block
> shape and the sibling token resolved to ADR-026.

## ADR-027 — Trivy permanently removed; a diversified multi-vendor SCA/IaC set (Grype+Syft · Checkov · OSV-Scanner · gitleaks; kube-linter optional) behind the capability layer, each pinned+verified

**Status:** accepted — resolves spike wh-nvk (`docs/research/20260609_trivy_replacement_sca_iac.md`); the
DIVERSIFY-arm ADR for epic wh-hxt. License/egress verdicts cited from ADR-025 (every SPDX upstream-verified
2026-06-10); kube-linter verified upstream by this spike; Action-SHAs + release-artifact facts resolved
2026-06-10. The registry rewrite is the SHARED wh-xn0∪wh-nvk impl ticket (one coordinated writer);
per-tool pin+verify plugs into ADR-024 §5.

**Context:** Trivy (aquasecurity) was a do-everything tool covering SCA · IaC/misconfig
(Dockerfile/k8s/Helm/Terraform/CloudFormation) · container-image CVE · secrets · SBOM behind several
white-hacker capabilities. It was **TeamPCP-compromised** (CVE-2026-33634 / GHSA-69fq-xp46-6x23: the
`trivy-action`/`setup-trivy` tags were force-pushed, malicious binary v0.69.4 + images v0.69.5–.6
published — verification + our LOW–MEDIUM partial exposure are FINAL in
`docs/research/20260609_trivy_teampcp_supply_chain.md`), and the `trivy-mcp` wrapper was unmaintained +
pinned a stale binary (the "MCP trap"). The user DECIDED to drop Trivy; wh-d5b quarantined it as the
interim stopgap (demoted below Checkov for IaC, `detect_tools.py:116`; "permanent removal wh-nvk" caveat
in `tool-registry.md:54-57`). **Trivy stays OUT regardless of its Apache-2.0 license** (ADR-025 §2:
license-clean ≠ admissible — admissibility composes with admission/integrity).

**Decision:**
1. **Permanently remove Trivy** from `SCANNER_PREFERENCE` (`detect_tools.py:114` sca; `:116` iac) and the
   `tool-registry.md` SCA/IaC lines + the safe-version pin block (`:50-57`); record it in the
   "Rejected (integrity/TeamPCP)" subsection — a category DISTINCT from ADR-025's License-gate rejections
   (Trivy is license-clean but integrity-compromised). **It does not return.**
2. **Adopt the diversified split behind the capability layer (ADR-015), each a CLI (no MCP, ADR-002):**
   **SCA** → OSV-Scanner (cross-language) + Grype (image/dir) + native gates per-language; **container
   image + SBOM** → Grype + Syft; **IaC/misconfig** → Checkov (incl. Dockerfile, filling hadolint's
   GPL-rejected slot); **secrets** → gitleaks; **k8s second-source** → kube-linter (optional EXTEND);
   **GH-Actions** → actionlint/zizmor (kept). KICS is **excluded** (same TeamPCP campaign); trufflehog is
   removed by ADR-025 (AGPL License-gate fail) — not a swap.
3. **DIVERSIFY is blast-radius reduction, NOT the security control (subordinate to ADR-024 §1).** Security
   comes from CONTAIN (every tool offline + no-creds + sandboxed + provenance-verified), so a compromise
   of any tool — Trivy, its replacement, or one not yet picked — is inert. Multi-vendor split additionally
   limits blast radius (no single-vendor compromise removes the whole pipeline) at the **cost of more
   supply-chain surfaces** — every replacement therefore passes the SAME ADR-025 admissibility +
   ADR-024 admission gates. Diversity is defense-in-depth under containment; it is never re-elevated to
   "the answer."
4. **Per-tool pin+verify is ADR-024 §5's admission arm — not a new mechanism.** Pin every official Action
   to a **full commit-SHA** (a version tag is a mutable ref — the `trivy-action` 76/77 force-push proves
   only a SHA is immutable) and **verify the binary at admission**: Grype/Syft = cosign keyless
   (`checksums.txt`+`.pem`+`.sig`); OSV-Scanner = SLSA provenance (`multiple.intoto.jsonl`) + SHA256SUMS;
   kube-linter = Sigstore bundle (`.sigstore.json`); **gitleaks = checksum-only with NO upstream signature,
   so the expected checksum VALUE is pinned in OUR registry row / a committed pin file (reviewed once at
   admission via human PR) — the upstream `checksums.txt` ships from the same release as the binary and so
   does not defeat a publisher/release compromise (the TeamPCP vector: re-published binary + metadata);
   pinning the value in our git history makes the trust root our reviewed commit (the recorded gap is the
   missing upstream signature, the compensating control is the in-repo pin)**; Checkov = pip hash-pin
   (`pip install checkov==<ver> --require-hashes`) or a **digest**-pinned image — its Docker Action pins a
   *mutable* `:3.3.0` image tag, so the binary/pip path is preferred. The resolved SHAs are point-in-time
   (2026-06-10) — re-resolve + re-verify at the actual pin commit (ADR-006).
5. **The registry rewrite is ONE coordinated change shared with wh-xn0** (admissibility columns + these
   replacement rows + the `test_registry_lock.py:51` `r"0\.7[01]"` lock-regex retirement + the
   SCANNER_PREFERENCE edits) — never two uncoordinated writers to `tool-registry.md` + `detect_tools.py`.
6. **GATING (lens-5):** the impl must NOT flip the SAST default live until `evals/score.py` measures the
   downgrade (ADR-025 §4) GREEN on a **re-baselined, Java-inclusive** corpus (the stale 32-vs-103 baseline
   re-baselined first) — because Java taint is floor-only after find-sec-bugs (LGPL) drops, the measurement
   is blind where the loss is worst without Java cases. This gates the SAST arm of the shared rewrite; the
   Trivy/SCA/IaC row changes are not blocked by it.

**Rationale:** Removing a compromised tool is necessary but not sufficient (ADR-024: selection-by-trust was
defeated by Mini Shai-Hulud's valid SLSA provenance); the replacement set is safe **because it runs under
CONTAIN**, and diversified **so one vendor compromise degrades at most one capability** while the ADR-003
floor guarantees no capability is left empty. CLI-first (ADR-002) avoids recreating the trivy-mcp trap (a
3rd-party MCP layer obscuring the pinned artifact). Pin-to-SHA + verify-at-admission (ADR-024 §5 / ADR-006)
defeats the tag-force-push and substituted-binary vectors. The honest costs are recorded, not hidden:
gitleaks' single-maintainer/feature-complete posture + checksum-only releases (tracked via the staleness
arm), the checkov-action mutable image-tag, and the SAST precision downgrade (measured, not asserted —
Policy 9).

**Supersedes:** **nothing formally superseded in the ARD.** This ADR **RATIFIES** the `tool-registry.md`
COMPROMISED-block's "permanent removal wh-nvk" caveat (`:54-57`) and **supersedes wh-d5b's *temporary*
framing** ("Quarantined … returns when a safe pinned+verified version is cleared") — the removal is
**permanent; Trivy does not return**. **Extends** ADR-024 (uses its §5 admission arm + its CONTAIN-primary
demotion of DIVERSIFY — does not re-derive either) and **consumes** ADR-025 (cites its admissibility
verdicts + registry-schema columns + the SAST eval-measurement gate — does not restate them).

**Alternatives rejected:** (a) keep Trivy because it is Apache-2.0 — license-clean ≠ admissible; TeamPCP
integrity compromise (ADR-025 §2; wh-nvk). (b) Replace Trivy with one other do-everything tool — re-creates
the single-vendor blast radius the diversified set reduces. (c) Adopt KICS — same TeamPCP campaign
(`20260609_trivy_teampcp_supply_chain.md:44`); re-introduces a compromised-vendor surface. (d) Keep
trufflehog as the secrets tool — AGPL-3.0 License-gate fail + `--results=verified` egress (ADR-025 §2).
(e) Wrap any replacement in a 3rd-party MCP — the trivy-mcp trap (unmaintained indirection over a stale
binary); CLI-first (ADR-002). (f) Pin Actions to version tags — defeated by the `trivy-action` force-push;
only a full commit-SHA is immutable (ADR-024 §5). (g) Treat diversity as the security control — falsified
by Mini Shai-Hulud (ADR-024 §1); CONTAIN is primary, diversity is blast-radius reduction under it. (h) Use
the checkov Docker Action as-is — it pins a mutable `:3.3.0` image tag (the trivy-action trap class);
prefer the pip/digest-pinned binary path. (i) Flip the SAST default before measuring — Policy 9 /
ADR-025 §4 (the Java-inclusive eval gate must run GREEN first).

**References:** wh-nvk (this spike), `docs/research/20260609_trivy_replacement_sca_iac.md` (the scorecard +
coverage-parity matrix + the resolved Action-SHAs + per-tool verify primitives + the diversity-thesis
verdict subordinated to CONTAIN); `docs/research/20260609_trivy_teampcp_supply_chain.md` (TeamPCP
verification + exposure FINAL); `docs/research/20260609_tool_admissibility_license_gdpr.md` (ADR-025's
admissibility matrix — cited, not re-derived); `docs/research/20260610_contain_primary_control.md` +
`docs/research/20260609_supply_chain_tooling_strategy.md` (CONTAIN-primary framing). Code/registry anchors:
`plugins/white-hacker/skills/sec-detect/scripts/detect_tools.py:110-119` (SCANNER_PREFERENCE),
`plugins/white-hacker/skills/_shared/reference/tool-registry.md:30,38,50-57` (SCA/IaC + Trivy block),
`plugins/white-hacker/skills/_shared/scripts/tests/test_registry_lock.py:51` (the `r"0\.7[01]"` lock).
ADRs: ADR-002 (CLI-first/MCP-optional), ADR-003 (floor/degrade), ADR-006 (pin+verify), ADR-015
(capability-not-brand registry; self-updates), ADR-024 (CONTAIN primary; the artifact-provenance admission
arm §5; DIVERSIFY=blast-radius reduction §1), ADR-025 (admissibility two gates; the re-audited admissible
set; the SAST supersession + eval gate; the registry-schema columns); siblings wh-d5b (interim quarantine —
its temporary framing **superseded** here), wh-562 (the Gate-2 DATA gate validates the shared Trivy
watchlist entry — wh-k6l's instantiation; the sibling Gate-2 ADR is ADR-026), wh-xn0
(the SHARED registry rewrite), wh-hxt.4 (the ADMIT-via-loop screen), wh-hxt.1 (the staleness arm tracking
Betterleaks), wh-hxt.2 (the retire→replace runbook).
