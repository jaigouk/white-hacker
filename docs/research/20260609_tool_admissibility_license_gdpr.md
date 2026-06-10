# Tool-admissibility — MIT/Apache-2.0-only license gate + local/no-telemetry data-egress gate; registry re-audit

**Spike:** wh-xn0 (epic wh-hxt — supply-chain-resilient tooling) · **Date:** 2026-06-09 (license
re-verification 2026-06-10) · **Status:** RESOLVED → ADR-025
**Resolves to:** ADR-025 (the two gates as registry policy; the re-audited admissible set; the
registry column convention; explicit ADR-011 supersession; the SAST-downgrade eval-measurement plan).

> **Naming caution (carried from the ticket + launch contract).** This spike's **Egress-gate** (one of
> its two admissibility gates — the other is the **License-gate**) governs whether a *capability TOOL*
> runs locally without uploading source / sending telemetry. It is a DIFFERENT object from
> **wh-562's "Gate-2"**, which gates *watchlist/registry DATA entries* (per-entry GHSA/OSV provenance).
> **The bare token "Gate-1" is RESERVED for the eval gate (KB edits) — this spike never reuses it; its
> own gates are named "License-gate" and "Egress-gate".** Four gates, four object kinds, never merged
> (ADR-024 §5): eval **Gate-1** (KB edits) · **Gate-2** (DATA entries, wh-562) · **CONTAIN admission**
> (TOOL artifacts, ADR-024) · this spike's **License-gate + Egress-gate** (tool admissibility). This
> ADR adds the fourth screen at a different layer — **tool admissibility** (license + egress *defaults*) —
> which runs *before* a tool is even pinned. Admissibility ≠ admission: admissibility asks "is this tool
> *allowed* in the registry?" (License-gate + Egress-gate), admission (ADR-024) asks "is *this artifact* the
> one we verified?" (pin + checksum/cosign/SLSA). Keep all four names apart.

---

## 1. Goal

Define and enforce a **two-gate admissibility policy for every capability TOOL**, then re-audit the
registry against it. The two gates are deterministic (Policy 5 — code answers, not the model):

- **License-gate (license):** `license ∈ {MIT, Apache-2.0}` ONLY. Reject BSD (incl. BSD-3-Clause), LGPL
  (any version), GPL, AGPL, MPL, any copyleft, proprietary, commercial-restricted. A dual-license that
  *offers* MIT or Apache-2.0 at the user's option passes (the user elects the permissive arm).
- **Egress-gate (data-egress):** the tool runs **locally/offline** and does **NOT** upload source or send
  telemetry **by default**. A tool whose telemetry is on-by-default is admissible ONLY with the disable
  flag pinned in its invocation.

Out of scope (separate decisions on disjoint files): the agent's **own** model call + pipeline PII
redaction → **wh-81y** (Spike B, its own ADR). This ticket governs *tools*, not the agent's output.

## 2. Background / decision context (cite, don't re-debate)

- **NG1 / ADR-015** — the product is the *concept* (capability interfaces), not a fixed tool list. An
  admissibility gate is **registry governance**, not a coupling: it constrains *which* tools may sit
  behind a capability, while the capability interface itself is unchanged.
- **ADR-023 (precedent).** Resource-aware execution adopted **MIT/Apache-2.0-only bundling** and
  **rejected psutil for BSD-3** — "the bar is stricter than permissive." This spike *generalises* that
  exact rule from the *one bundled helper* to *every capability tool* (append-only; ADR-025 GENERALISES
  ADR-023's licence rule, does not supersede it).
- **ADR-024 (admission arm).** CONTAIN ratified the **artifact-provenance admission arm** (pin to an
  immutable ref + verify checksum/cosign/SLSA at admission). **This spike CITES ADR-024 for pinning
  rather than re-deriving it** — admissibility (license/egress *policy*) is this ticket's ground;
  admission (pin/verify of the *specific artifact*) is ADR-024's. They compose: a tool must pass
  admissibility to enter the registry, then pass admission each time its artifact is executed.
- **ADR-003 (floor).** Every capability degrades to the Read/Grep/Glob floor when it has no admissible
  tool — never block on a missing tool. The survey shows the floor *fallback* is NOT triggered for any
  capability (each has ≥1 admissible tool), but the policy names it as the guaranteed backstop.
- **ADR-011 (superseded by this spike).** ADR-011 names **Opengrep (LGPL-2.1)** the cross-language SAST
  default. Opengrep fails the License-gate. ADR-025 **supersedes ADR-011 explicitly** and replaces the cross-language
  taint default with **floor + per-language MIT/Apache linters** — a *precision* downgrade that must be
  **MEASURED** against `evals/score.py`, not asserted (Policy 9; plan in §6, run post-wave).
- **What's blocked.** `tool-registry.md` has no license/egress/gdpr columns and seeds License-gate violators as
  defaults: Opengrep (`:24`), govulncheck (`:29`), trufflehog (`:34`), hadolint (`:38`), and the SCANNER
  preference list (`detect_tools.py:110`) leads SAST with `opengrep`/`semgrep`. Until the gates are
  codified, the self-update loop can keep admitting non-compliant tools.

## 3. RQ1 — license verification (every claim from the UPSTREAM LICENSE/SPDX)

Each license below was fetched from the project's **own LICENSE file** (raw GitHub) or the **GitHub
License API** (`/repos/{owner}/{repo}/license` → SPDX id), 2026-06-10. **No blog was used.** Where the
License API and a raw LICENSE both exist they agreed.

### 3a. License-gate VIOLATORS (drop / replace) — all CONFIRMED from upstream

| Tool | SPDX (upstream) | Source URL (verified 2026-06-10) | Verdict |
| --- | --- | --- | --- |
| **Opengrep** | **LGPL-2.1** | raw `opengrep/opengrep@main/LICENSE` → "GNU LESSER GENERAL PUBLIC LICENSE Version 2.1" | DROP (copyleft) |
| **Semgrep CE** | **LGPL-2.1** | raw `semgrep/semgrep@develop/LICENSE` → "GNU LESSER GENERAL PUBLIC LICENSE Version 2.1" | DROP (copyleft) |
| **CodeQL CLI** | **proprietary** | `github.com/github/codeql-cli-binaries/blob/main/LICENSE.md` → "GitHub CodeQL Terms and Conditions" | DROP (proprietary; ALSO forbids private-repo/CI analysis without paid GHAS — double fail w/ egress) |
| **govulncheck** (`golang.org/x/vuln`) | **BSD-3-Clause** | raw `golang/vuln@master/LICENSE` → 3-condition BSD redistribution clause; DB data CC-BY-4.0 | DROP (BSD-3 — exactly the psutil precedent, ADR-023) |
| **trufflehog** | **AGPL-3.0** | raw `trufflesecurity/trufflehog@main/LICENSE` → "GNU AFFERO GENERAL PUBLIC LICENSE" | DROP (network-copyleft; also `--results=verified` = egress) |
| **hadolint** | **GPL-3.0** | raw `hadolint/hadolint@master/LICENSE` → "GNU GENERAL PUBLIC LICENSE Version 3" | DROP (copyleft) |
| **find-sec-bugs** | **LGPL-3.0** | GitHub License API `find-sec-bugs/find-sec-bugs` → `spdx_id: LGPL-3.0` | DROP (copyleft) — **see §3c precision note** |

### 3b. License-gate ADMITTED set (MIT / Apache-2.0) — all CONFIRMED from upstream

| Capability | Tool | SPDX (upstream) | Source URL (verified 2026-06-10) |
| --- | --- | --- | --- |
| SAST (per-lang) | **gosec** | Apache-2.0 | raw `securego/gosec@master/LICENSE.txt` → "Apache License Version 2.0" |
| SAST (per-lang) | **bandit** | Apache-2.0 | raw `PyCQA/bandit@main/LICENSE` → "Apache License Version 2.0" |
| SAST (per-lang) | **eslint-plugin-security** | Apache-2.0 | raw `eslint-community/eslint-plugin-security@main/LICENSE` → "Apache License Version 2.0" |
| SAST (per-lang) | **ruff** (`-S`/bandit rules) | MIT | raw `astral-sh/ruff@main/LICENSE` → "MIT License" |
| SCA | **OSV-Scanner** | Apache-2.0 | License API `google/osv-scanner` → `Apache-2.0` |
| SCA | **Grype** | Apache-2.0 | License API `anchore/grype` → `Apache-2.0` |
| SCA (SBOM) | **Syft** | Apache-2.0 | License API `anchore/syft` → `Apache-2.0` |
| SCA (py) | **pip-audit** | Apache-2.0 | License API `pypa/pip-audit` → `Apache-2.0` |
| SCA (rust) | **cargo-audit** | **MIT OR Apache-2.0** (dual) | `rustsec/rustsec` cargo-audit README → "Licensed under either of … at your option" |
| secrets | **gitleaks** | MIT | License API `gitleaks/gitleaks` → `MIT` |
| secrets | **detect-secrets** | Apache-2.0 | License API `Yelp/detect-secrets` → `Apache-2.0` |
| IaC/CI | **Checkov** | Apache-2.0 | License API `bridgecrewio/checkov` → `Apache-2.0` |
| IaC/CI | **actionlint** | MIT | License API `rhysd/actionlint` → `MIT` |
| IaC/CI | **zizmor** | MIT | License API `zizmorcore/zizmor` → `MIT` |
| AI-redteam | **promptfoo** | MIT | License API `promptfoo/promptfoo` → `MIT` |
| AI-redteam | **garak** | Apache-2.0 | License API `NVIDIA/garak` → `Apache-2.0` |

**Trivy is NOT admitted** regardless of its license (Apache-2.0): it was struck per **wh-nvk** after the
**TeamPCP** compromise (CVE-2026-33634 / GHSA-69fq-xp46-6x23; quarantined wh-d5b, permanently removed
wh-nvk). It does not return. (License-clean ≠ admissible — admissibility composes with admission/integrity.)

### 3c. License results vs the 2026-06-09 survey digest — DELTA (flag loud)

The survey digest is **CONFIRMED** with **one precision correction** and **zero contradictions**:

- **find-sec-bugs: digest said "LGPL" → upstream SPDX is `LGPL-3.0`** (GitHub License API, not just
  "LGPL"). Verdict unchanged (DROP — any LGPL fails the License-gate), but the matrix now records the precise SPDX.
- **govulncheck:** digest "BSD-3" CONFIRMED as `BSD-3-Clause`; the *vulnerability DB data* is **CC-BY-4.0**
  (a data-license, distinct from the *tool* code license — recorded for completeness; the *tool* fails
  the License-gate on BSD-3).
- **cargo-audit:** digest "MIT/Apache" CONFIRMED as **dual `MIT OR Apache-2.0` at the user's option** —
  admissible (the policy treats an at-your-option dual offering of a permitted license as a pass).
- Every other digest license (Opengrep/Semgrep/CodeQL/trufflehog/hadolint violators; the full admitted
  set) **matched upstream exactly**. No tool the digest called admissible turned out copyleft, and no
  tool it called a violator turned out permissive.

## 4. RQ2 — per-capability admissibility (≥1 admissible tool OR the floor)

Every capability has **≥1 admissible tool** — the floor *fallback* is named by policy (ADR-003) but
**not triggered** by the current set.

| Capability | Admissible (MIT/Apache + local) | Dropped (license) | Floor (ADR-003) |
| --- | --- | --- | --- |
| **SAST** | **floor** + gosec (Apache-2.0, Go) · bandit (Apache-2.0, Py) · ruff `-S` (MIT, Py) · eslint-plugin-security (Apache-2.0, JS/TS) | Opengrep / Semgrep CE (LGPL-2.1) · CodeQL (proprietary) · find-sec-bugs (LGPL-3.0, Java) | Read/Grep/Glob heuristic pass (confidence capped) — **PRIMARY** for cross-language taint + **Java** (no admissible Java SAST after find-sec-bugs drops) |
| **SCA** | OSV-Scanner · Grype · Syft · pip-audit (Apache-2.0) · cargo-audit (MIT/Apache) | govulncheck (BSD-3); ~~Trivy~~ (Apache-2.0 but TeamPCP — wh-nvk, NOT admitted) | read manifests/lockfiles, grep pinned versions vs known-bad ranges |
| **secrets** | gitleaks (MIT) · detect-secrets (Apache-2.0) | trufflehog (AGPL-3.0) | grep high-entropy + known key patterns |
| **IaC/CI** | Checkov (Apache-2.0) · actionlint · zizmor (MIT) | hadolint (GPL-3.0); ~~Trivy config~~ (wh-nvk) | read Dockerfile/manifests/workflows + `reference/infra.md` (Checkov covers Dockerfile misconfig in hadolint's place) |
| **AI-redteam** | promptfoo (MIT) · garak (Apache-2.0) | — | static `reference/ai-llm.md` + KB patterns over the code |

### 4a. The SAST honest answer (the hard case)

No **permissive cross-language taint engine** exists in 2026: the two that dominate (Semgrep CE,
Opengrep) are both LGPL-2.1, and CodeQL is proprietary. The honest answer is the **floor + per-language
MIT/Apache linters**:

- **Go** → gosec (Apache-2.0). **Python** → bandit / ruff `-S` (Apache-2.0 / MIT). **JS/TS** →
  eslint-plugin-security (Apache-2.0). **Java** → **no admissible SAST** (find-sec-bugs is LGPL-3.0;
  SpotBugs core is LGPL too) → **floor only** for Java taint.
- This is a **precision DOWNGRADE** from ADR-011's Opengrep default: per-language linters are
  pattern-based, mostly *intra*-procedural; they do not do the interprocedural cross-file taint Opengrep
  provided. **ADR-025 supersedes ADR-011 explicitly** and accepts the downgrade as the cost of the
  license rule — **but the cost is MEASURED, not asserted** (Policy 9; §6).
- **Track-via-refresh:** an MIT/Apache cross-language taint engine is a standing want. `sec-kb-refresh`
  watches for one (e.g. cognium / any emerging MIT semantic-SAST) and proposes it through the *same*
  admissibility gate if one matures. It is **not** a default today.

## 5. RQ3 — data-egress verdict per admitted tool (telemetry/upload defaults + disable flags)

Verified from each tool's docs/default config. The egress gate asks: *does the DEFAULT invocation run
local with no source upload and no telemetry?*

| Tool | Default data-egress | Verdict | Pinned flag (if needed) |
| --- | --- | --- | --- |
| gosec / bandit / ruff / eslint-plugin-security | fully local; no telemetry | **PASS** | — |
| OSV-Scanner | local scan; queries OSV.dev DB (offline mode supported via local DB) | **PASS** | run against a fetched DB under the fetch/analyze split (ADR-024 §2) for full offline |
| Grype / Syft | local; Grype updates its DB over network unless pre-seeded | **PASS** | `GRYPE_DB_AUTO_UPDATE=false` + fetched DB (fetch/analyze split) for offline |
| pip-audit | local; queries PyPI/OSV advisory source | **PASS** | offline against a local advisory DB; else degrade to floor (never egress to satisfy the gate — ADR-024 §2) |
| cargo-audit | local; pulls the RustSec advisory-db (git) | **PASS** | pre-clone advisory-db; `--stale`/offline |
| gitleaks | fully local; no telemetry | **PASS** | — |
| detect-secrets | fully local; no telemetry | **PASS** | — |
| Checkov | local; does NOT upload source by default; optionally enriches via Prisma public API | **PASS** | run **offline / without `--bc-api-key`** (no auto-telemetry constant; `--bc-api-key` = opt-in push) |
| actionlint / zizmor | fully local; no telemetry | **PASS** | — |
| **promptfoo** | **telemetry ON by default** (cmd name, assertion types, version, CI flag, and — if logged in — user id/email; **NEVER prompts/outputs/configs/keys**) | **PASS only with flag** | **`PROMPTFOO_DISABLE_TELEMETRY=1`** (pin in invocation); also `PROMPTFOO_DISABLE_UPDATE=1` to stop the NPM version check for a fully no-egress run |
| garak | local probes against the target model endpoint you point it at; no product telemetry | **PASS** | — |

**Excluded-by-License-gate tools whose egress reinforces the drop** (recorded, not admitted): **CodeQL** =
SaaS code upload to GitHub code-scanning (egress fail compounding the proprietary fail); **trufflehog
`--results=verified`** makes **live HTTP** calls to validate found secrets against provider APIs (egress).

**Net:** every admitted tool passes the egress gate; **promptfoo is the only one that requires a pinned
flag** to pass (telemetry-off). This is consistent with ADR-024's fetch/analyze split — DB-backed tools
fetch network-ON, then analyze network-OFF; they never run with ambient egress to "satisfy" a scan.

## 6. SAST-downgrade cost — the eval-measurement plan (run POST-wave, NOT this wave)

ADR-011's supersession trades interprocedural taint (Opengrep) for per-language linters + floor. Policy 9
forbids asserting the cost — it must be measured against the labeled eval corpus before KEEP:

1. **Baseline (Opengrep-on):** run `evals/score.py` against the corpus with the *current* SCANNER_PREFERENCE
   (SAST leads with `opengrep`). Record recall/precision per `*/label.json` (neutralize the
   `vulnerable_variant`/`benign_lookalike` filenames first — they leak the answer; QA convention).
2. **Candidate (linters+floor):** re-run with SAST = per-language linters + floor only (Opengrep removed).
3. **Delta:** compare recall (misses) and precision (FPs). The downgrade is **KEPT** if the recall loss is
   within an agreed tolerance OR the floor + linters recover the dropped findings; otherwise the gap is a
   filed follow-up (e.g. prioritise tracking an MIT cross-language taint engine, or a targeted floor rule).
4. **Drift-guard:** `baseline.n_cases == len(corpus cases)` must hold (the baseline is currently stale:
   32 vs 103 — re-baseline before trusting the delta).
5. **Where it runs:** this is an `evals/` measurement on the Claude Code subscription (token budget is the
   cap), reported in a `docs/qa/<YYYYMMDD>/` cycle. **NOT run in this spike wave** — the ADR records the
   plan; the measurement gates the KEEP of the SAST change in the impl ticket.

## 7. RQ4 — registry schema change (columns + SCANNER_PREFERENCE sync)

Add three columns to every tool entry in `_shared/reference/tool-registry.md` so each carries its
admissibility evidence inline:

- **`license`** — the upstream SPDX id (e.g. `Apache-2.0`, `MIT`). Must ∈ {MIT, Apache-2.0} (or a dual
  offering one of them) for an *admitted* row; violators move to a "Rejected (License-gate)" subsection with
  their SPDX + reason.
- **`data_egress`** — `local` | `local+db-fetch` (DB-backed, fetch/analyze split) | `telemetry-off-flag`
  (admitted only with the pinned flag) | `upload` (rejected). Carries the pinned flag where needed.
- **`gdpr`** — a short note on whether the tool, in its admitted invocation, sends any data off-host
  (`none` for fully-local tools; the flag-gated note for promptfoo). This is the *tool's* data-flow only;
  the agent's own model-call PII posture is **wh-81y**, not this column.

**SCANNER_PREFERENCE sync (`detect_tools.py:110`).** The lock test `test_registry_lock.py` enforces
doc↔code **at the CAPABILITY level** (a capability present in code must exist in the doc) — it is GREEN
today (4 passed). **Per-tool drops** (removing `opengrep`/`semgrep` from the `sast` list, `govulncheck`
from `sca`, `trufflehog` from `secrets`, `hadolint` from `iac`) are enforced by the **impl ticket's TDD**,
not the capability-level lock. The impl ticket must update `SCANNER_PREFERENCE` so the SAST list leads
with the per-language linters and the violators are removed, keeping the doc and code in sync.

## 8. RQ5 — the deterministic two-gate admissibility screen (SPEC here; IMPLEMENT in wh-hxt.4)

A **deterministic, pure-function** screen (Policy 5 — no LLM; a new tool is admitted or rejected by code
with a stated reason). **SPEC'd here; IMPLEMENTED in wh-hxt.4** (the ADMIT-via-loop registry-row writer —
no registry-row writer exists today, so the screen lands when that writer lands; wh-hxt.4 is blocked by
wh-562, which is correct sequencing).

```
# Pure-function contract (no I/O beyond the passed-in record; no model call):
def admit_tool(tool: ToolRecord) -> AdmitVerdict:
    """
    tool: {name, license_spdx, data_egress, telemetry_default, disable_flag|None}
    returns: AdmitVerdict(admitted: bool, reason: str)
    Deterministic; same input -> same verdict; no RNG, no network, no LLM.
    """
    # License-gate (license):
    PERMITTED = {"MIT", "Apache-2.0"}
    lic = set(tool.license_spdx.replace(" OR ", "|").split("|"))   # dual "MIT OR Apache-2.0" -> {"MIT","Apache-2.0"}
    if not (lic & PERMITTED):
        return AdmitVerdict(False, f"License-gate reject: {tool.license_spdx} not in {{MIT, Apache-2.0}}")
    # Egress-gate (data-egress):
    if tool.data_egress == "upload":
        return AdmitVerdict(False, "Egress-gate reject: uploads source / SaaS by default")
    if tool.telemetry_default == "on" and tool.disable_flag is None:
        return AdmitVerdict(False, "Egress-gate reject: telemetry on by default and no disable flag")
    return AdmitVerdict(True, "admitted")
```

- **Both gates must pass.** A new tool failing either is rejected with the stated reason (the loop records
  the rejection in its proposal output — a human sees why a tool was not added).
- **Composes with ADR-024 admission.** Admissibility (this screen) decides *whether the tool is allowed in
  the registry at all*. ADR-024 admission then pins + verifies the *specific artifact* every execution.
  A tool must pass BOTH to be both admitted and executed.
- **Test intent (for the impl, wh-hxt.4 TDD):** pin `== admitted` for an MIT-local tool AND
  `!= admitted` for each rejection class (LGPL/GPL/AGPL/BSD-3/proprietary license; upload egress;
  telemetry-on-no-flag). Pin the dual-license parse (`MIT OR Apache-2.0` → admitted). A test that can't
  fail when the allowlist changes is wrong (Policy 9).

## 9. Recommendation

Adopt the **two-gate admissibility policy** (License-gate MIT/Apache-2.0-only + Egress-gate
local/no-default-telemetry) as **registry governance**, codified in ADR-025. Re-audit the registry to the
§3b admitted set; drop the §3a violators; add the §7 columns; sync `SCANNER_PREFERENCE`; **explicitly
supersede ADR-011** and replace the cross-language SAST default with **floor + per-language MIT/Apache
linters**, with the §6 eval-measurement plan gating the KEEP of that downgrade. SPEC the §8 deterministic
screen here; implement it in wh-hxt.4.

## 10. Risk & follow-up

- **R1 — SAST recall regression (Java especially).** No admissible Java SAST remains; cross-language
  taint drops to the floor. **Mitigation:** the §6 eval plan measures it before KEEP; track an MIT taint
  engine via `sec-kb-refresh`. **Follow-up:** the eval measurement runs in the impl ticket / a QA cycle.
- **R2 — gitleaks bus-factor.** gitleaks (MIT, admitted) is single-maintainer + declared feature-complete
  (security patches only; maintainer moving to "Betterleaks"). Still admissible; **track Betterleaks via
  `sec-kb-refresh`** (it would face the same admissibility gate).
- **R3 — registry double-writer.** The registry rewrite (columns from here + replacement rows from wh-nvk
  + the lock-regex fix) MUST be **ONE coordinated change** — never two uncoordinated writers to
  `tool-registry.md` + `SCANNER_PREFERENCE`. The combined draft spec is in §11.
- **R4 — promptfoo telemetry drift.** If a future promptfoo version changes its telemetry default or env
  var, the pinned `PROMPTFOO_DISABLE_TELEMETRY=1` must be re-verified at version bump (pin-and-verify,
  ADR-006). Recorded in the registry `data_egress` note.
- **Coordination recorded (AC):** the registry rewrite is shared with **wh-nvk** as ONE combined ticket
  (§11), not two uncoordinated writers. The RQ5 screen hands to **wh-hxt.4**. No `bd create` this wave
  (override #3) — §11 is a DRAFT spec for `/design-ticket`.

## 11. Draft impl ticket (for /design-ticket) — SHARED with wh-nvk

> **One coordinated registry-rewrite change** — columns (this spike) + replacement rows (wh-nvk) +
> lock-regex fix together. Do NOT split into two uncoordinated writers to `tool-registry.md` +
> `detect_tools.py`. File via `/design-ticket` (not `bd create`) when the wave un-gates.

- **Title:** Registry rewrite — admissibility columns + Trivy-replacement rows + SCANNER_PREFERENCE sync (wh-xn0 ∪ wh-nvk)
- **Goal:** Make `tool-registry.md` and `detect_tools.py:SCANNER_PREFERENCE` reflect the ADR-025 admissible
  set: add `license`/`data_egress`/`gdpr` columns, drop the License-gate violators, install the wh-nvk
  replacement rows (Grype/Syft/Checkov/etc.), and keep the doc↔code lock green.
- **Files:**
  - `plugins/white-hacker/skills/_shared/reference/tool-registry.md` — add the three columns; move
    Opengrep/Semgrep/CodeQL/govulncheck/trufflehog/hadolint/find-sec-bugs to a "Rejected (License-gate)"
    subsection with SPDX + reason; SAST line leads with per-language linters + floor; pin
    `PROMPTFOO_DISABLE_TELEMETRY=1` in the AI-redteam row.
  - `plugins/white-hacker/skills/sec-detect/scripts/detect_tools.py` — `SCANNER_PREFERENCE`: SAST →
    `[(gosec, go), (bandit, python), (ruff, python), (eslint-plugin-security, "typescript")]` (drop
    opengrep/semgrep); SCA → drop `govulncheck`, drop `trivy`, add wh-nvk rows (grype/osv-scanner/...);
    secrets → drop `trufflehog`, keep gitleaks + add detect-secrets; iac → drop `hadolint`, drop `trivy`,
    keep checkov + actionlint/zizmor.
  - `plugins/white-hacker/skills/_shared/scripts/tests/test_registry_lock.py` + the impl's per-tool TDD —
    the lock stays capability-level GREEN; ADD per-tool tests that the violators are ABSENT from
    SCANNER_PREFERENCE and the admitted tools are PRESENT (Policy 9: pin both present-and-absent).
- **ACs:**
  1. Every admitted registry row carries `license ∈ {MIT, Apache-2.0}` (or dual) + `data_egress` +
     `gdpr`; every rejected tool is in the Rejected subsection with SPDX + reason.
  2. `SCANNER_PREFERENCE` contains ZERO License-gate violators (no opengrep/semgrep/govulncheck/trufflehog/
     hadolint); SAST leads with per-language linters; Trivy absent from SCA + IaC.
  3. `test_registry_lock.py` GREEN (capability-level); the new per-tool tests GREEN (violators absent,
     admitted present); `nice -n 10 uv run --with pytest pytest .../tests -q` passes.
  4. ADR-011 supersession reflected (registry no longer names Opengrep the default); ADR-025 cited in the
     registry header.
  5. The §6 SAST-downgrade eval measurement is run (or explicitly scheduled in a `docs/qa/<YYYYMMDD>/`
     cycle) before the SAST-default change is KEPT.
- **Depends-on / coordination:** wh-nvk (replacement rows) — SAME ticket; the RQ5 admissibility screen is
  wh-hxt.4 (separate); the eval re-baseline (32→103) precedes the SAST measurement.

## 12. Evidence artifacts

No PoC code (this spike produces policy + a re-audit, not runnable code). All license/egress claims are
cited inline (§3, §5) to upstream LICENSE files / the GitHub License API / official tool docs, verified
2026-06-10. The deterministic screen (§8) is a contract spec; its TDD lands in wh-hxt.4.

## 13. References

ADR-003 (floor / graceful degradation) · ADR-006 (pin + verify) · ADR-011 (Opengrep SAST default —
**superseded by ADR-025**) · ADR-015 (capability-not-brand registry; self-updates) · ADR-023 (MIT/Apache-2.0-only
bundling precedent; psutil BSD-3 rejection — **generalised** here) · ADR-024 (CONTAIN; the artifact-provenance
**admission** arm + the three-gates-three-objects rule; fetch/analyze split) · wh-nvk (Trivy replacement set +
the SHARED registry rewrite) · wh-hxt.4 (the ADMIT-via-loop writer where the RQ5 screen lands) · wh-562
(its "Gate-2" is the DATA-edit gate — distinct from this spike's Egress-gate) · wh-81y (Spike B —
the agent's own model-call PII posture, the GDPR pipeline concern this ticket does NOT cover).
Upstream sources verified 2026-06-10: raw GitHub LICENSE files + the GitHub License API
(`/repos/{owner}/{repo}/license`) per §3; `promptfoo.dev/docs/configuration/telemetry` per §5.
