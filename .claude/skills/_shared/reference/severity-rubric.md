# Severity rubric — count preconditions, don't guess impact

> Used by `sec-triage`. Severity is **derived here**, from reachability across trust boundaries —
> never from the discovery finder's self-assessment. The scoring *standard* is swappable; the
> *method* (precondition counting) is constant.

## 1. Enumerate preconditions first
Before assigning anything, list every condition that must hold for the bug to trigger, e.g.:
non-default config/feature flag, authenticated session, specific role, a race/timing window,
a victim action, network position, a second bug. **Then** map by count.

## 2. Map preconditions → tier
| Preconditions / access | Tier |
|---|---|
| **0 preconditions + unauthenticated remote** | **HIGH / Critical** |
| **1–2 preconditions OR authenticated** | **MEDIUM** |
| **3+ preconditions OR local-only** | **LOW** |

- A **threat-model match** may bump severity by **at most one step** (and only if the threat model
  is supplied during triage).
- Compute as `severity = min(precondition_count_score, required_access_level_score)` — the *easier*
  of "few preconditions" and "low access required" does not override the *harder* constraint; the
  binding (more restrictive) factor wins.

## 3. Severity factors to weigh (per the harness rubric)
Reachability · attacker control of the input · preconditions · authentication level · read-vs-write
(scope) · blast radius (single user / tenant / all users / platform).

## 4. Keep three things SEPARATE (do not let them collapse)
1. **Verification class** — *how strong is the evidence?*
   `verified ∈ { ladder_passed, ladder_failed, static_review_only }`.
   `static_review_only` is the Phase-0/1 default (no execution). "No PoC" is **weak evidence, not
   proof of safety.**
2. **Triage outcome** — *did the adversarial verifier accept it?* `review ∈ { ACCEPT, REJECT }`.
3. **Severity label** — the presentation tier (HIGH/MEDIUM/LOW) from §2.

Downstream tooling branches on **class**, not outcome; precondition-derived ordering is distinct
from the `severity_label`. This prevents "real/confirmed" from silently inflating into "critical".

## 5. Swappable scoring standard
`sec-threat-model` asks which standard the project uses and records it in `THREAT_MODEL.md`; triage
applies it. Do **not** hard-code one:
- **CVSS 3.1 / 4.0** (numeric vectors),
- **OWASP Risk Rating** (likelihood × impact),
- an **organization bug-bar**.
The precondition-counting method above maps onto any of them; only the label/score formatting changes.

## 6. Confidence gate (works with `exclusion-rules.md`)
Report only `confidence ≥ 0.7`; final gate for surfacing = **HIGH/MEDIUM with confidence ≥ 8/10**
and **> 80 % exploitability**. Lower-confidence items stay in `VULN-FINDINGS.json` for the record
but are not promoted to the human report.
