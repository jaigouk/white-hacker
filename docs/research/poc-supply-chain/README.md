# poc-supply-chain — demo for the deps-scan supply-chain-malware floor (wh-07w)

A tiny, **fully neutralized** npm project that exercises the offline supply-chain-malware
floor (`deps-scan/scripts/supply_chain.py`, signals S1–S8 from
[`spike-09`](../spike-09-npm-ai-supply-chain-2026-06.md)). Nothing here installs, runs, or
exfiltrates anything — the "malicious" content is detection **test data** only.

## What's in it
- **`package.json`** — one **bad** package: `expresss@1.0.0` (a doubled-char squat of the
  allowlisted `express`: it is distance-1 under S4 **and** ASCII/separator-folds onto `express`
  under S5, since "doubled chars" is an S5 tell per spike-09 §S5), plus a **benign control** dep
  `react@18.2.0` (exact pinned registry version). A `postinstall` lifecycle hook references the
  inert script below.
- **`scripts/postinstall.js`** — an **INERT, commented** install script. It contains the S6
  dangerous-API trigger *strings* (`child_process`, `eval`, `~/.npmrc`, `Buffer.from(...,'base64')`,
  `fetch`) in clearly non-functional `// SAMPLE (inert):` comments, then exports a harmless no-op.
  Same discipline as the eval corpus's neutralized filenames — a white-hacker reviewer can audit it.

## Run the floor on it
```bash
cd plugins/white-hacker/skills/deps-scan/scripts
uv run --with jsonschema python -c "import sys; sys.path.insert(0,'.'); \
  sys.path.insert(0,'../../_shared/scripts'); import json, supply_chain as sc; \
  print(json.dumps(sc.scan('../../../../../docs/research/poc-supply-chain'), indent=2))"
```
You'll get a schema-valid findings document with at least one `category:"supply-chain"`,
`tool_assisted:false` candidate. `expresss` is **HIGH** — it trips S5 (doubled-char fold onto
`express`) and the inert postinstall trips S6 (≥2 dangerous-API strings), so the finding carries
the F4 rung-0 "do not build yet — run `npm ci --ignore-scripts`" remediation. The `react` control
dep stays clean.

## What the floor CAN and CAN'T see pre-install
**Can** (offline, zero network, from on-disk files only):
- lifecycle hooks present (S1), non-registry/git source deps (S2), unpinned ranges with no
  lockfile (S3), typosquat distance to the allowlist (S4), homoglyph/separator scope collisions
  (S5), dangerous-API strings + obfuscation in a **referenced** install script (S6/S7).

**Can't** (out of scope — needs a network / install, ADR-007 keeps us static-first):
- runtime/behavioral analysis (what the package does once executed — that's Socket-style,
  network-only), full provenance/attestation verification (`npm audit signatures` hits the
  registry/Sigstore), and any dependency whose install script isn't on disk yet (un-fetched
  transitive deps). S8 (known-bad match) only fires if an offline OSSF/GHSA snapshot was
  pre-cloned; absent that, the run records `malware-db` as unavailable and degrades to S1–S7.

The floor **never blocks** and emits low/medium-confidence `tool_assisted:false` candidates —
triage and a human decide.
