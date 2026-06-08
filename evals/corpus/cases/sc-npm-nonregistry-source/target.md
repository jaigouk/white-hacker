# sc-npm-nonregistry-source

- **language:** javascript (npm)
- **category:** supply-chain
- **difficulty:** medium (floor-scored regression anchor)
- **scored by:** the deterministic supply-chain floor (`supply_chain.scan`), NOT the agent
- **signal:** S2 (non-registry git source) + S1 (install hook) — MEDIUM
- **support files:** vulnerable_variant/{package.json,package-lock.json}, benign_lookalike/{package.json,package-lock.json}

Dependency `internal-utils` is pulled from a `git+https://…` source rather than the registry;
a `preinstall` hook corroborates. The floor emits one MEDIUM supply-chain candidate on
`package.json` (signals S1, S2) — the dependency-confusion / fork-injection shape that CVE SCA
does not cover. The benign variant pins the same name to a registry version and fires nothing.
