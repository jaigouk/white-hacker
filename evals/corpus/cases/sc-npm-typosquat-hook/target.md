# sc-npm-typosquat-hook

- **language:** javascript (npm)
- **category:** supply-chain
- **difficulty:** medium (floor-scored regression anchor)
- **scored by:** the deterministic supply-chain floor (`supply_chain.scan`), NOT the agent
- **signal:** S4 (typosquat, Damerau-Levenshtein 1) + S1 (install hook) — MEDIUM
- **support files:** vulnerable_variant/{package.json,package-lock.json}, benign_lookalike/{package.json,package-lock.json}

Dependency `langchian` is one transposition away from the allowlisted `langchain`; a
`postinstall` hook corroborates. The floor emits one MEDIUM supply-chain candidate on
`package.json` (signals S1, S4). The benign variant uses the correct `langchain` (exact
allowlist match) with the same hook and fires nothing — a lone install hook is informational.
