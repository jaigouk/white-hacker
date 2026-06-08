# sc-npm-install-script-exec

- **language:** javascript (npm)
- **category:** supply-chain
- **difficulty:** medium (floor-scored regression anchor)
- **scored by:** the deterministic supply-chain floor (`supply_chain.scan`), NOT the agent
- **signal:** S6 (install script with >=2 dangerous APIs) — HIGH
- **support files:** vulnerable_variant/{package.json,package-lock.json,scripts/postinstall.js}, benign_lookalike/{package.json,package-lock.json}

A `postinstall` lifecycle hook runs `node scripts/postinstall.js`, which uses `child_process`
and `exec()` to read `~/.npmrc` and beacon it to a (neutralized) `example.test` sink at
`npm install` time — before any test runs. CVE-based SCA approves it (valid version, not yet
catalogued). The floor flags the script as a HIGH supply-chain candidate. The benign variant
drops the install hook and fires nothing.
