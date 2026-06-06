# PoC / fixture — sec-patch patch-ladder demonstration (T-5.4)

- **Status:** ✅ PASS — the ladder runs end-to-end on a buildable planted-vuln fixture: the PoC
  reproduces the vuln, `sec-patch` proposes a minimal root-cause diff **only under `PATCHES/`**
  (confinement held), a human applies it, the **PoC stops**, **existing tests pass**, the
  **re-attack** finds no bypass, and the **variant hunt** catches the sibling sink.
- **Date:** 2026-06-06 · **Maps to:** Phase 5 T-5.4.

## Fixture
- `app/vuln.py` — two command-injection sinks of the same class: `run_check` (`:16`) and
  `run_traceroute` (`:23`), each interpolating a user `host` into a `shell=True` command.
- `tests/test_functional.py` — legitimate-behavior tests (the "tests pass" rung); green on both
  vulnerable and patched code.
- `poc_exploit.py` — the oracle (the "PoC stops" rung): exit **0** = injection reproduced, exit
  **1** = blocked. Detects *execution* (a standalone `PWNED` line), not a literal substring, so the
  argv-list fix is correctly scored as blocked.
- `expected-patch.diff` — the proposed minimal root-cause diff (tracked here because `PATCHES/` is
  gitignored; `sec-patch` writes it to `PATCHES/F-001-command-injection.diff` at run time).
- `EXPECTED-PATCH-STATE.json` — the expected verdict (tracked; the live `PATCH-STATE.json` is
  gitignored). Validates against `.claude/skills/sec-patch/patch-state-schema.json`.

## Ladder run (verified — transcribed from a scratch copy outside the repo)
> Run in a scratch copy so the `git status` confinement check is observable (`PATCHES/` is
> gitignored inside this repo, so it would show nothing here):
> `cp -r docs/research/poc-patch-ladder /tmp/ladder && cd /tmp/ladder && git init -q && git add -A && git commit -qm base`

| Rung | Command | Result |
|------|---------|--------|
| baseline | `uv run python poc_exploit.py` | `INJECTION REPRODUCED` (exit 0) |
| tests (pre) | `uv run --with pytest pytest -q` | `2 passed` |
| **confinement** | sec-patch writes only `PATCHES/F-001-…diff`; `git status --porcelain` | **`?? PATCHES/`** (nothing else touched) |
| apply (human) | `git apply PATCHES/F-001-command-injection.diff` | applied |
| **build** | (interpreted Python) | `n/a` |
| **PoC stops** | `uv run python poc_exploit.py` | `blocked` (exit 1) |
| **tests pass** | `uv run --with pytest pytest -q` | `2 passed` |
| **re-attack** | fresh review of the patched code (argv list removes shell parsing on BOTH sinks) | no bypass → `pass` |
| **variant hunt** | — | `run_traceroute` (`app/vuln.py:23`) sibling sink fixed in the same diff |

→ `verdict: patched`.

## Verify (from the repo root)
```bash
# the verdict validates AND records reattack=pass with a non-empty variant list
uv run --with jsonschema python -c "import json,sys; sys.path.insert(0,'.claude/skills/sec-patch/scripts'); \
import validate_patch_state as v; d=json.load(open('docs/research/poc-patch-ladder/EXPECTED-PATCH-STATE.json')); \
assert v.validate(d)==[]; p=d['patches'][0]; assert p['ladder']['reattack']=='pass' and len(p['variants'])>0; print('OK')"
# the proposed diff applies cleanly + the PoC then reports 'blocked' (re-run the scratch steps above)
```

## Notes
- **Confinement evidence** is shown in a scratch copy because `.gitignore` ignores `PATCHES/`
  inside this repo (same reason the verdict/diff use tracked names here).
- The re-attack rung is a **fresh-session review** (white-hacker grants no `Task`/`Agent` tool — a
  separate `/security-review` or `/sec-patch` invocation; ADR-008 fresh context), transcribed as a
  one-time live demonstration rather than a CI assertion.
- Benign marker payload only (`; echo PWNED`); no destructive content.
