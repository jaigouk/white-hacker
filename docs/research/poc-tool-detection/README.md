# PoC — Language + tool detection with graceful degradation

- **Status:** ✅ PASS (12/12 tests)
- **Date:** 2026-06-06
- **Verifies:** the `sec-detect` premise (auto-detect stack) and the
  "never block on a missing tool → degrade to Read/Grep/Glob" assumption.

## Files
- `detect_tools.py` — detection logic (`detect_languages`, `detect_available_tools`,
  `build_scan_plan` with a degradation ladder; `which` is injectable for tests).
- `test_detect_tools.py` — 12 tests incl. edge cases (empty repo, multi-language,
  TS-vs-JS disambiguation, infra-only, per-language SCA tool match, degradation).

## Run
```bash
cd docs/research/poc-tool-detection
uv run --with pytest pytest -q          # -> 12 passed
python3 detect_tools.py /path/to/repo   # prints a SCAN-PLAN-style JSON
```

## Result (verified)
```
12 passed in 0.03s
```

## Conclusion / decision
- Auto-detection from manifest signal files is reliable and cheap → keep as the
  `sec-detect` approach.
- Graceful degradation works: when a category has no installed tool the plan marks
  it `degraded` and falls back to `read-grep-glob heuristic pass (confidence capped)`
  instead of failing. → confirms **ADR-003** (graceful degradation).
- This PoC becomes the seed for the real `sec-detect` skill `scripts/` (which will
  ship with these same tests, expanded).
