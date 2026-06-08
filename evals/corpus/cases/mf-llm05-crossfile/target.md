# mf-llm05-crossfile

- **language:** python
- **category:** improper-output-handling
- **difficulty:** hard (T-12.9b cross-file taint)
- **support files:** _support_planner.py
- Cross-file LLM05: model_suggestion (in _support_planner.py) returns LLM output; the sink file passes `s` to subprocess(shell=True). Sink file alone shows only `s = model_suggestion(...)`. To know `s` is MODEL output (untrusted per ai-llm), the agent must read _support_planner. Benign validates against an allowlist (argv, no shell).
