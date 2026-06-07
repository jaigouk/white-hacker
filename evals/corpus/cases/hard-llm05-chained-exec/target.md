# hard-llm05-chained-exec

- **language:** python
- **category:** improper-output-handling
- **difficulty:** hard (T-12.9 headroom case)
- LLM05 chained across functions: model output stored in a dict, later run via subprocess(shell=True). Source is model output -> improper-output-handling (ai-llm sec.2), not plain cmdi. Benign constrains the model to an allowlisted argv action.
