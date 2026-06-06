# Eval corpus — labeled vulnerable / benign look-alike pairs

Ground truth for the white-hacker review pipeline (Phase 7 T-7.1). Each
`cases/<id>/` holds:

| file | role |
|------|------|
| `target.md` | the case context (language, category, one-line description) |
| `vulnerable_variant.<ext>` | the variant that **should** produce a finding (a `SINK` marker is on the dangerous line) |
| `benign_lookalike.<ext>` | the safe variant of the same shape that **must not** fire (the false-positive term) |
| `label.json` | ground truth: `{case_id, language, category, severity, owasp, vulnerable:{file,line}, benign_lookalike:{file}}` (validated against `../label-schema.json`) |

## Provenance
- **Generated** by [`generate.py`](generate.py) (deterministic, reproducible — re-run to regenerate),
  OWASP-Benchmark-style: small representative detection snippets, not runnable services.
- Categories mirror `_shared/reference/core-checklist.md` (injection, AuthN/AuthZ, ssrf, crypto,
  deserialization, xss, config) **plus** the AI classes (`improper-output-handling`/LLM05,
  `prompt-injection`/LLM01, `excessive-agency`/LLM06, `tool-poisoning`/MCP01, `rag-poisoning`/LLM08,
  `data-exfil`/LLM02) across python / javascript / typescript / go.
- 32 cases at Phase 7 (minimum baseline ≥ 30). **Phase 9** grows this toward ≥ 100 and mixes in real
  CVE pre/post-fix anchors, then freezes the corpus read-only behind the keep-or-revert gate.

## Scoring
`evals/score.py` consumes a finding-schema findings JSON + these labels and emits TPR / FPR /
Youden's J (a finding matches a label by file + category + line-within-tolerance; a benign
look-alike that fires is a false positive). See `evals/tests/test_score.py`.
