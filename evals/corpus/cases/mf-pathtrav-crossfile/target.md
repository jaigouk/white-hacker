# mf-pathtrav-crossfile

- **language:** python
- **category:** injection
- **difficulty:** hard (T-12.9b cross-file taint)
- **support files:** _support_ctx.py
- Cross-file path traversal: the taint (ctx.target <- req query) originates in _support_ctx.py; the sink file alone shows only `ctx.target` (neutral name). Vuln opens BASE+ctx.target with no canonicalization; benign realpath+base-check. Requires building the cross-file call graph to see ctx.target is attacker-controlled.
