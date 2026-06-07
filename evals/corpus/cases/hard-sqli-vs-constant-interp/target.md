# hard-sqli-vs-constant-interp

- **language:** python
- **category:** injection
- **difficulty:** hard (T-12.9 headroom case, subtle FN/FP boundary)
- FP-inducer pair: vulnerable twin f-string-interpolates a user-supplied status into SQL (real SQLi); benign twin interpolates a server-side CONSTANT (no taint -> not injectable, but lexically identical f-string-in-query shape). Tests precision: an f-string in a query is not automatically a finding.
