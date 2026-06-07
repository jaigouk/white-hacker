# hard-deser-yaml-load

- **language:** python
- **category:** deserialization
- **difficulty:** hard (T-12.9 headroom case, subtle FN/FP boundary)
- FP-inducer pair: vulnerable twin uses yaml.load(untrusted) (unsafe full loader); benign twin uses yaml.safe_load (safe but lexically similar). Tests precision: do NOT flag safe_load.
