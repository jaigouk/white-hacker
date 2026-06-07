# hard-cmdi-vs-hardcoded-argv

- **language:** python
- **category:** injection
- **difficulty:** hard (T-12.9 headroom case, subtle FN/FP boundary)
- FP-inducer pair: vulnerable twin runs user input via shell=True (real cmdi); benign twin calls subprocess.run with a fully HARDCODED argv list and no user input (scary-looking but safe). Tests precision: do NOT flag the constant-argv benign.
