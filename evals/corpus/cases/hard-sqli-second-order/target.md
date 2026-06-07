# hard-sqli-second-order

- **language:** python
- **category:** injection
- **difficulty:** hard (T-12.9 headroom case)
- Second-order SQLi: a user-controlled column stored earlier is read back and concatenated into ORDER BY (cannot be bound). Benign allowlists the column before interpolation.
