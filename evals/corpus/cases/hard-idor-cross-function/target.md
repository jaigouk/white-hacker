# hard-idor-cross-function

- **language:** python
- **category:** AuthN/AuthZ
- **difficulty:** hard (T-12.9 headroom case)
- Cross-function IDOR/BOLA: object loaded by id in a helper, returned without an ownership check against current_user. Benign re-verifies invoice.owner_id == current_user.id.
