# hard-authz-missing-ownership

- **language:** python
- **category:** AuthN/AuthZ
- **difficulty:** hard (T-12.9 headroom case, subtle FN/FP boundary)
- Looks-safe-but-isn't: an authentication check (is_active) is present, which can mask that the OWNERSHIP check is absent -> IDOR. Benign adds the doc.owner_id == current_user.id check. Tests whether the reviewer distinguishes authN-present from authZ-missing.
