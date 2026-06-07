# hard-ssrf-allowlist-suffix-bypass

- **language:** python
- **category:** ssrf
- **difficulty:** hard (T-12.9 headroom case, subtle FN/FP boundary)
- Looks-safe-but-isn't: an ALLOWLIST guard (the pattern the checklist calls safe) implemented with host.endswith('internal.example') -> an attacker domain like 'evil-internal.example' satisfies the suffix. Benign uses an exact-set membership allowlist (truly safe). Tests whether the reviewer audits the allowlist's correctness, not just its presence.
