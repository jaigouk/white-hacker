# hard-ssrf-blocklist-bypass

- **language:** python
- **category:** ssrf
- **difficulty:** hard (T-12.9 headroom case)
- Bypassable SSRF: blocklist guard (misses 0.0.0.0, [::1], decimal IP, ::ffff:127.0.0.1) -> still a finding. Benign uses an https+allowlist guard (exclusion rule 20: NOT a finding).
