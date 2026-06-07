# hard-xss-incomplete-sanitizer

- **language:** python
- **category:** xss
- **difficulty:** hard (T-12.9 headroom case)
- Bypassable XSS: a regex strips <script> tags only, then interpolates raw into HTML (misses onerror=, <img>, <svg>, attribute-context payloads). Benign uses html.escape.
