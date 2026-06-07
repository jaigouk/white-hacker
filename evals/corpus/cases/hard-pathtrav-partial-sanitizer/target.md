# hard-pathtrav-partial-sanitizer

- **language:** python
- **category:** injection
- **difficulty:** hard (T-12.9 headroom case)
- Bypassable path traversal: single non-recursive replace('../','') -> '....//' collapses back to '../'. Benign canonicalizes (realpath) and confirms the result stays under BASE.
