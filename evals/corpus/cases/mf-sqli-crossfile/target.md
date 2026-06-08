# mf-sqli-crossfile

- **language:** python
- **category:** injection
- **difficulty:** hard (T-12.9b cross-file taint)
- **support files:** _support_prefs.py
- Cross-file second-order SQLi: load_sort (in _support_prefs.py) returns a user-stored value; the sink file f-strings it into ORDER BY. Sink file alone shows only `col = load_sort(...)`. Vuln interpolates raw; benign allowlists. Requires tracing load_sort across files.
