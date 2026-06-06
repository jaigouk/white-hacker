#!/usr/bin/env bash
# Capture hook (T-8.3) — delegates to capture_hooks.py mode 'cve_digest'. Non-blocking (~0 cost).
exec python3 "$(dirname "$0")/capture_hooks.py" cve_digest
