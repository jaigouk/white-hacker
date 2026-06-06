#!/usr/bin/env bash
# sec-learn harvest (T-8.5) — collate capture-hook traces into the reflection input.
# Usage: harvest.sh [traces-dir]   (defaults to ./evals/traces)
exec python3 "$(dirname "$0")/harvest.py" "${1:-evals/traces}"
