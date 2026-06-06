#!/usr/bin/env bash
# PreToolUse outer-loop confinement (T-8.4) — delegates to confine_self_writes.py (see its header
# for the residual-risk statement). Reads the PreToolUse event JSON on stdin; exit 2 = hard block.
exec python3 "$(dirname "$0")/confine_self_writes.py"
