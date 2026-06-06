#!/usr/bin/env bash
# PreToolUse review-posture guard (T-6.4) — delegates to guard_bash.py (see its header for the
# residual-risk statement). Reads the PreToolUse event JSON on stdin; exit 2 = hard block.
exec python3 "$(dirname "$0")/guard_bash.py"
