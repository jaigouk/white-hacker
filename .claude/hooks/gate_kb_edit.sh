#!/usr/bin/env bash
# PreToolUse/Stop gate on KB edits (T-9.3) — delegates to gate_kb_edit.py. Blocks an ai-attack-kb /
# checklist write unless evals/gate-verdict.json says KEEP. Exit 2 = hard block.
exec python3 "$(dirname "$0")/gate_kb_edit.py"
