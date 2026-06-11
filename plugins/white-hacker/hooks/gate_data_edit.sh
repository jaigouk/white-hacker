#!/usr/bin/env bash
# PreToolUse Gate-2 DATA write-lane gate (wh-hxt.6; ADR-026 §3) — delegates to gate_data_edit.py.
# Blocks a write to the named watchlist DATA file unless evals/data-verdict.json is a content-bound,
# one-shot KEEP whose path + sha256 match the proposed write. Exit 2 = hard block.
exec python3 "$(dirname "$0")/gate_data_edit.py"
