#!/usr/bin/env bash
# Team-mode review gate (T-6.5) — delegates to gate_review.py. On a TaskCompleted/TeammateIdle
# event, exit 2 (block) until TRIAGE.json exists; else exit 0 and surface summary + report path.
exec python3 "$(dirname "$0")/gate_review.py"
