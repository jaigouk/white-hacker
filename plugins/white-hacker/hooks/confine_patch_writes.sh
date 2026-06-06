#!/usr/bin/env bash
# PreToolUse confinement tripwire (sec-patch). Delegates to confine_patch_writes.py — see that
# file's header for the verbatim RESIDUAL-RISK statement (this is a tripwire, not the boundary;
# the strong guarantee is structural: no Write/Edit tool, no granted apply capability, human
# applies PATCHES/). Reads the PreToolUse event JSON on stdin; exit 2 = hard block.
exec python3 "$(dirname "$0")/confine_patch_writes.py"
