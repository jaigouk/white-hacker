#!/usr/bin/env bash
# SessionStart factual-context injection (T-10.6) — delegates to sessionstart_project_facts.py.
# Emits the sec-init project profile as FACTUAL additionalContext (<=10k chars, never imperative);
# clean no-op when no .white-hacker/project-profile.json is present. Non-blocking (always exit 0).
exec python3 "$(dirname "$0")/sessionstart_project_facts.py"
