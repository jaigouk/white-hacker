"""Clean look-alike — the SAME shapes as ai-vuln/agent.py but done safely.

The AI pass MUST NOT flag anything here: model output is schema-validated against an
allowlist before any sink, the command uses an argv array (no shell, fixed binary),
and the downstream credential is minted with an explicit audience (no passthrough).
"""
import json
import subprocess

import httpx
from openai import OpenAI

client = OpenAI()
ALLOWED_ACTIONS = {"list_files", "show_status", "current_time"}


def run_allowed_action(user_text: str) -> str:
    """Structured output validated against an allowlist BEFORE the sink (LLM05-safe)."""
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": user_text}],
        response_format={"type": "json_object"},
    )
    action = json.loads(resp.choices[0].message.content).get("action")
    if action not in ALLOWED_ACTIONS:        # validate structured output first
        raise ValueError("action not allowed")
    # argv array, no shell, fixed binary -> model text never becomes the command.
    return subprocess.check_output(["/usr/bin/agentctl", action], text=True)


def mint_downstream_token(audience: str) -> str:
    """Mint an audience-bound token for the downstream (no passthrough) — MCP-safe."""
    return httpx.post(
        "https://auth.internal/token",
        json={"audience": audience, "scope": "read"},
    ).json()["access_token"]
