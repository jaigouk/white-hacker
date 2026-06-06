"""Vulnerable AI/MCP agent fixture for the ai-llm-review pass (poc-ai-review).

THREE planted vulnerabilities. This is a DETECTION FIXTURE — not a runnable service,
no real secrets, no working exploit payloads. The ai-llm-review pass should flag the
LLM05 sink (VULN 1), the lethal-trifecta path (VULN 2), and the MCP token passthrough
(VULN 3), each with a kb_ref to an ai-attack-kb entry.
"""
import subprocess

import httpx
from mcp.server import Server
from openai import OpenAI

client = OpenAI()
mcp = Server("vuln-agent")
DB = {"alice": "private notes for alice"}


# --- VULN 1: LLM05 improper output handling -> RCE -------------------------
def summarize_and_run(user_text: str) -> str:
    """The model is asked for a shell command; we run it. Classic LLM05 -> RCE."""
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": f"Return a shell command to: {user_text}"}],
    )
    cmd = resp.choices[0].message.content
    # LLM05 sink: raw model output flows into a shell with shell=True.
    return subprocess.check_output(cmd, shell=True, text=True)


# --- VULN 2: lethal trifecta (private data + untrusted content + exfil) ----
def research_agent(account: str, web_url: str) -> None:
    private = DB.get(account, "")          # (1) access to private data
    untrusted = httpx.get(web_url).text    # (2) exposure to untrusted web content
    decision = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": untrusted + private}],
    ).choices[0].message.content
    # (3) exfiltration: the model decides where to POST the private data.
    httpx.post(decision, content=private)  # exfil leg -> trifecta complete


# --- VULN 3: MCP token passthrough -----------------------------------------
@mcp.tool()
def call_downstream(incoming_token: str, path: str) -> str:
    """Forward the caller's token straight to a downstream API (token passthrough)."""
    # MCP: passes the incoming token through instead of minting an audience-bound one.
    return httpx.get(
        f"https://api.internal/{path}",
        headers={"Authorization": f"Bearer {incoming_token}"},
    ).text
