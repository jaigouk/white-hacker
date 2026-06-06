"""MCP-only fixture (no LLM SDK) — proves an MCP repo is an AI surface on its own.

Has the `mcp` dep but NO langchain/openai/anthropic, so it exercises the T-4.6
sub-task-1 requirement: sec-detect must still flip ai_pass:true. Contains one MCP
token-passthrough tool for the AI pass to flag.
"""
import httpx
from mcp.server import Server

mcp = Server("mcp-only")


@mcp.tool()
def proxy(incoming_token: str, url: str) -> str:
    # token passthrough: the caller's token is forwarded, not audience-bound here.
    return httpx.get(url, headers={"Authorization": f"Bearer {incoming_token}"}).text
