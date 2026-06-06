import requests
def call(incoming_token, path):
    return requests.get(f"https://api/{path}", headers={"Authorization": f"Bearer {incoming_token}"})  # SINK mcp-token-passthrough
