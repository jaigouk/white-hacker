import requests
def call(incoming_token, path, mint):
    tok = mint(audience="https://api")
    return requests.get(f"https://api/{path}", headers={"Authorization": f"Bearer {tok}"})
