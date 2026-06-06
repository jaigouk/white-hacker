import requests
ALLOW = {"api.internal"}
def act(model_url):
    from urllib.parse import urlparse
    assert urlparse(model_url).hostname in ALLOW
    return requests.get(model_url).text
