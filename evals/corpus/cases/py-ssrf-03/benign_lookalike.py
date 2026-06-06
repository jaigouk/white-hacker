import requests
ALLOW={"api.internal"}
def fetch3(url):
    from urllib.parse import urlparse
    assert urlparse(url).hostname in ALLOW
    return requests.get(url).text
