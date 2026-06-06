import requests
ALLOW={"api.internal"}
def fetch1(url):
    from urllib.parse import urlparse
    assert urlparse(url).hostname in ALLOW
    return requests.get(url).text
