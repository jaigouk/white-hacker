import requests
from urllib.parse import urlparse

ALLOWED = {"api.internal.example", "cdn.internal.example"}


def fetch(url):
    host = urlparse(url).hostname or ""
    if host not in ALLOWED:
        raise ValueError("blocked host")
    return requests.get(url, timeout=5).content
