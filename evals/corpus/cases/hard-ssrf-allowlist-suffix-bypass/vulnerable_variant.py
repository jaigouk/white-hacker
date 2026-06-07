import requests
from urllib.parse import urlparse


def fetch(url):
    host = urlparse(url).hostname or ""
    if not host.endswith("internal.example"):
        raise ValueError("blocked host")
    return requests.get(url, timeout=5).content
