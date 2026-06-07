import requests
from urllib.parse import urlparse

ALLOWED = {"api.internal.example", "cdn.internal.example"}


def _looks_safe(url):
    p = urlparse(url)
    return p.scheme == "https" and p.hostname in ALLOWED


def fetch_remote(url):
    if not _looks_safe(url):
        raise ValueError("blocked host")
    return requests.get(url, timeout=5).content
