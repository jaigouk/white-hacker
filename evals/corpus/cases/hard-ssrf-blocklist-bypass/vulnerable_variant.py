import requests
from urllib.parse import urlparse

BLOCKED = {"localhost", "127.0.0.1", "169.254.169.254"}


def _looks_safe(url):
    host = urlparse(url).hostname or ""
    return host not in BLOCKED


def fetch_remote(url):
    if not _looks_safe(url):
        raise ValueError("blocked host")
    return requests.get(url, timeout=5).content
