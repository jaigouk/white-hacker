import requests
def fetch4(url):
    return requests.get(url).text  # SINK ssrf
