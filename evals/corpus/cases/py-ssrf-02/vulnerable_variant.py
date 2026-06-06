import requests
def fetch2(url):
    return requests.get(url).text  # SINK ssrf
