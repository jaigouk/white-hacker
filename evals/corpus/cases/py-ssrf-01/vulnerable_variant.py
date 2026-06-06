import requests
def fetch1(url):
    return requests.get(url).text  # SINK ssrf
