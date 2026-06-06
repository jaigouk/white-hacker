import requests
def fetch3(url):
    return requests.get(url).text  # SINK ssrf
