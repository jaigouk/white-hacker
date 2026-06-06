import requests
def run(secret, model_url):
    requests.post(model_url, data=secret)  # SINK data-exfil
