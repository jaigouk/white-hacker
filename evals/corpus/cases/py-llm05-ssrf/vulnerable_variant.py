import requests
def act(model_url):
    return requests.get(model_url).text  # SINK improper-output-handling
