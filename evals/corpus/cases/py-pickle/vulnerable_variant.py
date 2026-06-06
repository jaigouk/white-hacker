import pickle
def load(blob):
    return pickle.loads(blob)  # SINK insecure-deserialization
