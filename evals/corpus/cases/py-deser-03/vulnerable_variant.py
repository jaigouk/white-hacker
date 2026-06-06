import pickle
def load3(b):
    return pickle.loads(b)  # SINK insecure-deserialization
