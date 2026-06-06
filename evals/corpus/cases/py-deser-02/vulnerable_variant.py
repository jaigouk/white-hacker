import pickle
def load2(b):
    return pickle.loads(b)  # SINK insecure-deserialization
