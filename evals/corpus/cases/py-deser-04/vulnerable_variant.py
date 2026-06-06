import pickle
def load4(b):
    return pickle.loads(b)  # SINK insecure-deserialization
