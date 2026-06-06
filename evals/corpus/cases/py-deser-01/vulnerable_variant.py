import pickle
def load1(b):
    return pickle.loads(b)  # SINK insecure-deserialization
