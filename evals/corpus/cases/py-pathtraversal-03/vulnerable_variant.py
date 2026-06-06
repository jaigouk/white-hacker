def read3(name):
    return open("/data/" + name).read()  # SINK path-traversal
