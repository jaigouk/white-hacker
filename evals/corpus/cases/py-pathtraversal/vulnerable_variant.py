def read(name):
    return open("/data/" + name).read()  # SINK path-traversal
