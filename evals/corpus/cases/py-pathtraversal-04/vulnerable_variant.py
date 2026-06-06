def read4(name):
    return open("/data/" + name).read()  # SINK path-traversal
