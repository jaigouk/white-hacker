def read1(name):
    return open("/data/" + name).read()  # SINK path-traversal
