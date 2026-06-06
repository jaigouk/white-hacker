def read2(name):
    return open("/data/" + name).read()  # SINK path-traversal
