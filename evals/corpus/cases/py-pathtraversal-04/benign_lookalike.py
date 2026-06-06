import os
def read4(name):
    p=os.path.realpath("/data/"+name)
    assert p.startswith("/data/")
    return open(p).read()
