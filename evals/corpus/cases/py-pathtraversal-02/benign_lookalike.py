import os
def read2(name):
    p=os.path.realpath("/data/"+name)
    assert p.startswith("/data/")
    return open(p).read()
