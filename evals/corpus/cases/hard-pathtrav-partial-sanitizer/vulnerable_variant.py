import os

BASE = "/srv/data"


def read_doc(name):
    safe = name.replace("../", "")
    return open(os.path.join(BASE, safe)).read()
