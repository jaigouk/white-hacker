import os

BASE = "/srv/data"


def read_doc(name):
    full = os.path.realpath(os.path.join(BASE, name))
    if not full.startswith(BASE + os.sep):
        raise ValueError("path escape")
    return open(full).read()
