import os
from _support_ctx import Ctx

BASE = "/srv/files"


def read_file(ctx: Ctx):
    full = os.path.realpath(os.path.join(BASE, ctx.target))
    if not full.startswith(BASE + os.sep):
        raise ValueError("path escape")
    return open(full).read()
