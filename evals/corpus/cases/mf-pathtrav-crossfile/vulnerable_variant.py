import os
from _support_ctx import Ctx

BASE = "/srv/files"


def read_file(ctx: Ctx):
    return open(os.path.join(BASE, ctx.target)).read()
