OK={"/home"}
def go2(redirect, nxt):
    return redirect(nxt if nxt in OK else "/home")
