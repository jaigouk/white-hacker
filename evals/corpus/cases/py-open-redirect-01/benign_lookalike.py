OK={"/home"}
def go1(redirect, nxt):
    return redirect(nxt if nxt in OK else "/home")
