OK={"/home"}
def go3(redirect, nxt):
    return redirect(nxt if nxt in OK else "/home")
