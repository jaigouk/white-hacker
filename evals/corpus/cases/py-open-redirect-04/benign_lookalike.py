OK={"/home"}
def go4(redirect, nxt):
    return redirect(nxt if nxt in OK else "/home")
