import hashlib
def h1(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # SINK weak-hash
