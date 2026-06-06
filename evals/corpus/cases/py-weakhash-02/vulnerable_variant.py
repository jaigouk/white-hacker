import hashlib
def h2(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # SINK weak-hash
