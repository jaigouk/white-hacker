import hashlib
def h4(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # SINK weak-hash
