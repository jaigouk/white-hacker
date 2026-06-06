import hashlib
def h3(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # SINK weak-hash
