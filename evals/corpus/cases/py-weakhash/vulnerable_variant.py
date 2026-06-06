import hashlib
def hpw(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # SINK weak-hash
