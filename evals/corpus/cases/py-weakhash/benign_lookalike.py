import bcrypt
def hpw(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
