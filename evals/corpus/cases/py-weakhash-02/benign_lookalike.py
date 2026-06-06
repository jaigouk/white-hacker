import bcrypt
def h2(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
