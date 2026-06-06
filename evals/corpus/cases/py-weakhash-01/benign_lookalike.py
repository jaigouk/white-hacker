import bcrypt
def h1(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
