import bcrypt
def h3(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
