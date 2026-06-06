import bcrypt
def h4(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
