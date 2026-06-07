import jwt


def verify(token, public_key):
    return jwt.decode(token, public_key, algorithms=["RS256", "HS256"])
