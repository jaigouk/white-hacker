def get_user(db, uid):
    q = "SELECT * FROM users WHERE id = '%s'" % uid  # SINK sqli
    return db.execute(q).fetchone()
