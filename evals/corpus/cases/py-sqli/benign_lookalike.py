def get_user(db, uid):
    return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
