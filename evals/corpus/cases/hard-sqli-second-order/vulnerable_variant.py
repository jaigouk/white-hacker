def save_pref(db, user_id, sort_col):
    db.execute("UPDATE prefs SET sort=? WHERE uid=?", (sort_col, user_id))


def list_items(db, user_id):
    col = db.execute("SELECT sort FROM prefs WHERE uid=?", (user_id,)).fetchone()[0]
    return db.execute(f"SELECT * FROM items ORDER BY {col}").fetchall()
