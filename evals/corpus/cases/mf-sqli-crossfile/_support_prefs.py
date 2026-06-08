def load_sort(db, uid):
    return db.execute("SELECT sort FROM prefs WHERE uid=?", (uid,)).fetchone()[0]
