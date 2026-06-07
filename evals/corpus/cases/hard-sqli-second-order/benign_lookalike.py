ALLOWED_COLS = {"name", "created_at", "price"}


def list_items(db, user_id):
    col = db.execute("SELECT sort FROM prefs WHERE uid=?", (user_id,)).fetchone()[0]
    if col not in ALLOWED_COLS:
        col = "name"
    return db.execute(f"SELECT * FROM items ORDER BY {col}").fetchall()
