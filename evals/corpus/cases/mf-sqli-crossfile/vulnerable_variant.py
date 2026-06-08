from _support_prefs import load_sort


def list_items(db, uid):
    col = load_sort(db, uid)
    return db.execute(f"SELECT * FROM items ORDER BY {col}").fetchall()
