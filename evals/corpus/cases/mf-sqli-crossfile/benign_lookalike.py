from _support_prefs import load_sort

ALLOWED = {"name", "created_at", "price"}


def list_items(db, uid):
    col = load_sort(db, uid)
    if col not in ALLOWED:
        col = "name"
    return db.execute(f"SELECT * FROM items ORDER BY {col}").fetchall()
