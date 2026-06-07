STATUS = "active"


def count_active(db):
    return db.execute(
        f"SELECT count(*) FROM users WHERE status='{STATUS}'"
    ).fetchone()
