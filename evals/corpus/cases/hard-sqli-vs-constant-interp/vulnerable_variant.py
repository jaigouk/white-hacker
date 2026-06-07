def count_status(db, status):
    return db.execute(
        f"SELECT count(*) FROM users WHERE status='{status}'"
    ).fetchone()
