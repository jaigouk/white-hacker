def q4(db, v):
    return db.execute("SELECT * FROM t4 WHERE c = ?", (v,))
