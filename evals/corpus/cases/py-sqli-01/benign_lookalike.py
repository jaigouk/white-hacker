def q1(db, v):
    return db.execute("SELECT * FROM t1 WHERE c = ?", (v,))
