def q2(db, v):
    return db.execute("SELECT * FROM t2 WHERE c = '" + v + "'")  # SINK sqli
