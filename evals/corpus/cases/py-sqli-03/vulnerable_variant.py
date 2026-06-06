def q3(db, v):
    return db.execute("SELECT * FROM t3 WHERE c = '" + v + "'")  # SINK sqli
