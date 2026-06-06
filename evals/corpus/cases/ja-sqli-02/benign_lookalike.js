function q2(db, v){ return db.query("SELECT * FROM t2 WHERE c=$1", [v]); }
