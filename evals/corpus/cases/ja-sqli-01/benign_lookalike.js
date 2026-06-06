function q1(db, v){ return db.query("SELECT * FROM t1 WHERE c=$1", [v]); }
