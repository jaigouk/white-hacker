function q3(db, v){ return db.query("SELECT * FROM t3 WHERE c=$1", [v]); }
