function q4(db, v){ return db.query("SELECT * FROM t4 WHERE c=$1", [v]); }
