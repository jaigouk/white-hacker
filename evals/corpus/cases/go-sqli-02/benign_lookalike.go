package m
import "database/sql"
func Q2(db *sql.DB, v string) *sql.Row {
	return db.QueryRow("SELECT * FROM t2 WHERE c=$1", v)
}
