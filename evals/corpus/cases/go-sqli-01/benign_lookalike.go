package m
import "database/sql"
func Q1(db *sql.DB, v string) *sql.Row {
	return db.QueryRow("SELECT * FROM t1 WHERE c=$1", v)
}
