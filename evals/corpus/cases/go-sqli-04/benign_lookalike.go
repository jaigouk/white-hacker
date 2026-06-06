package m
import "database/sql"
func Q4(db *sql.DB, v string) *sql.Row {
	return db.QueryRow("SELECT * FROM t4 WHERE c=$1", v)
}
