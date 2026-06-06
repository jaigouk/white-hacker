package m
import "database/sql"
func Q3(db *sql.DB, v string) *sql.Row {
	return db.QueryRow("SELECT * FROM t3 WHERE c=$1", v)
}
