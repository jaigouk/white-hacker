package m
import "database/sql"
func Find(db *sql.DB, id string) *sql.Row {
	return db.QueryRow("SELECT * FROM t WHERE id=$1", id)
}
