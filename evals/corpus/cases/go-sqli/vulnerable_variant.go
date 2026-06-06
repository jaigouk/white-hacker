package m
import ("database/sql"; "fmt")
func Find(db *sql.DB, id string) *sql.Row {
	return db.QueryRow(fmt.Sprintf("SELECT * FROM t WHERE id=%s", id))  // SINK sqli
}
