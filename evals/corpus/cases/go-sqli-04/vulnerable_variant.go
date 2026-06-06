package m
import ("database/sql"; "fmt")
func Q4(db *sql.DB, v string) *sql.Row {
	return db.QueryRow(fmt.Sprintf("SELECT * FROM t4 WHERE c=%s", v))  // SINK sqli
}
