package m
import ("database/sql"; "fmt")
func Q2(db *sql.DB, v string) *sql.Row {
	return db.QueryRow(fmt.Sprintf("SELECT * FROM t2 WHERE c=%s", v))  // SINK sqli
}
