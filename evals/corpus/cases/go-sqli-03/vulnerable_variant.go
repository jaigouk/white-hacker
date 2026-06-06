package m
import ("database/sql"; "fmt")
func Q3(db *sql.DB, v string) *sql.Row {
	return db.QueryRow(fmt.Sprintf("SELECT * FROM t3 WHERE c=%s", v))  // SINK sqli
}
