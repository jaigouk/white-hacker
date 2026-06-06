package m
import ("database/sql"; "fmt")
func Q1(db *sql.DB, v string) *sql.Row {
	return db.QueryRow(fmt.Sprintf("SELECT * FROM t1 WHERE c=%s", v))  // SINK sqli
}
