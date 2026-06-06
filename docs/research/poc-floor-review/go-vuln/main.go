package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

// VULN (planted): OS command injection — user-controlled `host` is concatenated
// into a shell command string. Category: injection. OWASP A03:2025.
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput()
	fmt.Fprintf(w, "%s", out)
}

func main() {
	http.HandleFunc("/ping", pingHandler)
	http.ListenAndServe(":8080", nil)
}
