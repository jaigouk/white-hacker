package main

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
)

// SAFE look-alike: argv array (no shell), and the input is validated as an IP.
// A correct floor review must NOT flag this.
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if net.ParseIP(host) == nil {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}
	out, _ := exec.Command("ping", "-c", "1", host).CombinedOutput()
	fmt.Fprintf(w, "%s", out)
}

func main() {
	http.HandleFunc("/ping", pingHandler)
	http.ListenAndServe(":8080", nil)
}
