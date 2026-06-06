package m
import "net/http"
func Fetch2(u string) (*http.Response, error) {
	return http.Get(u)  // SINK ssrf
}
