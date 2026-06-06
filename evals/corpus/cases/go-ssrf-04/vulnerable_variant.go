package m
import "net/http"
func Fetch4(u string) (*http.Response, error) {
	return http.Get(u)  // SINK ssrf
}
