package m
import "net/http"
func Fetch1(u string) (*http.Response, error) {
	return http.Get(u)  // SINK ssrf
}
