package m
import "net/http"
func Fetch3(u string) (*http.Response, error) {
	return http.Get(u)  // SINK ssrf
}
