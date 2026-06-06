package m
import "net/http"
func Fetch(url string) (*http.Response, error) {
	return http.Get(url)  // SINK ssrf
}
