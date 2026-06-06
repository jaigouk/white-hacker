package m
import ("net/http"; "net/url")
func Fetch1(raw string) (*http.Response, error) {
	u,_:=url.Parse(raw); if u.Host!="api.internal" { return nil, http.ErrAbortHandler }
	return http.Get(raw)
}
