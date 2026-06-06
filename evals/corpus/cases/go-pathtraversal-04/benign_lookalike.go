package m
import ("os"; "path/filepath"; "strings")
func Read4(n string) ([]byte, error) {
	p:=filepath.Clean(filepath.Join("/data", n)); if !strings.HasPrefix(p,"/data/") { return nil, os.ErrPermission }
	return os.ReadFile(p)
}
