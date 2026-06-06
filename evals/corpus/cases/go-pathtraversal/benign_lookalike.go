package m
import ("os"; "path/filepath"; "strings")
func Read(name string) ([]byte, error) {
	p := filepath.Clean(filepath.Join("/data", name))
	if !strings.HasPrefix(p, "/data/") { return nil, os.ErrPermission }
	return os.ReadFile(p)
}
