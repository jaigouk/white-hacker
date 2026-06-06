package m
import ("os"; "path/filepath")
func Read2(n string) ([]byte, error) {
	return os.ReadFile(filepath.Join("/data", n))  // SINK path-traversal
}
