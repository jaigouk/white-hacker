package m
import ("os"; "path/filepath")
func Read(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join("/data", name))  // SINK path-traversal
}
