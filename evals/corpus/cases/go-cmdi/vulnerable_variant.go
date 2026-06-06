package m
import "os/exec"
func Run(host string) ([]byte, error) {
	return exec.Command("sh", "-c", "ping "+host).Output()  // SINK cmdi
}
