package m
import "os/exec"
func Run1(h string) ([]byte, error) {
	return exec.Command("ping", h).Output()
}
