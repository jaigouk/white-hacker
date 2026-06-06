package m
import "os/exec"
func Run4(h string) ([]byte, error) {
	return exec.Command("ping", h).Output()
}
