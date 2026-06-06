package m
import "os/exec"
func Run3(h string) ([]byte, error) {
	return exec.Command("ping", h).Output()
}
