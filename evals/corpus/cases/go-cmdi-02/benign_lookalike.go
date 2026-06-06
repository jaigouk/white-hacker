package m
import "os/exec"
func Run2(h string) ([]byte, error) {
	return exec.Command("ping", h).Output()
}
