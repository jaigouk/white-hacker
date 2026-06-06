package m
import "os/exec"
func Run(host string) ([]byte, error) {
	return exec.Command("ping", "-c1", host).Output()
}
