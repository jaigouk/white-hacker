package m
import ("math/rand"; "fmt")
func Token() string {
	return fmt.Sprintf("%d", rand.Int())  // SINK weak-rng
}
