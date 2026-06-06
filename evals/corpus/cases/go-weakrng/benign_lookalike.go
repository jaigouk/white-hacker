package m
import ("crypto/rand"; "encoding/hex")
func Token() string {
	b := make([]byte, 16); rand.Read(b); return hex.EncodeToString(b)
}
