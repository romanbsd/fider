package crypto

import (
	"crypto/sha256"

	"fmt"
)

// SHA256 returns the SHA256 hash of a given string
func SHA256(input string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(input)))
}