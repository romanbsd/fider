package crypto_test

import (
	"testing"

	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/crypto"
)

func TestSHA256Hash(t *testing.T) {
	RegisterT(t)

	hash := crypto.SHA256("Fider")

	Expect(hash).Equals("198dc582102b47e73068acab643f03dbb91f20fae57d89cd98b40c45a25af591")
}