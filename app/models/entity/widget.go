package entity

import (
	"time"

	"github.com/getfider/fider/app/pkg/crypto"
	"github.com/getfider/fider/app/pkg/rand"
)

// WidgetToken represents a token used by the feedback widget to authenticate requests
type WidgetToken struct {
	ID         int        `json:"id"`
	Label      string     `json:"label"`
	Hash       string     `json:"-"`
	RawToken   string     `json:"-"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	RevokedAt  *time.Time `json:"revokedAt"`
}

// GenerateWidgetToken returns a new raw widget token
func GenerateWidgetToken() string {
	return rand.String(32)
}

// HashWidgetToken returns the sha256 hash of a raw widget token
func HashWidgetToken(token string) string {
	return crypto.SHA256(token)
}

// GenerateDeviceSecret returns a new raw per-device secret, issued once at a
// device's first widget sign-in and required to re-authenticate that same
// device afterwards (proof of possession beyond the shared tenant widget
// token, which every device of a tenant uses).
func GenerateDeviceSecret() string {
	return rand.String(32)
}

// HashDeviceSecret returns the sha256 hash of a raw device secret
func HashDeviceSecret(secret string) string {
	return crypto.SHA256(secret)
}
