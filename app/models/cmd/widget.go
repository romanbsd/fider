package cmd

import (
	"github.com/getfider/fider/app/models/entity"
)

// CreateWidgetToken creates a new widget sign-in token for the current tenant
type CreateWidgetToken struct {
	Label  string
	Result *entity.WidgetToken
}

// RevokeWidgetToken revokes an existing widget token
type RevokeWidgetToken struct {
	TokenID int
}

// UpdateWidgetTokenLastUsed marks a widget token as recently used. Result is
// set only when the token exists and is not revoked; otherwise the command
// fails with app.ErrNotFound.
type UpdateWidgetTokenLastUsed struct {
	Hash   string
	Result *entity.WidgetToken
}

// RegisterDeviceUser ensures a device user exists for the given device hash.
// Result holds the resolved (existing or newly created) user and Created
// reports whether a new user row was inserted.
//
// A first registration (no existing device_hash row) always succeeds and
// returns a freshly generated NewDeviceSecret the caller must store and
// present on every later sign-in for that device. Re-authenticating an
// existing device requires DeviceSecret to match what was issued at its
// first registration (fails with app.ErrDeviceSecretMismatch otherwise) —
// without this, the shared tenant widget token alone would let any holder
// authenticate as any known device_hash.
type RegisterDeviceUser struct {
	DeviceHash string
	Name       string
	// Email is accepted for compatibility with the sign-in payload but is never
	// persisted: it is unverified client input and users.email is an identity key.
	Email           string
	DeviceSecret    string
	Result          *entity.User
	Created         bool
	NewDeviceSecret string
}
