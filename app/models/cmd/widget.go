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

// UpdateWidgetTokenLastUsed marks a widget token as recently used
type UpdateWidgetTokenLastUsed struct {
	Hash string
}

// RegisterDeviceUser ensures a device user exists for the given device hash.
// Result holds the resolved (existing or newly created) user and Created
// reports whether a new user row was inserted.
type RegisterDeviceUser struct {
	DeviceHash string
	Name       string
	Email      string
	Result     *entity.User
	Created    bool
}