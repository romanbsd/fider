package entity

import (
	"encoding/json"

	"github.com/getfider/fider/app/models/enum"
)

// User represents an user inside our application
type User struct {
	ID            int             `json:"id"`
	Name          string          `json:"name"`
	Tenant        *Tenant         `json:"-"`
	Email         string          `json:"-"`
	Role          enum.Role       `json:"role"`
	Providers     []*UserProvider `json:"-"`
	AvatarBlobKey string          `json:"-"`
	AvatarType    enum.AvatarType `json:"-"`
	AvatarURL     string          `json:"avatarURL,omitempty"`
	Status        enum.UserStatus `json:"status"`
	IsTrusted     bool            `json:"isTrusted"`
	SecurityStamp string          `json:"-"`
	// DeviceSecretHash is set only for widget/mobile device-registered users:
	// the hash of the per-device secret issued at first sign-in, required to
	// re-authenticate that device on later sign-ins (see
	// docs/MOBILE_FEEDBACK_API.md §4.4). Empty for every other user.
	DeviceSecretHash string `json:"-"`
}

// HasProvider returns true if current user has registered with given provider
func (u *User) HasProvider(provider string) bool {
	for _, p := range u.Providers {
		if p.Name == provider {
			return true
		}
	}
	return false
}

// IsCollaborator returns true if user has special permissions
func (u *User) IsCollaborator() bool {
	return u.Role == enum.RoleCollaborator || u.Role == enum.RoleAdministrator
}

// IsAdministrator returns true if user is administrator
func (u *User) IsAdministrator() bool {
	return u.Role == enum.RoleAdministrator
}

// RequiresModeration returns true if user requires moderation
func (u *User) RequiresModeration() bool {
	return u.Role == enum.RoleVisitor && !u.IsTrusted
}

// UserProvider represents the relationship between an User and an Authentication provide
type UserProvider struct {
	Name string
	UID  string
}

// UserWithEmail is a wrapper around User that includes the email field when marshaling to JSON
type UserWithEmail struct {
	*User
}

func (umc UserWithEmail) MarshalJSON() ([]byte, error) {
	type Alias User // Prevent recursion
	return json.Marshal(&struct {
		*Alias
		Email string `json:"email"`
	}{
		Alias: (*Alias)(umc.User),
		Email: umc.Email,
	})
}
