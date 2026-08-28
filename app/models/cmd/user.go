package cmd

import (
	"github.com/getfider/fider/app/models/dto"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/enum"
)

type BlockUser struct {
	UserID int
}

type UnblockUser struct {
	UserID int
}

type UntrustUser struct {
	UserID int
}

type RegenerateAPIKey struct {
	Result string
}

type DeleteCurrentUser struct {
}

type ChangeUserRole struct {
	UserID int
	Role   enum.Role
}

type ChangeUserEmail struct {
	UserID int
	Email  string
}

type UpdateCurrentUserSettings struct {
	Settings map[string]string
}

type RegisterUser struct {
	User *entity.User
}

type RegisterUserProvider struct {
	UserID       int
	ProviderName string
	ProviderUID  string
}

// LockUserProviderIdentity serializes provisioning of one external identity
// within a tenant for the duration of the current database transaction. A
// verified email, when present, is locked as well so two different provider
// UIDs sharing an email cannot race on the same Fider user.
type LockUserProviderIdentity struct {
	ProviderName string
	ProviderUID  string
	Email        string
}

// HydrateUserIdentity fills profile fields that were unavailable when an
// anonymous external identity was first provisioned.
type HydrateUserIdentity struct {
	UserID int
	Name   string
	Email  string
	Result *entity.User
}

type UpdateCurrentUser struct {
	Name       string
	AvatarType enum.AvatarType
	Avatar     *dto.ImageUpload
}

type RotateAllUserSecurityStamps struct{}
