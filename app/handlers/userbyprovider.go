package handlers

import (
	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/web"
)

// FindUserByProviderOrEmail looks up an existing user by identity provider UID,
// then by email. Returns nil, nil when no user matches.
func FindUserByProviderOrEmail(c *web.Context, provider, uid, email string) (*entity.User, error) {
	getByProvider := &query.GetUserByProvider{Provider: provider, UID: uid}
	if err := bus.Dispatch(c, getByProvider); err != nil {
		if errors.Cause(err) != app.ErrNotFound {
			return nil, err
		}
	} else if getByProvider.Result != nil {
		return getByProvider.Result, nil
	}

	if email == "" {
		return nil, nil
	}

	getByEmail := &query.GetUserByEmail{Email: email}
	if err := bus.Dispatch(c, getByEmail); err != nil {
		if errors.Cause(err) != app.ErrNotFound {
			return nil, err
		}
	} else if getByEmail.Result != nil {
		return getByEmail.Result, nil
	}

	return nil, nil
}

// RegisterUserByProvider links a user authenticated by an identity provider to
// Fider. When the user does not exist yet (by provider UID, then by email) a new
// Visitor user is created; otherwise the provider is attached to the existing
// user. Returns the linked user.
func RegisterUserByProvider(c *web.Context, tenant *entity.Tenant, existing *entity.User, provider, uid, name, email string) (*entity.User, error) {
	user := existing
	if user == nil {
		byProvider, err := FindUserByProviderOrEmail(c, provider, uid, email)
		if err != nil {
			return nil, err
		}
		user = byProvider
	}

	if user == nil {
		user = &entity.User{
			Tenant:    tenant,
			Name:      name,
			Email:     email,
			Role:      enum.RoleVisitor,
			Providers: []*entity.UserProvider{{UID: uid, Name: provider}},
		}
		if err := bus.Dispatch(c, &cmd.RegisterUser{User: user}); err != nil {
			return nil, err
		}
	} else if !user.HasProvider(provider) {
		if err := bus.Dispatch(c, &cmd.RegisterUserProvider{
			UserID:       user.ID,
			ProviderName: provider,
			ProviderUID:  uid,
		}); err != nil {
			return nil, err
		}
	}

	return user, nil
}