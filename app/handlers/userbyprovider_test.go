package handlers_test

import (
	"context"
	"testing"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/handlers"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/query"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/mock"
	"github.com/getfider/fider/app/pkg/web"
)

func userByProviderLookup(ctx context.Context, q *query.GetUserByProvider) error {
	Expect(q.Provider).Equals("myprovider")
	if q.UID == "uid-known" {
		q.Result = mock.JonSnow
		return nil
	}
	return app.ErrNotFound
}

func userByEmailLookup(ctx context.Context, q *query.GetUserByEmail) error {
	if q.Email == mock.JonSnow.Email {
		q.Result = mock.JonSnow
		return nil
	}
	return app.ErrNotFound
}

func TestFindUserByProviderOrEmail_ByProvider(t *testing.T) {
	RegisterT(t)

	bus.AddHandler(userByProviderLookup)
	bus.AddHandler(userByEmailLookup)

	server := mock.NewServer()
	server.OnTenant(mock.DemoTenant)
	var result *entity.User
	var findErr error
	_, _ = server.Execute(func(c *web.Context) error {
		result, findErr = handlers.FindUserByProviderOrEmail(c, "myprovider", "uid-known", "unknown@email.com")
		return nil
	})

	Expect(findErr).IsNil()
	Expect(result).Equals(mock.JonSnow)
}

func TestFindUserByProviderOrEmail_ByEmail(t *testing.T) {
	RegisterT(t)

	bus.AddHandler(userByProviderLookup)
	bus.AddHandler(userByEmailLookup)

	server := mock.NewServer()
	server.OnTenant(mock.DemoTenant)
	var result *entity.User
	var findErr error
	_, _ = server.Execute(func(c *web.Context) error {
		result, findErr = handlers.FindUserByProviderOrEmail(c, "myprovider", "uid-unknown", mock.JonSnow.Email)
		return nil
	})

	Expect(findErr).IsNil()
	Expect(result).Equals(mock.JonSnow)
}

func TestFindUserByProviderOrEmail_NotFound(t *testing.T) {
	RegisterT(t)

	bus.AddHandler(userByProviderLookup)
	bus.AddHandler(userByEmailLookup)

	server := mock.NewServer()
	server.OnTenant(mock.DemoTenant)
	var result *entity.User
	var findErr error
	_, _ = server.Execute(func(c *web.Context) error {
		result, findErr = handlers.FindUserByProviderOrEmail(c, "myprovider", "uid-unknown", "nobody@nowhere.com")
		return nil
	})

	Expect(findErr).IsNil()
	Expect(result).IsNil()
}

func TestFindUserByProviderOrEmail_ProviderError(t *testing.T) {
	RegisterT(t)

	bus.AddHandler(func(ctx context.Context, q *query.GetUserByProvider) error {
		return errors.New("db down")
	})

	server := mock.NewServer()
	server.OnTenant(mock.DemoTenant)
	var findErr error
	_, _ = server.Execute(func(c *web.Context) error {
		_, findErr = handlers.FindUserByProviderOrEmail(c, "myprovider", "uid-known", "unknown@email.com")
		return nil
	})

	Expect(findErr).IsNotNil()
}