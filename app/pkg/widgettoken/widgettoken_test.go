package widgettoken_test

import (
	"context"
	"testing"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/query"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/jwt"
	"github.com/getfider/fider/app/pkg/mock"
	"github.com/getfider/fider/app/pkg/web"
	"github.com/getfider/fider/app/pkg/widgettoken"
)

func TestValidateToken_Valid(t *testing.T) {
	RegisterT(t)

	touched := false
	bus.AddHandler(func(ctx context.Context, c *cmd.UpdateWidgetTokenLastUsed) error {
		Expect(c.Hash).Equals(entity.HashWidgetToken("raw-token"))
		touched = true
		c.Result = &entity.WidgetToken{ID: 1, Hash: c.Hash}
		return nil
	})

	server := mock.NewServer()
	server.OnTenant(mock.DemoTenant)
	var validateErr error
	_, _ = server.Execute(func(c *web.Context) error {
		validateErr = widgettoken.Validate(c, "raw-token")
		return nil
	})

	Expect(validateErr).IsNil()
	Expect(touched).IsTrue()
}

func TestValidateToken_Invalid(t *testing.T) {
	RegisterT(t)

	bus.AddHandler(func(ctx context.Context, c *cmd.UpdateWidgetTokenLastUsed) error {
		return app.ErrNotFound
	})

	server := mock.NewServer()
	server.OnTenant(mock.DemoTenant)
	var validateErr error
	_, _ = server.Execute(func(c *web.Context) error {
		validateErr = widgettoken.Validate(c, "bad-token")
		return nil
	})

	Expect(validateErr).IsNotNil()
}

func TestValidateToken_LastUsedFailure(t *testing.T) {
	RegisterT(t)

	bus.AddHandler(func(ctx context.Context, c *cmd.UpdateWidgetTokenLastUsed) error {
		return errors.New("failed to update last used")
	})

	server := mock.NewServer()
	server.OnTenant(mock.DemoTenant)
	var validateErr error
	_, _ = server.Execute(func(c *web.Context) error {
		validateErr = widgettoken.Validate(c, "raw-token")
		return nil
	})

	Expect(validateErr).IsNotNil()
	Expect(errors.Cause(validateErr).Error()).ContainsSubstring("failed to update last used")
}

func TestDeviceHash_Deterministic(t *testing.T) {
	RegisterT(t)

	first := widgettoken.DeviceHash("device-123")
	Expect(first).Equals(widgettoken.DeviceHash("device-123"))
	Expect(first).NotEquals(widgettoken.DeviceHash("device-456"))
}

func TestValidateSession(t *testing.T) {
	RegisterT(t)

	// a real-user JWT (no widget token) is always valid
	server := mock.NewServer()
	server.OnTenant(mock.DemoTenant)
	var sessionErr error
	_, _ = server.Execute(func(c *web.Context) error {
		sessionErr = widgettoken.ValidateSession(c, &jwt.WidgetClaims{})
		return nil
	})
	Expect(sessionErr).IsNil()

	// a device-user JWT with an active widget token is valid
	bus.AddHandler(func(ctx context.Context, q *query.GetWidgetTokenByHash) error {
		q.Result = &entity.WidgetToken{ID: 1, Hash: q.Hash}
		return nil
	})
	_, _ = server.Execute(func(c *web.Context) error {
		sessionErr = widgettoken.ValidateSession(c, &jwt.WidgetClaims{WidgetTokenHash: "active-hash"})
		return nil
	})
	Expect(sessionErr).IsNil()

	// a device-user JWT whose widget token was revoked is rejected
	bus.Reset()
	bus.AddHandler(func(ctx context.Context, q *query.GetWidgetTokenByHash) error {
		return app.ErrNotFound
	})
	_, _ = server.Execute(func(c *web.Context) error {
		sessionErr = widgettoken.ValidateSession(c, &jwt.WidgetClaims{WidgetTokenHash: "revoked-hash"})
		return nil
	})
	Expect(sessionErr).IsNotNil()
}
