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

func TestValidUDID(t *testing.T) {
	RegisterT(t)

	cases := []struct {
		name string
		udid string
		want bool
	}{
		{name: "valid uuid v4", udid: "550e8400-e29b-41d4-a716-446655440000", want: true},
		{name: "valid uuid v4 uppercase", udid: "550E8400-E29B-41D4-A716-446655440000", want: true},
		{
			name: "valid uuid v1",
			udid: "550e8400-e29b-11d4-a716-446655440000",
			want: true,
		},
		{name: "empty", udid: "", want: false},
		{name: "short non-uuid string within old length bounds", udid: "device-123", want: false},
		{name: "arbitrary 36-char string, not uuid shape", udid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", want: false},
		{name: "uuid missing hyphens", udid: "550e8400e29b41d4a716446655440000", want: false},
		{name: "invalid version nibble", udid: "550e8400-e29b-91d4-a716-446655440000", want: false},
		{name: "invalid variant nibble", udid: "550e8400-e29b-41d4-c716-446655440000", want: false},
	}

	for _, tc := range cases {
		if got := widgettoken.ValidUDID(tc.udid); got != tc.want {
			t.Errorf("%s: ValidUDID(%q) = %v, want %v", tc.name, tc.udid, got, tc.want)
		}
	}
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
