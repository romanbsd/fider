package apiv1_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/handlers/apiv1"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/enum"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/mock"
)

func TestWidgetSignIn_NewDevice_ReturnsDeviceSecret(t *testing.T) {
	RegisterT(t)

	bus.AddHandler(func(ctx context.Context, c *cmd.UpdateWidgetTokenLastUsed) error {
		c.Result = &entity.WidgetToken{ID: 1, Hash: c.Hash}
		return nil
	})
	bus.AddHandler(func(ctx context.Context, c *cmd.RegisterDeviceUser) error {
		c.Created = true
		c.NewDeviceSecret = "brand-new-secret"
		c.Result = &entity.User{ID: 99, Name: "Widget Visitor", Role: enum.RoleVisitor, Status: enum.UserActive}
		return nil
	})

	status, query := mock.NewServer().
		OnTenant(mock.DemoTenant).
		ExecutePostAsJSON(apiv1.WidgetSignIn(), `{ "token": "raw-token", "udid": "550e8400-e29b-41d4-a716-446655440000" }`)

	Expect(status).Equals(http.StatusOK)
	Expect(query.String("device_secret")).Equals("brand-new-secret")
	Expect(query.String("token")).NotEquals("")
}

func TestWidgetSignIn_ExistingDevice_NoDeviceSecretInResponse(t *testing.T) {
	RegisterT(t)

	bus.AddHandler(func(ctx context.Context, c *cmd.UpdateWidgetTokenLastUsed) error {
		c.Result = &entity.WidgetToken{ID: 1, Hash: c.Hash}
		return nil
	})
	bus.AddHandler(func(ctx context.Context, c *cmd.RegisterDeviceUser) error {
		Expect(c.DeviceSecret).Equals("existing-secret")
		c.Created = false
		c.Result = &entity.User{ID: 99, Name: "Widget Visitor", Role: enum.RoleVisitor, Status: enum.UserActive}
		return nil
	})

	status, query := mock.NewServer().
		OnTenant(mock.DemoTenant).
		ExecutePostAsJSON(apiv1.WidgetSignIn(), `{ "token": "raw-token", "udid": "550e8400-e29b-41d4-a716-446655440000", "device_secret": "existing-secret" }`)

	Expect(status).Equals(http.StatusOK)
	Expect(query.String("device_secret")).Equals("")
}

func TestWidgetSignIn_WrongDeviceSecret_Unauthorized(t *testing.T) {
	RegisterT(t)

	bus.AddHandler(func(ctx context.Context, c *cmd.UpdateWidgetTokenLastUsed) error {
		c.Result = &entity.WidgetToken{ID: 1, Hash: c.Hash}
		return nil
	})
	bus.AddHandler(func(ctx context.Context, c *cmd.RegisterDeviceUser) error {
		return app.ErrDeviceSecretMismatch
	})

	status, _ := mock.NewServer().
		OnTenant(mock.DemoTenant).
		ExecutePostAsJSON(apiv1.WidgetSignIn(), `{ "token": "raw-token", "udid": "550e8400-e29b-41d4-a716-446655440000", "device_secret": "wrong" }`)

	Expect(status).Equals(http.StatusUnauthorized)
}
