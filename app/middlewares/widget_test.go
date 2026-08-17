package middlewares_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/middlewares"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/jwt"
	"github.com/getfider/fider/app/pkg/mock"
	"github.com/getfider/fider/app/pkg/web"
	"github.com/getfider/fider/app/pkg/widgettoken"
)

var testDeviceUser = &entity.User{
	ID:     99,
	Name:   "Widget Visitor",
	Email:  "visitor@widget.io",
	Tenant: mock.DemoTenant,
	Status: enum.UserActive,
	Role:   enum.RoleVisitor,
}

func registerWidgetBus() {
	bus.AddHandler(func(ctx context.Context, q *query.GetWidgetTokenByHash) error {
		return app.ErrNotFound
	})
	bus.AddHandler(func(ctx context.Context, q *query.GetUserByDeviceHash) error {
		return app.ErrNotFound
	})
	bus.AddHandler(func(ctx context.Context, c *cmd.UpdateWidgetTokenLastUsed) error {
		return nil
	})
}

func TestWidgetAuth_NoCredentials(t *testing.T) {
	RegisterT(t)
	registerWidgetBus()

	server := mock.NewServer()
	server.Use(middlewares.WidgetAuth())
	status, _ := server.
		OnTenant(mock.DemoTenant).
		Execute(func(c *web.Context) error {
			return c.NoContent(http.StatusOK)
		})

	Expect(status).Equals(http.StatusUnauthorized)
}

func TestWidgetAuth_WidgetToken(t *testing.T) {
	RegisterT(t)
	registerWidgetBus()

	bus.AddHandler(func(ctx context.Context, q *query.GetWidgetTokenByHash) error {
		q.Result = &entity.WidgetToken{ID: 1, Hash: q.Hash}
		return nil
	})

	bus.AddHandler(func(ctx context.Context, q *query.GetUserByDeviceHash) error {
		if q.DeviceHash == widgettoken.DeviceHash("device-0x123") {
			q.Result = testDeviceUser
			return nil
		}
		return app.ErrNotFound
	})

	server := mock.NewServer()
	server.Use(middlewares.WidgetAuth())
	status, response := server.
		OnTenant(mock.DemoTenant).
		AddHeader("X-Widget-Token", "some-raw-token").
		AddHeader("X-Widget-UDID", "device-0x123").
		Execute(func(c *web.Context) error {
			return c.String(http.StatusOK, c.User().Name)
		})

	Expect(status).Equals(http.StatusOK)
	Expect(response.Body.String()).Equals("Widget Visitor")
}

func TestWidgetAuth_WidgetToken_Invalid(t *testing.T) {
	RegisterT(t)
	registerWidgetBus()

	server := mock.NewServer()
	server.Use(middlewares.WidgetAuth())
	status, _ := server.
		OnTenant(mock.DemoTenant).
		AddHeader("X-Widget-Token", "invalid-token").
		AddHeader("X-Widget-UDID", "device-0x123").
		Execute(func(c *web.Context) error {
			return c.NoContent(http.StatusOK)
		})

	Expect(status).Equals(http.StatusUnauthorized)
}

func TestWidgetAuth_WidgetToken_MissingUDID(t *testing.T) {
	RegisterT(t)
	registerWidgetBus()

	server := mock.NewServer()
	server.Use(middlewares.WidgetAuth())
	status, _ := server.
		OnTenant(mock.DemoTenant).
		AddHeader("X-Widget-Token", "some-raw-token").
		Execute(func(c *web.Context) error {
			return c.NoContent(http.StatusOK)
		})

	Expect(status).Equals(http.StatusUnauthorized)
}

func TestWidgetAuth_WidgetToken_DeviceNotFound(t *testing.T) {
	RegisterT(t)
	registerWidgetBus()

	bus.AddHandler(func(ctx context.Context, q *query.GetWidgetTokenByHash) error {
		q.Result = &entity.WidgetToken{ID: 1, Hash: q.Hash}
		return nil
	})

	server := mock.NewServer()
	server.Use(middlewares.WidgetAuth())
	status, _ := server.
		OnTenant(mock.DemoTenant).
		AddHeader("X-Widget-Token", "some-raw-token").
		AddHeader("X-Widget-UDID", "unknown-device").
		Execute(func(c *web.Context) error {
			return c.NoContent(http.StatusOK)
		})

	Expect(status).Equals(http.StatusUnauthorized)
}

func TestWidgetAuth_MobileJWT(t *testing.T) {
	RegisterT(t)
	registerWidgetBus()

	mobileUser := &entity.User{
		ID:            mock.JonSnow.ID,
		Name:          mock.JonSnow.Name,
		Email:         mock.JonSnow.Email,
		Tenant:        mock.DemoTenant,
		Status:        enum.UserActive,
		Role:          enum.RoleAdministrator,
		SecurityStamp: "stamp-1",
		Providers:     mock.JonSnow.Providers,
	}

	token, _ := jwt.Encode(jwt.FiderClaims{
		UserID:        mobileUser.ID,
		UserName:      mobileUser.Name,
		SecurityStamp: mobileUser.SecurityStamp,
	})

	bus.AddHandler(func(ctx context.Context, q *query.GetUserByID) error {
		if q.UserID == mobileUser.ID {
			q.Result = mobileUser
			return nil
		}
		return app.ErrNotFound
	})

	server := mock.NewServer()
	server.Use(middlewares.WidgetAuth())
	status, response := server.
		OnTenant(mock.DemoTenant).
		AddHeader("Authorization", "Bearer "+token).
		Execute(func(c *web.Context) error {
			return c.String(http.StatusOK, c.User().Name)
		})

	Expect(status).Equals(http.StatusOK)
	Expect(response.Body.String()).Equals("Jon Snow")
}

func TestWidgetAuth_MobileJWT_Invalid(t *testing.T) {
	RegisterT(t)
	registerWidgetBus()

	server := mock.NewServer()
	server.Use(middlewares.WidgetAuth())
	status, _ := server.
		OnTenant(mock.DemoTenant).
		AddHeader("Authorization", "Bearer not-a-valid-jwt").
		Execute(func(c *web.Context) error {
			return c.NoContent(http.StatusOK)
		})

	Expect(status).Equals(http.StatusUnauthorized)
}

func TestWidgetAuth_SignInEndpoint(t *testing.T) {
	RegisterT(t)
	registerWidgetBus()

	server := mock.NewServer()
	server.Use(middlewares.WidgetAuth())
	status, _ := server.
		OnTenant(mock.DemoTenant).
		WithURL("http://demo.test.fider.io/widget/signin").
		Execute(func(c *web.Context) error {
			return c.NoContent(http.StatusOK)
		})

	Expect(status).Equals(http.StatusOK)
}

func TestWidgetRateLimit_AllowsWithinLimit(t *testing.T) {
	RegisterT(t)

	server := mock.NewServer()
	server.Use(middlewares.WidgetRateLimit())

	for i := 0; i < 3; i++ {
		status, _ := server.
			OnTenant(mock.DemoTenant).
			Execute(func(c *web.Context) error {
				return c.NoContent(http.StatusOK)
			})
		Expect(status).Equals(http.StatusOK)
	}
}

func TestWidgetRateLimit_BlocksOverLimit(t *testing.T) {
	RegisterT(t)

	// A dedicated tenant id gives this test its own limiter bucket
	busyTenant := &entity.Tenant{ID: 10, Name: "Busy", Subdomain: "busy"}

	blocked := false
	for i := 0; i < 125; i++ {
		// A fresh server per request is required: mock.Server reuses a single
		// httptest.ResponseRecorder across Execute calls, so a 429 written on a
		// recorder that already wrote 200 would be ignored and reported as 200.
		server := mock.NewServer()
		server.Use(middlewares.WidgetRateLimit())
		status, _ := server.
			OnTenant(busyTenant).
			Execute(func(c *web.Context) error {
				return c.NoContent(http.StatusOK)
			})
		if status == http.StatusTooManyRequests {
			blocked = true
			break
		}
	}

	Expect(blocked).IsTrue()
}

func TestWidgetAuth_TracksLastUsed(t *testing.T) {
	RegisterT(t)
	registerWidgetBus()

	touched := false
	bus.AddHandler(func(ctx context.Context, c *cmd.UpdateWidgetTokenLastUsed) error {
		touched = true
		return nil
	})
	bus.AddHandler(func(ctx context.Context, q *query.GetWidgetTokenByHash) error {
		q.Result = &entity.WidgetToken{ID: 1, Hash: q.Hash}
		return nil
	})
	bus.AddHandler(func(ctx context.Context, q *query.GetUserByDeviceHash) error {
		q.Result = testDeviceUser
		return nil
	})

	server := mock.NewServer()
	server.Use(middlewares.WidgetAuth())
	_, _ = server.
		OnTenant(mock.DemoTenant).
		AddHeader("X-Widget-Token", "some-raw-token").
		AddHeader("X-Widget-UDID", "device-0x123").
		Execute(func(c *web.Context) error {
			return c.NoContent(http.StatusOK)
		})

	Expect(touched).IsTrue()
}