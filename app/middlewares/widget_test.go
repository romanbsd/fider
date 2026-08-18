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

const testDeviceSecret = "test-device-secret"

var testDeviceUser = &entity.User{
	ID:               99,
	Name:             "Widget Visitor",
	Email:            "visitor@widget.io",
	Tenant:           mock.DemoTenant,
	Status:           enum.UserActive,
	Role:             enum.RoleVisitor,
	DeviceSecretHash: entity.HashDeviceSecret(testDeviceSecret),
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
		if q.DeviceHash == widgettoken.DeviceHash("11111111-1111-4111-8111-111111111111") {
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
		AddHeader("X-Widget-UDID", "11111111-1111-4111-8111-111111111111").
		AddHeader("X-Widget-Device-Secret", testDeviceSecret).
		Execute(func(c *web.Context) error {
			return c.String(http.StatusOK, c.User().Name)
		})

	Expect(status).Equals(http.StatusOK)
	Expect(response.Body.String()).Equals("Widget Visitor")
}

func TestWidgetAuth_WidgetToken_MissingDeviceSecret(t *testing.T) {
	RegisterT(t)
	registerWidgetBus()

	bus.AddHandler(func(ctx context.Context, q *query.GetWidgetTokenByHash) error {
		q.Result = &entity.WidgetToken{ID: 1, Hash: q.Hash}
		return nil
	})

	bus.AddHandler(func(ctx context.Context, q *query.GetUserByDeviceHash) error {
		if q.DeviceHash == widgettoken.DeviceHash("11111111-1111-4111-8111-111111111111") {
			q.Result = testDeviceUser
			return nil
		}
		return app.ErrNotFound
	})

	server := mock.NewServer()
	server.Use(middlewares.WidgetAuth())
	status, _ := server.
		OnTenant(mock.DemoTenant).
		AddHeader("X-Widget-Token", "some-raw-token").
		AddHeader("X-Widget-UDID", "11111111-1111-4111-8111-111111111111").
		Execute(func(c *web.Context) error {
			return c.NoContent(http.StatusOK)
		})

	Expect(status).Equals(http.StatusUnauthorized)
}

func TestWidgetAuth_WidgetToken_WrongDeviceSecret(t *testing.T) {
	RegisterT(t)
	registerWidgetBus()

	bus.AddHandler(func(ctx context.Context, q *query.GetWidgetTokenByHash) error {
		q.Result = &entity.WidgetToken{ID: 1, Hash: q.Hash}
		return nil
	})

	bus.AddHandler(func(ctx context.Context, q *query.GetUserByDeviceHash) error {
		if q.DeviceHash == widgettoken.DeviceHash("11111111-1111-4111-8111-111111111111") {
			q.Result = testDeviceUser
			return nil
		}
		return app.ErrNotFound
	})

	server := mock.NewServer()
	server.Use(middlewares.WidgetAuth())
	status, _ := server.
		OnTenant(mock.DemoTenant).
		AddHeader("X-Widget-Token", "some-raw-token").
		AddHeader("X-Widget-UDID", "11111111-1111-4111-8111-111111111111").
		AddHeader("X-Widget-Device-Secret", "not-the-right-secret").
		Execute(func(c *web.Context) error {
			return c.NoContent(http.StatusOK)
		})

	Expect(status).Equals(http.StatusUnauthorized)
}

func TestWidgetAuth_WidgetToken_Invalid(t *testing.T) {
	RegisterT(t)
	registerWidgetBus()

	server := mock.NewServer()
	server.Use(middlewares.WidgetAuth())
	status, _ := server.
		OnTenant(mock.DemoTenant).
		AddHeader("X-Widget-Token", "invalid-token").
		AddHeader("X-Widget-UDID", "11111111-1111-4111-8111-111111111111").
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
		AddHeader("X-Widget-UDID", "22222222-2222-4222-8222-222222222222").
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
		Origin:        jwt.FiderClaimsOriginAPI,
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

func TestWidgetRateLimit_BlockedClientDoesNotConsumeTenantCapacity(t *testing.T) {
	RegisterT(t)

	// A dedicated tenant id gives this test its own limiter buckets. The
	// per-client sign-in ceiling is WIDGET_RATE_LIMIT/4 (30 with the default
	// 120) and the tenant ceiling is WIDGET_RATE_LIMIT (120).
	busyTenant := &entity.Tenant{ID: 20, Name: "Busy", Subdomain: "busy"}

	// A fresh server per request is required (see TestWidgetRateLimit_BlocksOverLimit).
	signIn := func(clientIP string) int {
		server := mock.NewServer()
		server.Use(middlewares.WidgetRateLimit())
		status, _ := server.
			OnTenant(busyTenant).
			WithRemoteAddr(clientIP + ":1234").
			WithURL("http://busy.test.fider.io/widget/signin").
			Execute(func(c *web.Context) error {
				return c.NoContent(http.StatusOK)
			})
		return status
	}

	// Client A exhausts its own per-client budget (30 allowed requests).
	for i := 0; i < 30; i++ {
		Expect(signIn("10.0.0.1")).Equals(http.StatusOK)
	}

	// Client A keeps hammering; every request is now rejected by the per-client
	// limiter (which runs first) and must NOT consume tenant capacity.
	blocked := 0
	for i := 0; i < 100; i++ {
		if signIn("10.0.0.1") == http.StatusTooManyRequests {
			blocked++
		}
	}
	Expect(blocked).Equals(100)

	// Client B must still be served: tenant capacity was left intact by A's
	// rejected requests. With the previous ordering (tenant check first) A's
	// 100 rejected requests would have drained the shared tenant bucket and B
	// would be blocked here.
	Expect(signIn("10.0.0.2")).Equals(http.StatusOK)
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
		AddHeader("X-Widget-UDID", "11111111-1111-4111-8111-111111111111").
		Execute(func(c *web.Context) error {
			return c.NoContent(http.StatusOK)
		})

	Expect(touched).IsTrue()
}
