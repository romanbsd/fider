package middlewares_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/middlewares"
	"github.com/getfider/fider/app/models/query"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/pkg/firebase"
	"github.com/getfider/fider/app/pkg/jwt"
	"github.com/getfider/fider/app/pkg/mock"
	"github.com/getfider/fider/app/pkg/web"
)

func withAppCheckMode(mode string) func() {
	previous := env.Config.Widget.Firebase.AppCheckMode
	env.Config.Widget.Firebase.AppCheckMode = mode
	return func() { env.Config.Widget.Firebase.AppCheckMode = previous }
}

func TestAppCheck_MonitorAllowsMissingLegacyToken(t *testing.T) {
	RegisterT(t)
	defer withAppCheckMode(firebase.ModeMonitor)()

	server := mock.NewServer()
	server.Use(middlewares.WidgetAppCheck())
	status, _ := server.
		WithURL("http://demo.test.fider.io/widget/signin").
		Execute(func(c *web.Context) error { return c.NoContent(http.StatusOK) })

	Expect(status).Equals(http.StatusOK)
}

func TestAppCheck_EnforceRejectsMissingToken(t *testing.T) {
	RegisterT(t)
	defer withAppCheckMode(firebase.ModeEnforce)()

	server := mock.NewServer()
	server.Use(middlewares.WidgetAppCheck())
	status, _ := server.
		WithURL("http://demo.test.fider.io/widget/signin").
		Execute(func(c *web.Context) error { return c.NoContent(http.StatusOK) })

	Expect(status).Equals(http.StatusUnauthorized)
}

func TestAppCheck_EnforceAllowsVerifiedToken(t *testing.T) {
	RegisterT(t)
	defer withAppCheckMode(firebase.ModeEnforce)()
	defer firebase.SetVerifierForTest(firebase.StubVerifier{AppCheckClaims: &firebase.AppCheckClaims{AppID: "app-1"}})()

	server := mock.NewServer()
	server.Use(middlewares.WidgetAppCheck())
	status, _ := server.
		WithURL("http://demo.test.fider.io/widget/signin").
		AddHeader("X-Firebase-AppCheck", "valid-token").
		Execute(func(c *web.Context) error {
			claims, err := middlewares.RequireAppCheck(c)
			Expect(err).IsNil()
			Expect(claims.AppID).Equals("app-1")
			return c.NoContent(http.StatusOK)
		})

	Expect(status).Equals(http.StatusOK)
}

func TestAppCheck_EnforceRejectsSignOutWithoutToken(t *testing.T) {
	RegisterT(t)
	defer withAppCheckMode(firebase.ModeEnforce)()

	server := mock.NewServer()
	server.Use(middlewares.WidgetAppCheck())
	status, _ := server.
		WithURL("http://demo.test.fider.io/widget/signout").
		Execute(func(c *web.Context) error { return c.NoContent(http.StatusOK) })

	Expect(status).Equals(http.StatusUnauthorized)
}

func TestAppCheck_DoesNotAffectNonMobileRequest(t *testing.T) {
	RegisterT(t)
	defer withAppCheckMode(firebase.ModeEnforce)()

	server := mock.NewServer()
	server.Use(middlewares.AppCheck())
	status, _ := server.
		WithURL("http://demo.test.fider.io/").
		Execute(func(c *web.Context) error { return c.NoContent(http.StatusOK) })

	Expect(status).Equals(http.StatusOK)
}

func TestAppCheck_EnforcesAuthenticatedMobileAPIRequest(t *testing.T) {
	RegisterT(t)
	defer withAppCheckMode(firebase.ModeEnforce)()

	server := mock.NewServer()
	server.Use(func(next web.HandlerFunc) web.HandlerFunc {
		return func(c *web.Context) error {
			c.Set(app.MobileApiCtxKey, true)
			return next(c)
		}
	})
	server.Use(middlewares.AppCheck())
	status, _ := server.
		WithURL("http://demo.test.fider.io/api/v1/posts").
		Execute(func(c *web.Context) error { return c.NoContent(http.StatusOK) })

	Expect(status).Equals(http.StatusUnauthorized)
}

func TestAppCheck_EnforceComposesWithAuthenticationModes(t *testing.T) {
	RegisterT(t)
	defer withAppCheckMode(firebase.ModeEnforce)()

	uiToken, err := jwt.Encode(jwt.FiderClaims{
		UserID:   mock.JonSnow.ID,
		UserName: mock.JonSnow.Name,
	})
	Expect(err).IsNil()
	mobileToken, err := jwt.Encode(jwt.FiderClaims{
		UserID:        mock.JonSnow.ID,
		UserName:      mock.JonSnow.Name,
		UserEmail:     mock.JonSnow.Email,
		Origin:        jwt.FiderClaimsOriginAPI,
		SecurityStamp: mock.JonSnow.SecurityStamp,
	})
	Expect(err).IsNil()

	bus.AddHandler(func(_ context.Context, q *query.GetUserByID) error {
		q.Result = mock.JonSnow
		return nil
	})
	bus.AddHandler(func(_ context.Context, q *query.GetUserByAPIKey) error {
		if q.APIKey == "api-key" {
			q.Result = mock.JonSnow
			return nil
		}
		return app.ErrNotFound
	})

	tests := []struct {
		name       string
		authorize  func(*mock.Server)
		wantStatus int
	}{
		{name: "public", authorize: func(*mock.Server) {}, wantStatus: http.StatusOK},
		{name: "UI cookie", authorize: func(request *mock.Server) {
			request.AddCookie(web.CookieAuthName, uiToken)
		}, wantStatus: http.StatusOK},
		{name: "API key", authorize: func(request *mock.Server) {
			request.AddHeader("Authorization", "Bearer api-key")
		}, wantStatus: http.StatusOK},
		{name: "mobile JWT", authorize: func(request *mock.Server) {
			request.AddHeader("Authorization", "Bearer "+mobileToken)
		}, wantStatus: http.StatusUnauthorized},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := mock.NewServer()
			server.Use(middlewares.User())
			server.Use(middlewares.AppCheck())
			request := server.
				OnTenant(mock.DemoTenant).
				WithURL("http://demo.test.fider.io/api/v1/posts")
			test.authorize(request)
			status, _ := request.Execute(func(c *web.Context) error {
				return c.NoContent(http.StatusOK)
			})
			if status != test.wantStatus {
				t.Fatalf("status = %d, want %d", status, test.wantStatus)
			}
		})
	}
}

func TestWidgetAppCheck_RejectionKeepsCORSHeaders(t *testing.T) {
	RegisterT(t)
	defer withAppCheckMode(firebase.ModeEnforce)()

	server := mock.NewServer()
	server.Use(middlewares.WidgetCORS())
	server.Use(middlewares.WidgetAppCheck())
	status, response := server.
		WithURL("http://demo.test.fider.io/widget/signin").
		Execute(func(c *web.Context) error { return c.NoContent(http.StatusOK) })

	Expect(status).Equals(http.StatusUnauthorized)
	Expect(response.Header().Get("Access-Control-Allow-Origin")).Equals("*")
	Expect(response.Header().Get("Access-Control-Allow-Headers")).Equals(
		"Content-Type, Authorization, X-Firebase-AppCheck",
	)
}
