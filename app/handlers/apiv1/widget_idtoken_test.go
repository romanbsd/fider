package apiv1

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/query"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/idtoken"
	"github.com/getfider/fider/app/pkg/jwt"
	"github.com/getfider/fider/app/pkg/mock"
	"github.com/getfider/fider/app/pkg/web"
)

func stubIDTokenClaims(claims *idtoken.Claims, provider string) func() {
	prev := verifyIDToken
	verifyIDToken = func(_ *web.Context, _ string) (*idtoken.Claims, string, error) {
		return claims, provider, nil
	}
	return func() { verifyIDToken = prev }
}

func TestMobileSignIn_IDToken_SignsInExistingUser(t *testing.T) {
	RegisterT(t)
	defer stubIDTokenClaims(&idtoken.Claims{
		UserID:        "google-sub-1",
		Email:         mock.JonSnow.Email,
		EmailVerified: true,
		Name:          mock.JonSnow.Name,
	}, "google")()
	bus.AddHandler(func(ctx context.Context, q *query.GetUserByProvider) error {
		return app.ErrNotFound
	})
	bus.AddHandler(func(ctx context.Context, q *query.GetUserByEmail) error {
		q.Result = mock.JonSnow
		return nil
	})
	bus.AddHandler(func(ctx context.Context, c *cmd.RegisterUserProvider) error {
		Expect(c.ProviderName).Equals("google")
		return nil
	})

	status, _ := mock.NewServer().
		OnTenant(mock.DemoTenant).
		ExecutePostAsJSON(MobileSignIn(), `{ "id_token": "valid-id-token" }`)

	Expect(status).Equals(http.StatusOK)
}

func TestMobileSignIn_IDToken_AppleProviderName(t *testing.T) {
	RegisterT(t)
	defer stubIDTokenClaims(&idtoken.Claims{
		UserID:        "apple-sub-1",
		Email:         mock.JonSnow.Email,
		EmailVerified: true,
		Name:          mock.JonSnow.Name,
	}, "apple")()
	bus.AddHandler(func(ctx context.Context, q *query.GetUserByProvider) error {
		return app.ErrNotFound
	})
	bus.AddHandler(func(ctx context.Context, q *query.GetUserByEmail) error {
		q.Result = mock.JonSnow
		return nil
	})
	bus.AddHandler(func(ctx context.Context, c *cmd.RegisterUserProvider) error {
		Expect(c.ProviderName).Equals("apple")
		return nil
	})

	status, _ := mock.NewServer().
		OnTenant(mock.DemoTenant).
		ExecutePostAsJSON(MobileSignIn(), `{ "id_token": "valid-id-token" }`)

	Expect(status).Equals(http.StatusOK)
}

func TestMobileSignIn_IDToken_JWTExpiresInOneDay(t *testing.T) {
	RegisterT(t)
	defer stubIDTokenClaims(&idtoken.Claims{
		UserID:        "google-sub-1",
		Email:         mock.JonSnow.Email,
		EmailVerified: true,
		Name:          mock.JonSnow.Name,
	}, "google")()

	bus.AddHandler(func(ctx context.Context, q *query.GetUserByProvider) error {
		return app.ErrNotFound
	})
	bus.AddHandler(func(ctx context.Context, q *query.GetUserByEmail) error {
		q.Result = mock.JonSnow
		return nil
	})
	bus.AddHandler(func(ctx context.Context, c *cmd.RegisterUserProvider) error {
		return nil
	})

	status, body := mock.NewServer().
		OnTenant(mock.DemoTenant).
		ExecutePostAsJSON(MobileSignIn(), `{ "id_token": "valid-id-token" }`)

	Expect(status).Equals(http.StatusOK)
	claims, err := jwt.DecodeFiderClaims(body.String("token"))
	Expect(err).IsNil()
	Expect(claims.ExpiresAt.Time.Before(time.Now().Add(idTokenJWTDuration + time.Minute))).IsTrue()
	Expect(claims.ExpiresAt.Time.After(time.Now().Add(idTokenJWTDuration - time.Hour))).IsTrue()
}
