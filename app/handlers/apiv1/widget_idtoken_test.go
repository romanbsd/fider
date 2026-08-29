package apiv1

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/firebase"
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
	bus.AddHandler(func(context.Context, *cmd.LockUserProviderIdentity) error { return nil })
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
	bus.AddHandler(func(context.Context, *cmd.LockUserProviderIdentity) error { return nil })
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

	bus.AddHandler(func(context.Context, *cmd.LockUserProviderIdentity) error { return nil })
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

func TestMobileSignIn_IDToken_RejectsBlockedExistingUser(t *testing.T) {
	RegisterT(t)
	defer stubIDTokenClaims(&idtoken.Claims{
		UserID:        "google-sub-1",
		Email:         mock.JonSnow.Email,
		EmailVerified: true,
		Name:          mock.JonSnow.Name,
	}, "google")()
	blocked := *mock.JonSnow
	blocked.Status = enum.UserBlocked

	bus.AddHandler(func(context.Context, *cmd.LockUserProviderIdentity) error { return nil })
	bus.AddHandler(func(_ context.Context, q *query.GetUserByProvider) error {
		q.Result = &blocked
		return nil
	})

	status, _ := mock.NewServer().
		OnTenant(mock.DemoTenant).
		ExecutePostAsJSON(MobileSignIn(), `{ "id_token": "valid-id-token" }`)

	Expect(status).Equals(http.StatusUnauthorized)
}

func TestMobileSignIn_IDToken_RejectsNewUserOnPrivateTenant(t *testing.T) {
	RegisterT(t)
	defer stubIDTokenClaims(&idtoken.Claims{
		UserID:        "google-sub-1",
		Email:         "new-user@example.com",
		EmailVerified: true,
		Name:          "New User",
	}, "google")()
	privateTenant := *mock.DemoTenant
	privateTenant.IsPrivate = true

	bus.AddHandler(func(context.Context, *cmd.LockUserProviderIdentity) error { return nil })
	bus.AddHandler(func(context.Context, *query.GetUserByProvider) error { return app.ErrNotFound })
	bus.AddHandler(func(context.Context, *query.GetUserByEmail) error { return app.ErrNotFound })

	status, _ := mock.NewServer().
		OnTenant(&privateTenant).
		ExecutePostAsJSON(MobileSignIn(), `{ "id_token": "valid-id-token" }`)

	Expect(status).Equals(http.StatusUnauthorized)
}

func TestMobileSignIn_Firebase_ProvisionsAnonymousUser(t *testing.T) {
	RegisterT(t)
	defer firebase.SetVerifierForTest(firebase.StubVerifier{
		AppCheckClaims: &firebase.AppCheckClaims{AppID: "app-1"},
		AuthClaims:     &firebase.AuthClaims{UID: "firebase-user-1", Anonymous: true},
	})()

	bus.AddHandler(func(context.Context, *cmd.LockUserProviderIdentity) error { return nil })
	bus.AddHandler(func(context.Context, *query.GetUserByProvider) error { return app.ErrNotFound })
	bus.AddHandler(func(_ context.Context, c *cmd.RegisterUser) error {
		Expect(c.User.Name).Equals("Anonymous")
		Expect(c.User.Email).Equals("")
		Expect(c.User.Role).Equals(enum.RoleVisitor)
		Expect(c.User.Providers).HasLen(1)
		Expect(c.User.Providers[0].Name).Equals("firebase")
		Expect(c.User.Providers[0].UID).Equals("firebase-user-1")
		c.User.ID = 101
		c.User.SecurityStamp = "stamp"
		return nil
	})

	status, body := mock.NewServer().
		OnTenant(mock.DemoTenant).
		AddHeader("X-Firebase-AppCheck", "valid-app-check").
		ExecutePostAsJSON(MobileSignIn(), `{ "firebase_id_token": "valid-firebase-token" }`)

	Expect(status).Equals(http.StatusOK)
	Expect(body.Int32("user.id")).Equals(101)
	claims, err := jwt.DecodeFiderClaims(body.String("token"))
	Expect(err).IsNil()
	Expect(claims.UserID).Equals(101)
}

func TestMobileSignIn_Firebase_LinksExistingUserByVerifiedEmail(t *testing.T) {
	RegisterT(t)
	defer firebase.SetVerifierForTest(firebase.StubVerifier{
		AppCheckClaims: &firebase.AppCheckClaims{AppID: "app-1"},
		AuthClaims: &firebase.AuthClaims{
			UID:           "firebase-user-1",
			Name:          mock.JonSnow.Name,
			Email:         mock.JonSnow.Email,
			EmailVerified: true,
		},
	})()

	bus.AddHandler(func(context.Context, *cmd.LockUserProviderIdentity) error { return nil })
	bus.AddHandler(func(context.Context, *query.GetUserByProvider) error { return app.ErrNotFound })
	bus.AddHandler(func(_ context.Context, q *query.GetUserByEmail) error {
		Expect(q.Email).Equals(mock.JonSnow.Email)
		q.Result = mock.JonSnow
		return nil
	})
	bus.AddHandler(func(_ context.Context, c *cmd.RegisterUserProvider) error {
		Expect(c.UserID).Equals(mock.JonSnow.ID)
		Expect(c.ProviderName).Equals("firebase")
		Expect(c.ProviderUID).Equals("firebase-user-1")
		return nil
	})
	bus.AddHandler(func(_ context.Context, c *cmd.HydrateUserIdentity) error {
		c.Result = mock.JonSnow
		return nil
	})

	status, body := mock.NewServer().
		OnTenant(mock.DemoTenant).
		AddHeader("X-Firebase-AppCheck", "valid-app-check").
		ExecutePostAsJSON(MobileSignIn(), `{ "firebase_id_token": "valid-firebase-token" }`)

	Expect(status).Equals(http.StatusOK)
	Expect(body.Int32("user.id")).Equals(mock.JonSnow.ID)
}

func TestMobileSignIn_Firebase_RequiresValidAppCheck(t *testing.T) {
	RegisterT(t)
	defer firebase.SetVerifierForTest(firebase.StubVerifier{AppCheckErr: errors.New("invalid")})()

	status, _ := mock.NewServer().
		OnTenant(mock.DemoTenant).
		AddHeader("X-Firebase-AppCheck", "invalid-app-check").
		ExecutePostAsJSON(MobileSignIn(), `{ "firebase_id_token": "valid-firebase-token" }`)

	Expect(status).Equals(http.StatusUnauthorized)
}

func TestMobileSignIn_Firebase_RejectsMissingAuthClaims(t *testing.T) {
	RegisterT(t)
	defer firebase.SetVerifierForTest(firebase.StubVerifier{
		AppCheckClaims: &firebase.AppCheckClaims{AppID: "app-1"},
	})()

	status, _ := mock.NewServer().
		OnTenant(mock.DemoTenant).
		AddHeader("X-Firebase-AppCheck", "valid-app-check").
		ExecutePostAsJSON(MobileSignIn(), `{ "firebase_id_token": "invalid-firebase-token" }`)

	Expect(status).Equals(http.StatusUnauthorized)
}

func TestMobileSignIn_Firebase_DoesNotMaskProvisioningFailure(t *testing.T) {
	RegisterT(t)
	defer firebase.SetVerifierForTest(firebase.StubVerifier{
		AppCheckClaims: &firebase.AppCheckClaims{AppID: "app-1"},
		AuthClaims:     &firebase.AuthClaims{UID: "firebase-user-1", Anonymous: true},
	})()

	bus.AddHandler(func(context.Context, *cmd.LockUserProviderIdentity) error {
		return errors.New("database unavailable")
	})

	status, _ := mock.NewServer().
		OnTenant(mock.DemoTenant).
		AddHeader("X-Firebase-AppCheck", "valid-app-check").
		ExecutePost(MobileSignIn(), `{ "firebase_id_token": "valid-firebase-token" }`)

	Expect(status).Equals(http.StatusInternalServerError)
}

func TestMobileSignIn_Firebase_RejectsNewAnonymousUserOnPrivateTenant(t *testing.T) {
	RegisterT(t)
	defer firebase.SetVerifierForTest(firebase.StubVerifier{
		AppCheckClaims: &firebase.AppCheckClaims{AppID: "app-1"},
		AuthClaims:     &firebase.AuthClaims{UID: "firebase-user-1", Anonymous: true},
	})()
	privateTenant := *mock.DemoTenant
	privateTenant.IsPrivate = true

	bus.AddHandler(func(context.Context, *cmd.LockUserProviderIdentity) error { return nil })
	bus.AddHandler(func(context.Context, *query.GetUserByProvider) error { return app.ErrNotFound })

	status, _ := mock.NewServer().
		OnTenant(&privateTenant).
		AddHeader("X-Firebase-AppCheck", "valid-app-check").
		ExecutePostAsJSON(MobileSignIn(), `{ "firebase_id_token": "valid-firebase-token" }`)

	Expect(status).Equals(http.StatusUnauthorized)
}

func TestMobileSignIn_Firebase_RejectsBlockedExistingUser(t *testing.T) {
	RegisterT(t)
	defer firebase.SetVerifierForTest(firebase.StubVerifier{
		AppCheckClaims: &firebase.AppCheckClaims{AppID: "app-1"},
		AuthClaims:     &firebase.AuthClaims{UID: "firebase-user-1"},
	})()
	blocked := *mock.JonSnow
	blocked.Status = enum.UserBlocked

	bus.AddHandler(func(context.Context, *cmd.LockUserProviderIdentity) error { return nil })
	bus.AddHandler(func(_ context.Context, q *query.GetUserByProvider) error {
		q.Result = &blocked
		return nil
	})

	status, _ := mock.NewServer().
		OnTenant(mock.DemoTenant).
		AddHeader("X-Firebase-AppCheck", "valid-app-check").
		ExecutePostAsJSON(MobileSignIn(), `{ "firebase_id_token": "valid-firebase-token" }`)

	Expect(status).Equals(http.StatusUnauthorized)
}

func TestMobileSignIn_RejectsMultipleCredentialTypes(t *testing.T) {
	RegisterT(t)
	status, _ := mock.NewServer().OnTenant(mock.DemoTenant).ExecutePostAsJSON(
		MobileSignIn(),
		`{ "id_token": "oidc", "firebase_id_token": "firebase" }`,
	)
	Expect(status).Equals(http.StatusBadRequest)
}
