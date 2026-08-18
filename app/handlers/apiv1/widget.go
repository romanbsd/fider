package apiv1

import (
	"time"

	"github.com/getfider/fider/app/handlers"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/idtoken"
	"github.com/getfider/fider/app/pkg/jwt"
	"github.com/getfider/fider/app/pkg/validate"
	"github.com/getfider/fider/app/pkg/web"
)

// idTokenSource pairs an id_token validator with the provider identity it
// verifies tokens for. The provider name is stored with the user (user_providers)
// so Google and Apple identities stay separate and match the regular OAuth
// identities of the same providers. A provider may contribute more than one
// source: Apple signs in with different aud claims for the native app (App ID)
// and the web (Services ID), so each gets its own validator.
type idTokenSource struct {
	provider  string
	validator *idtoken.Validator
}

// idTokenSources lists every fully configured identity provider. It is built
// once at init: validators allocate an HTTP client and key cache each, so
// rebuilding on every sign-in would waste a client plus map per request.
var idTokenSources = func() []idTokenSource {
	providers := []struct {
		name string
		cfg  idtoken.Config
	}{
		{"google", idtoken.Config{
			JWKSURL:  env.Config.Widget.IdToken.Google.JWKSURL,
			Issuer:   env.Config.Widget.IdToken.Google.Issuer,
			ClientID: env.Config.Widget.IdToken.Google.ClientID,
		}},
		{"apple", idtoken.Config{
			JWKSURL:  env.Config.Widget.IdToken.Apple.JWKSURL,
			Issuer:   env.Config.Widget.IdToken.Apple.Issuer,
			ClientID: env.Config.Widget.IdToken.Apple.AppID,
		}},
		{"apple", idtoken.Config{
			JWKSURL:  env.Config.Widget.IdToken.Apple.JWKSURL,
			Issuer:   env.Config.Widget.IdToken.Apple.Issuer,
			ClientID: env.Config.Widget.IdToken.Apple.ServicesID,
		}},
	}
	var sources []idTokenSource
	for _, p := range providers {
		if v := idtoken.New(p.cfg); v.IsConfigured() {
			sources = append(sources, idTokenSource{provider: p.name, validator: v})
		}
	}
	return sources
}()

const (
	// idTokenJWTDuration is the lifetime of a mobile JWT issued from an
	// identity-provider (Google/Apple) id_token.
	idTokenJWTDuration = 24 * time.Hour
)

// verifyIDToken is the identity-provider check used by sign-in: each configured
// provider is tried until one verifies the token (the token's iss/aud match at
// most one). It returns the claims and the name of the provider that accepted
// the token. Tests stub it so they can exercise the sign-in flow without
// standing up a JWKS endpoint.
var verifyIDToken = func(c *web.Context, rawIDToken string) (*idtoken.Claims, string, error) {
	if len(idTokenSources) == 0 {
		return nil, "", errors.New("Identity provider sign in is not enabled")
	}
	for _, src := range idTokenSources {
		claims, err := src.validator.Verify(c, rawIDToken)
		if err != nil {
			continue
		}
		if !claims.EmailVerified {
			return nil, "", errors.New("id_token email is not verified")
		}
		return claims, src.provider, nil
	}
	return nil, "", errors.New("Invalid id_token")
}

type widgetSignInInput struct {
	IDToken string `json:"id_token"`
}

// MobileSignIn authenticates a mobile/web client via an identity-provider
// id_token and returns a Fider JWT for subsequent requests to /api/v1/*.
func MobileSignIn() web.HandlerFunc {
	return func(c *web.Context) error {
		input := new(widgetSignInInput)
		if err := c.Bind(input); err != nil {
			return c.Failure(err)
		}

		if input.IDToken == "" {
			return c.BadRequest(web.Map{
				"errors": web.Map{"id_token": "id_token is required"},
			})
		}

		user, err := signInByIDToken(c, input.IDToken)
		if err != nil {
			return c.HandleValidation(validate.Failed(err.Error()))
		}

		token, err := jwt.Encode(jwt.FiderClaims{
			UserID:        user.ID,
			UserName:      user.Name,
			UserEmail:     user.Email,
			Origin:        jwt.FiderClaimsOriginAPI,
			SecurityStamp: user.SecurityStamp,
			Metadata: jwt.Metadata{
				ExpiresAt: jwt.Time(time.Now().Add(idTokenJWTDuration)),
			},
		})
		if err != nil {
			return c.Failure(err)
		}

		return c.Ok(web.Map{
			"token": token,
			"user":  user,
		})
	}
}

// MobileSignOut acknowledges the sign out request. The server keeps nothing
// per-session and does NOT invalidate the issued JWT: rotating the user's
// security stamp here would log the user out everywhere (browser UI, other
// devices). Sign-out is client-side only — the client must discard its stored
// JWT, and the 24h token expires on its own.
func MobileSignOut() web.HandlerFunc {
	return func(c *web.Context) error {
		return c.Ok(web.Map{})
	}
}

func signInByIDToken(c *web.Context, rawIDToken string) (*entity.User, error) {
	claims, provider, err := verifyIDToken(c, rawIDToken)
	if err != nil {
		return nil, err
	}

	existing, err := handlers.FindUserByProviderOrEmail(c, provider, claims.UserID, claims.Email)
	if err != nil {
		return nil, err
	}

	if err := handlers.RequireProviderAdmission(c.Tenant(), existing, false); err != nil {
		return nil, err
	}
	return handlers.RegisterUserByProvider(c, c.Tenant(), existing, provider, claims.UserID, claims.Name, claims.Email)
}
