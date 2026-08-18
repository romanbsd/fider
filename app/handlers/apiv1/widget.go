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

var idTokenValidator = idtoken.New(idtoken.Config{
	JWKSURL:  env.Config.Widget.IdToken.JWKSURL,
	Issuer:   env.Config.Widget.IdToken.Issuer,
	ClientID: env.Config.Widget.IdToken.ClientID,
})

const (
	// idTokenJWTDuration is the lifetime of a mobile JWT issued from an
	// identity-provider (Google/Apple) id_token.
	idTokenJWTDuration = 24 * time.Hour
)

// verifyIDToken is the identity-provider check used by sign-in. Tests stub it
// so they can exercise the sign-in flow without standing up a JWKS endpoint.
var verifyIDToken = func(c *web.Context, rawIDToken string) (*idtoken.Claims, error) {
	if !idTokenValidator.IsConfigured() {
		return nil, errors.New("Identity provider sign in is not enabled")
	}
	claims, err := idTokenValidator.Verify(c, rawIDToken)
	if err != nil {
		return nil, errors.New("Invalid id_token")
	}
	if !claims.EmailVerified {
		return nil, errors.New("id_token email is not verified")
	}
	return claims, nil
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
	claims, err := verifyIDToken(c, rawIDToken)
	if err != nil {
		return nil, err
	}

	const provider = "idtoken"

	existing, err := handlers.FindUserByProviderOrEmail(c, provider, claims.UserID, claims.Email)
	if err != nil {
		return nil, err
	}

	if err := handlers.RequireProviderAdmission(c.Tenant(), existing, false); err != nil {
		return nil, err
	}
	return handlers.RegisterUserByProvider(c, c.Tenant(), existing, provider, claims.UserID, claims.Name, claims.Email)
}
