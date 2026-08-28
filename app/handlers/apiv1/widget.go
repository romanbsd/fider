package apiv1

import (
	stderrors "errors"
	"strings"
	"time"

	"github.com/getfider/fider/app/handlers"
	"github.com/getfider/fider/app/middlewares"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/dto"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/firebase"
	"github.com/getfider/fider/app/pkg/idtoken"
	"github.com/getfider/fider/app/pkg/jwt"
	"github.com/getfider/fider/app/pkg/log"
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
	IDToken         string `json:"id_token"`
	FirebaseIDToken string `json:"firebase_id_token"`
}

var errSignInUnauthorized = stderrors.New("sign-in is not authorized")

// MobileSignIn authenticates a mobile/web client via an identity-provider
// id_token and returns a Fider JWT for subsequent requests to /api/v1/*.
func MobileSignIn() web.HandlerFunc {
	return func(c *web.Context) error {
		input := new(widgetSignInInput)
		if err := c.Bind(input); err != nil {
			return c.Failure(err)
		}

		if input.IDToken == "" && input.FirebaseIDToken == "" {
			return c.BadRequest(web.Map{
				"errors": web.Map{"id_token": "id_token is required"},
			})
		}
		if input.IDToken != "" && input.FirebaseIDToken != "" {
			return c.BadRequest(web.Map{
				"errors": web.Map{"id_token": "id_token and firebase_id_token are mutually exclusive"},
			})
		}

		var (
			user *entity.User
			err  error
		)
		if input.FirebaseIDToken != "" {
			if _, appCheckErr := middlewares.RequireAppCheck(c); appCheckErr != nil {
				return c.UnauthorizedJSON()
			}
			user, err = signInByFirebaseIDToken(c, input.FirebaseIDToken)
			if err != nil {
				if stderrors.Is(err, errSignInUnauthorized) {
					return c.UnauthorizedJSON()
				}
				return c.Failure(err)
			}
		} else {
			user, err = signInByIDToken(c, input.IDToken)
			if err != nil {
				if stderrors.Is(err, errSignInUnauthorized) {
					return c.UnauthorizedJSON()
				}
				return c.HandleValidation(validate.Failed(err.Error()))
			}
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

func signInByFirebaseIDToken(c *web.Context, rawIDToken string) (*entity.User, error) {
	claims, err := firebase.VerifyIDToken(c, rawIDToken)
	if err != nil {
		log.Warnf(c, "Firebase ID token verification failed: @{Error}", dto.Props{"Error": err})
	}
	if err != nil || claims == nil || strings.TrimSpace(claims.UID) == "" {
		return nil, errSignInUnauthorized
	}

	const provider = "firebase"

	email := ""
	if claims.EmailVerified {
		email = claims.Email
	}
	if err := bus.Dispatch(c, &cmd.LockUserProviderIdentity{
		ProviderName: provider,
		ProviderUID:  claims.UID,
		Email:        email,
	}); err != nil {
		return nil, err
	}

	existing, err := handlers.FindUserByProviderOrEmail(c, provider, claims.UID, email)
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.Status != enum.UserActive {
		return nil, errSignInUnauthorized
	}
	if err := handlers.RequireProviderAdmission(c.Tenant(), existing, false); err != nil {
		return nil, errSignInUnauthorized
	}

	// Only a genuinely anonymous Firebase identity gets the "Anonymous"
	// placeholder; a nameless-but-authenticated Firebase user behaves like the
	// OIDC path and keeps an empty name rather than being mislabeled.
	name := strings.TrimSpace(claims.Name)
	nameIsPlaceholder := false
	if name == "" && claims.Anonymous {
		name = "Anonymous"
		nameIsPlaceholder = true
	}
	user, err := handlers.RegisterUserByProvider(c, c.Tenant(), existing, provider, claims.UID, name, email, nameIsPlaceholder)
	if err != nil {
		return nil, err
	}

	// Hydrate only previously empty or placeholder profile fields. Skip users
	// that are already fully populated or were created in this request.
	if existing != nil && (claims.Name != "" || email != "") &&
		(user.Name == "" || user.NameIsPlaceholder || user.Email == "") {
		hydrate := &cmd.HydrateUserIdentity{UserID: user.ID, Name: claims.Name, Email: email}
		if err := bus.Dispatch(c, hydrate); err != nil {
			return nil, err
		}
		if hydrate.Result != nil {
			user = hydrate.Result
		}
	}
	return user, nil
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

	email := ""
	if claims.EmailVerified {
		email = claims.Email
	}
	if err := bus.Dispatch(c, &cmd.LockUserProviderIdentity{
		ProviderName: provider,
		ProviderUID:  claims.UserID,
		Email:        email,
	}); err != nil {
		return nil, err
	}

	existing, err := handlers.FindUserByProviderOrEmail(c, provider, claims.UserID, claims.Email)
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.Status != enum.UserActive {
		return nil, errSignInUnauthorized
	}

	if err := handlers.RequireProviderAdmission(c.Tenant(), existing, false); err != nil {
		return nil, errSignInUnauthorized
	}
	return handlers.RegisterUserByProvider(c, c.Tenant(), existing, provider, claims.UserID, claims.Name, claims.Email, false)
}
