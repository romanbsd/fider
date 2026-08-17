package apiv1

import (
	"time"

	"github.com/getfider/fider/app/handlers"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/idtoken"
	"github.com/getfider/fider/app/pkg/jwt"
	"github.com/getfider/fider/app/pkg/validate"
	"github.com/getfider/fider/app/pkg/web"
	"github.com/getfider/fider/app/pkg/widgettoken"
)

var idTokenValidator = idtoken.New(idtoken.Config{
	JWKSURL:  env.Config.Widget.IdToken.JWKSURL,
	Issuer:   env.Config.Widget.IdToken.Issuer,
	ClientID: env.Config.Widget.IdToken.ClientID,
})

type widgetSignInInput struct {
	Token   string `json:"token"`
	UDID    string `json:"udid"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	IDToken string `json:"id_token"`
	// DeviceSecret is required to re-authenticate an already-registered
	// device (returned as device_secret in the response to that device's
	// first sign-in); empty for a device's first sign-in.
	DeviceSecret string `json:"device_secret"`
}

// WidgetSignIn authenticates a feedback widget device (or a mobile client via an
// identity provider token) and returns a Fider JWT for subsequent requests
func WidgetSignIn() web.HandlerFunc {
	return func(c *web.Context) error {
		input := new(widgetSignInInput)
		if err := c.Bind(input); err != nil {
			return c.Failure(err)
		}

		var (
			user            *entity.User
			widgetHash      string
			newDeviceSecret string
		)
		if input.IDToken != "" {
			u, err := signInByIDToken(c, input.IDToken)
			if err != nil {
				return c.HandleValidation(validate.Failed(err.Error()))
			}
			user = u
		} else {
			if input.Token == "" || !widgettoken.ValidUDID(input.UDID) {
				return c.BadRequest(web.Map{
					"errors": web.Map{"token": "token is required, udid must be a valid UUID"},
				})
			}
			u, secret, err := signInByWidgetToken(c, input)
			if err != nil {
				return c.Unauthorized()
			}
			user = u
			widgetHash = entity.HashWidgetToken(input.Token)
			newDeviceSecret = secret
		}

		token, err := jwt.Encode(jwt.WidgetClaims{
			FiderClaims: jwt.FiderClaims{
				UserID:        user.ID,
				UserName:      user.Name,
				UserEmail:     user.Email,
				Origin:        jwt.FiderClaimsOriginAPI,
				SecurityStamp: user.SecurityStamp,
				Metadata: jwt.Metadata{
					ExpiresAt: jwt.Time(time.Now().Add(365 * 24 * time.Hour)),
				},
			},
			WidgetTokenHash: widgetHash,
		})
		if err != nil {
			return c.Failure(err)
		}

		resp := web.Map{
			"token": token,
			"user":  user,
		}
		if newDeviceSecret != "" {
			// Only returned on a device's first sign-in; the client must store
			// it and present it as device_secret on every later sign-in for
			// this device, since it's never recoverable after this response.
			resp["device_secret"] = newDeviceSecret
		}
		return c.Ok(resp)
	}
}

// WidgetSignOut acknowledges the sign out request; the client discards its token
func WidgetSignOut() web.HandlerFunc {
	return func(c *web.Context) error {
		return c.Ok(web.Map{})
	}
}

func signInByWidgetToken(c *web.Context, input *widgetSignInInput) (*entity.User, string, error) {
	if err := widgettoken.Validate(c, input.Token); err != nil {
		return nil, "", err
	}

	register := &cmd.RegisterDeviceUser{
		DeviceHash:   widgettoken.DeviceHash(input.UDID),
		Name:         input.Name,
		Email:        input.Email,
		DeviceSecret: input.DeviceSecret,
	}
	if err := bus.Dispatch(c, register); err != nil {
		return nil, "", err
	}

	return register.Result, register.NewDeviceSecret, nil
}

func signInByIDToken(c *web.Context, rawIDToken string) (*entity.User, error) {
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

	const provider = "idtoken"

	existing, err := handlers.FindUserByProviderOrEmail(c, provider, claims.UserID, claims.Email)
	if err != nil {
		return nil, err
	}

	// idTokenValidator is configured once for the whole instance (env vars),
	// not per tenant like custom OAuth apps are. Without a further check, any
	// verified id_token from that single issuer/client could self-register on
	// every public tenant sharing the instance. Requiring the tenant to have
	// created at least one widget token — an admin-only, explicit action —
	// scopes self-registration to tenants that opted into the mobile/widget
	// feature themselves. This still shares one global issuer across every
	// opted-in tenant; per-tenant id_token configuration (like custom OAuth
	// apps) would close that gap but is out of scope here.
	if existing == nil {
		hasToken, err := tenantHasActiveWidgetToken(c)
		if err != nil {
			return nil, err
		}
		if !hasToken {
			return nil, errors.New("Mobile sign-in is not enabled for this site")
		}
	}

	if err := handlers.RequireProviderAdmission(c.Tenant(), existing, false); err != nil {
		return nil, err
	}
	return handlers.RegisterUserByProvider(c, c.Tenant(), existing, provider, claims.UserID, claims.Name, claims.Email)
}

func tenantHasActiveWidgetToken(c *web.Context) (bool, error) {
	tokens := &query.ListWidgetTokens{}
	if err := bus.Dispatch(c, tokens); err != nil {
		return false, err
	}
	return len(tokens.Result) > 0, nil
}

type widgetTokenInput struct {
	Label string `json:"label"`
}

// ListWidgetTokens returns all widget tokens of current tenant
func ListWidgetTokens() web.HandlerFunc {
	return func(c *web.Context) error {
		list := &query.ListWidgetTokens{}
		if err := bus.Dispatch(c, list); err != nil {
			return c.Failure(err)
		}
		return c.Ok(web.Map{"tokens": list.Result})
	}
}

// CreateWidgetToken creates a new widget token and returns the raw token once
func CreateWidgetToken() web.HandlerFunc {
	return func(c *web.Context) error {
		input := new(widgetTokenInput)
		if err := c.Bind(input); err != nil {
			return c.Failure(err)
		}

		create := &cmd.CreateWidgetToken{Label: input.Label}
		if err := bus.Dispatch(c, create); err != nil {
			return c.Failure(err)
		}

		return c.Ok(web.Map{
			"id":    create.Result.ID,
			"label": create.Result.Label,
			"token": create.Result.RawToken,
		})
	}
}

// RevokeWidgetToken revokes an existing widget token
func RevokeWidgetToken() web.HandlerFunc {
	return func(c *web.Context) error {
		id, err := c.ParamAsInt("id")
		if err != nil {
			return c.BadRequest(web.Map{})
		}

		if err := bus.Dispatch(c, &cmd.RevokeWidgetToken{TokenID: id}); err != nil {
			return c.Failure(err)
		}
		return c.Ok(web.Map{})
	}
}
