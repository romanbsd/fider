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
			user       *entity.User
			widgetHash string
		)
		if input.IDToken != "" {
			u, err := signInByIDToken(c, input.IDToken)
			if err != nil {
				return c.HandleValidation(validate.Failed(err.Error()))
			}
			user = u
		} else {
			if input.Token == "" || input.UDID == "" {
				return c.BadRequest(web.Map{
					"errors": web.Map{"token": "token and udid are required"},
				})
			}
			u, err := signInByWidgetToken(c, input)
			if err != nil {
				return c.Unauthorized()
			}
			user = u
			widgetHash = entity.HashWidgetToken(input.Token)
		}

		token, err := jwt.Encode(jwt.FiderClaims{
			UserID:          user.ID,
			UserName:        user.Name,
			UserEmail:       user.Email,
			Origin:          jwt.FiderClaimsOriginAPI,
			SecurityStamp:   user.SecurityStamp,
			WidgetTokenHash: widgetHash,
			Metadata: jwt.Metadata{
				ExpiresAt: jwt.Time(time.Now().Add(365 * 24 * time.Hour)),
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

// WidgetSignOut acknowledges the sign out request; the client discards its token
func WidgetSignOut() web.HandlerFunc {
	return func(c *web.Context) error {
		return c.Ok(web.Map{})
	}
}

func signInByWidgetToken(c *web.Context, input *widgetSignInInput) (*entity.User, error) {
	if err := widgettoken.Validate(c, input.Token); err != nil {
		return nil, err
	}

	register := &cmd.RegisterDeviceUser{
		DeviceHash: widgettoken.DeviceHash(input.UDID),
		Name:       input.Name,
		Email:      input.Email,
	}
	if err := bus.Dispatch(c, register); err != nil {
		return nil, err
	}

	return register.Result, nil
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

	// Private tenants reject unknown identities unless admission was granted
	// through the normal invite flow. Existing users always sign in.
	if c.Tenant().IsPrivate {
		existing, err := handlers.FindUserByProviderOrEmail(c, provider, claims.UserID, claims.Email)
		if err != nil {
			return nil, err
		}
		if existing == nil {
			return nil, errors.New("You are not invited to this site")
		}
		return handlers.RegisterUserByProvider(c, c.Tenant(), existing, provider, claims.UserID, claims.Name, claims.Email)
	}

	return handlers.RegisterUserByProvider(c, c.Tenant(), nil, provider, claims.UserID, claims.Name, claims.Email)
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