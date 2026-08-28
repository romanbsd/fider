package middlewares

import (
	stderrors "errors"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/metrics"
	"github.com/getfider/fider/app/models/dto"
	"github.com/getfider/fider/app/pkg/firebase"
	"github.com/getfider/fider/app/pkg/log"
	"github.com/getfider/fider/app/pkg/web"
)

const appCheckHeader = "X-Firebase-AppCheck"

type appCheckResult struct {
	claims *firebase.AppCheckClaims
	err    error
}

// AppCheck observes or enforces Firebase App Check for requests already
// authenticated through the mobile API channel. UI cookies and API keys do
// not set MobileApiCtxKey and are unaffected.
func AppCheck() web.MiddlewareFunc {
	return appCheckMiddleware(func(c *web.Context) bool {
		return c.Value(app.MobileApiCtxKey) != nil
	})
}

// WidgetAppCheck observes or enforces App Check on the public mobile sign-in
// and sign-out endpoints. Mount it after WidgetCORS so rejection responses
// remain readable by cross-origin clients and preflight requests can terminate
// first.
func WidgetAppCheck() web.MiddlewareFunc {
	return appCheckMiddleware(func(c *web.Context) bool {
		return c.Request.URL.Path == app.MobileSignInPath || c.Request.URL.Path == app.MobileSignOutPath
	})
}

func appCheckMiddleware(applies func(*web.Context) bool) web.MiddlewareFunc {
	if !firebase.Enabled() {
		return func(next web.HandlerFunc) web.HandlerFunc { return next }
	}
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(c *web.Context) error {
			if !applies(c) {
				return next(c)
			}

			result := verifyAppCheck(c)
			c.Set(app.AppCheckCtxKey, result)
			if result.err != nil && firebase.Mode() == firebase.ModeEnforce {
				return c.UnauthorizedJSON()
			}
			return next(c)
		}
	}
}

// RequireAppCheck returns verified claims for security-sensitive flows such as
// anonymous provisioning. It fails closed in every mode, including monitor.
func RequireAppCheck(c *web.Context) (*firebase.AppCheckClaims, error) {
	if result, ok := c.Value(app.AppCheckCtxKey).(*appCheckResult); ok {
		return result.claims, result.err
	}
	result := verifyAppCheck(c)
	c.Set(app.AppCheckCtxKey, result)
	return result.claims, result.err
}

func verifyAppCheck(c *web.Context) *appCheckResult {
	claims, err := firebase.VerifyAppCheck(c, c.Request.GetHeader(appCheckHeader))
	result := "valid"
	if err != nil {
		result = appCheckErrorResult(err)
		log.Warnf(c, "Firebase App Check verification failed (@{Result})", dto.Props{"Result": result})
	}
	metrics.AppCheckVerifications.WithLabelValues(firebase.Mode(), result).Inc()
	return &appCheckResult{claims: claims, err: err}
}

func appCheckErrorResult(err error) string {
	switch {
	case stderrors.Is(err, firebase.ErrMissingToken):
		return "missing"
	case stderrors.Is(err, firebase.ErrDisallowedApp):
		return "disallowed_app"
	case stderrors.Is(err, firebase.ErrDisabled):
		return "disabled"
	default:
		return "invalid"
	}
}
