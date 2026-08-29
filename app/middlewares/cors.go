package middlewares

import (
	"net/http"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/pkg/web"
)

// CORS adds Cross-Origin Resource Sharing response headers
func CORS() web.MiddlewareFunc {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(c *web.Context) error {
			c.Response.Header().Set("Access-Control-Allow-Origin", "*")
			c.Response.Header().Set("Access-Control-Allow-Methods", "GET")
			return next(c)
		}
	}
}

// WidgetCORS adds Cross-Origin Resource Sharing headers required by mobile
// clients: both the /widget/* sign-in routes and the mobile-JWT-authenticated
// /api/v1/* member surface it calls afterwards (see
// docs/MOBILE_FEEDBACK_API.md).
func WidgetCORS() web.MiddlewareFunc {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(c *web.Context) error {
			c.Response.Header().Set("Access-Control-Allow-Origin", "*")
			c.Response.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Response.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Firebase-AppCheck")
			c.Response.Header().Set("Access-Control-Max-Age", "86400")

			if c.Request.Method == http.MethodOptions {
				return c.NoContent(http.StatusOK)
			}
			return next(c)
		}
	}
}

// MobileApiCORS is WidgetCORS scoped to mobile-API sessions only: requests
// authenticated through an API-origin JWT issued by /widget/signin. It must run
// after authentication (the User middleware marks such sessions via
// app.MobileApiCtxKey). Unlike WidgetCORS (used for the public, unauthenticated
// /api/v1/* surface and the /widget/* sign-in routes), this guards the
// authenticated member API, which real collaborators and admins also call
// through same-origin UI sessions. Wildcard CORS on that surface would let any
// origin read responses acted on with the power of whatever session it holds,
// so only widen it for mobile-API sessions and leave UI-cookie sessions
// same-origin-only.
func MobileApiCORS() web.MiddlewareFunc {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(c *web.Context) error {
			if c.Value(app.MobileApiCtxKey) != nil {
				c.Response.Header().Set("Access-Control-Allow-Origin", "*")
				c.Response.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Firebase-AppCheck")
			}
			return next(c)
		}
	}
}
