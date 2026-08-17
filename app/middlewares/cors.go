package middlewares

import (
	"net/http"

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

// WidgetCORS adds Cross-Origin Resource Sharing headers required by the
// feedback widget (embedded on arbitrary customer sites) and mobile clients:
// both the /widget/* sign-in routes and the widget/mobile-JWT-authenticated
// /api/v1/* member surface it calls afterwards (see
// docs/MOBILE_FEEDBACK_API.md).
func WidgetCORS() web.MiddlewareFunc {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(c *web.Context) error {
			c.Response.Header().Set("Access-Control-Allow-Origin", "*")
			c.Response.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Response.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Widget-Token, X-Widget-UDID")
			c.Response.Header().Set("Access-Control-Max-Age", "86400")

			if c.Request.Method == http.MethodOptions {
				return c.NoContent(http.StatusOK)
			}
			return next(c)
		}
	}
}
