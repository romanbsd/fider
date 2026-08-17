package middlewares

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/pkg/jwt"
	"github.com/getfider/fider/app/pkg/ratelimit"
	"github.com/getfider/fider/app/pkg/web"
	"github.com/getfider/fider/app/pkg/widgettoken"
)

var (
	// widgetRateLimiter is the per-tenant ceiling for all widget traffic
	widgetRateLimiter = ratelimit.New(env.Config.Widget.RateLimit, time.Minute)
	// widgetClientRateLimiter throttles unauthenticated widget requests per
	// client so a single client cannot exhaust a tenant's budget
	widgetClientRateLimiter = ratelimit.New(env.Config.Widget.RateLimit, time.Minute)
)

// WidgetRateLimit throttles widget requests per tenant. Unauthenticated requests
// (the public sign-in) are additionally keyed by client so one client cannot
// starve the whole tenant for the duration of the window.
func WidgetRateLimit() web.MiddlewareFunc {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(c *web.Context) error {
			tenant := c.Tenant()
			if tenant == nil {
				return next(c)
			}

			if !widgetRateLimiter.Allow(fmt.Sprintf("%d", tenant.ID)) {
				return c.JSON(http.StatusTooManyRequests, web.Map{"error": "Too Many Requests"})
			}

			// Requests that are not yet attributed to a user (today: the sign-in
			// endpoint) keep a per-client limit on top of the tenant ceiling.
			if !c.IsAuthenticated() {
				clientKey := fmt.Sprintf("%d:%s", tenant.ID, clientIP(c.Request.RemoteAddr()))
				if !widgetClientRateLimiter.Allow(clientKey) {
					return c.JSON(http.StatusTooManyRequests, web.Map{"error": "Too Many Requests"})
				}
			}

			return next(c)
		}
	}
}

func clientIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// WidgetAuth authenticates requests coming from the feedback widget (a tenant
// widget token + device hash) or from mobile clients (a Fider Bearer JWT).
func WidgetAuth() web.MiddlewareFunc {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(c *web.Context) error {
			// The sign-in endpoint validates the widget token itself so that the
			// first request does not require an existing session.
			if c.Request.URL.Path == "/widget/signin" {
				return next(c)
			}

			tenant := c.Tenant()
			if tenant == nil {
				return c.Unauthorized()
			}

			if token, err := web.BearerToken(c.Request.GetHeader("Authorization")); err == nil {
				return authenticateMobile(c, token, next)
			}

			widgetToken, udid := widgetCredentials(c)
			if widgetToken != "" && udid != "" {
				user, err := authenticateWidget(c, widgetToken, udid)
				if err != nil {
					return c.Unauthorized()
				}
				c.SetUser(user)
				return next(c)
			}

			return c.Unauthorized()
		}
	}
}

func widgetCredentials(c *web.Context) (token, udid string) {
	return c.Request.GetHeader("X-Widget-Token"), c.Request.GetHeader("X-Widget-UDID")
}

func authenticateWidget(c *web.Context, rawToken, udid string) (*entity.User, error) {
	if err := widgettoken.Validate(c, rawToken); err != nil {
		return nil, err
	}

	byDevice := &query.GetUserByDeviceHash{DeviceHash: widgettoken.DeviceHash(udid)}
	if err := bus.Dispatch(c, byDevice); err != nil {
		return nil, err
	}

	return byDevice.Result, nil
}

func authenticateMobile(c *web.Context, token string, next web.HandlerFunc) error {
	claims, err := jwt.DecodeFiderClaims(token)
	if err != nil {
		return c.Unauthorized()
	}

	user, err := findUserByClaims(c, claims)
	if err != nil || user == nil {
		return c.Unauthorized()
	}
	if claims.SecurityStamp != "" && user.SecurityStamp != claims.SecurityStamp {
		return c.Unauthorized()
	}
	if user.Status == enum.UserBlocked {
		return c.Unauthorized()
	}

	c.SetUser(user)
	return next(c)
}