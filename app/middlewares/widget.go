package middlewares

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/getfider/fider/app"
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

			// The sign-in endpoint is the only unauthenticated widget route (this
			// middleware runs before WidgetAuth, so c.IsAuthenticated() is never
			// true here yet); keep a per-client limit on top of the tenant ceiling
			// so one client cannot starve it.
			if c.Request.URL.Path == "/widget/signin" {
				clientKey := fmt.Sprintf("%d:%s", tenant.ID, clientIP(c.Request.RemoteAddr(), c.Request.GetHeader("X-Forwarded-For")))
				if !widgetClientRateLimiter.Allow(clientKey) {
					return c.JSON(http.StatusTooManyRequests, web.Map{"error": "Too Many Requests"})
				}
			}

			return next(c)
		}
	}
}

// clientIP returns the caller address. `X-Forwarded-For` is honoured only when
// the direct socket peer is a private/loopback address (i.e. our own reverse
// proxy); otherwise an end client could spoof it. Falls back to the peer address
// so per-client buckets stay distinct instead of grouping every caller under the
// proxy address.
func clientIP(remoteAddr, forwardedFor string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	if forwardedFor != "" && isTrustedProxy(host) {
		if first, _, ok := strings.Cut(forwardedFor, ","); ok {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(forwardedFor)
	}

	return host
}

func isTrustedProxy(peer string) bool {
	ip := net.ParseIP(peer)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
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

	if byDevice.Result.Status == enum.UserBlocked {
		return nil, app.ErrNotFound
	}

	return byDevice.Result, nil
}

func authenticateMobile(c *web.Context, token string, next web.HandlerFunc) error {
	claims, err := jwt.DecodeFiderClaims(token)
	if err != nil || claims.Origin != jwt.FiderClaimsOriginAPI {
		return c.Unauthorized()
	}

	user, ok := resolveAPIClaimsUser(c, claims)
	if !ok {
		return c.Unauthorized()
	}

	c.SetUser(user)
	return next(c)
}