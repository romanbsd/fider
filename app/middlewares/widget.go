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
	// widgetRateLimiter caps the total widget traffic per tenant. It is separate
	// from widgetSigninLimiter below so a single abusive client cannot exhaust
	// the tenant's budget and starve every other widget client for the window.
	widgetRateLimiter = ratelimit.New(env.Config.Widget.RateLimit, time.Minute)
	// widgetSigninLimiter throttles /widget/signin per client IP. Its per-client
	// ceiling is a fraction of the tenant ceiling: with two buckets at the same
	// limit, one client burning its own budget would still exhaust the shared
	// tenant bucket, so the per-client limit only adds isolation when it binds
	// first.
	widgetSigninLimiter = ratelimit.New(max(1, env.Config.Widget.RateLimit/4), time.Minute)
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

			// The sign-in endpoint is the only unauthenticated widget route (this
			// middleware runs before WidgetAuth, so c.IsAuthenticated() is never
			// true here yet). Its per-client check runs before the tenant-wide one
			// so a client that has exhausted its own budget is rejected without
			// consuming the shared tenant capacity that every other widget client
			// depends on.
			if c.Request.URL.Path == app.WidgetSignInPath {
				clientKey := fmt.Sprintf("signin:%d:%s", tenant.ID, clientIP(c.Request.RemoteAddr(), c.Request.GetHeader("X-Forwarded-For")))
				if !widgetSigninLimiter.Allow(clientKey) {
					return c.JSON(http.StatusTooManyRequests, web.Map{"error": "Too Many Requests"})
				}
			}

			if !widgetRateLimiter.Allow(fmt.Sprintf("tenant:%d", tenant.ID)) {
				return c.JSON(http.StatusTooManyRequests, web.Map{"error": "Too Many Requests"})
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
			if c.Request.URL.Path == app.WidgetSignInPath {
				return next(c)
			}

			tenant := c.Tenant()
			if tenant == nil {
				return c.Unauthorized()
			}

			if token, err := web.BearerToken(c.Request.GetHeader("Authorization")); err == nil {
				return authenticateMobile(c, token, next)
			}

			widgetToken, udid, deviceSecret := widgetCredentials(c)
			if widgetToken != "" && widgettoken.ValidUDID(udid) {
				user, err := authenticateWidget(c, widgetToken, udid, deviceSecret)
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

func widgetCredentials(c *web.Context) (token, udid, deviceSecret string) {
	return c.Request.GetHeader("X-Widget-Token"), c.Request.GetHeader("X-Widget-UDID"), c.Request.GetHeader("X-Widget-Device-Secret")
}

func authenticateWidget(c *web.Context, rawToken, udid, deviceSecret string) (*entity.User, error) {
	if err := widgettoken.Validate(c, rawToken); err != nil {
		return nil, err
	}

	byDevice := &query.GetUserByDeviceHash{DeviceHash: widgettoken.DeviceHash(udid)}
	if err := bus.Dispatch(c, byDevice); err != nil {
		return nil, err
	}

	// The tenant-wide widget token alone identifies the tenant, not the
	// caller: every device shares it. Require proof of possession of the
	// secret issued to this specific device at its first sign-in, so a token
	// holder can't authenticate as any other known device_hash.
	if byDevice.Result.DeviceSecretHash == "" || deviceSecret == "" ||
		entity.HashDeviceSecret(deviceSecret) != byDevice.Result.DeviceSecretHash {
		return nil, app.ErrDeviceSecretMismatch
	}

	if byDevice.Result.Status == enum.UserBlocked {
		return nil, app.ErrNotFound
	}

	return byDevice.Result, nil
}

func authenticateMobile(c *web.Context, token string, next web.HandlerFunc) error {
	claims, err := jwt.DecodeWidgetClaims(token)
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
