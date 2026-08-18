package middlewares

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/bus"

	"github.com/getfider/fider/app/pkg/validate"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/jwt"
	"github.com/getfider/fider/app/pkg/web"
	webutil "github.com/getfider/fider/app/pkg/web/util"
)

// User gets JWT Auth token from cookie and insert into context
func User() web.MiddlewareFunc {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(c *web.Context) error {
			var (
				token            string
				user             *entity.User
				fromSignUpCookie bool
				isMobileJWT      bool
			)

			cookie, err := c.Request.Cookie(web.CookieAuthName)
			if err == nil {
				token = cookie.Value
			} else {
				// The signup-transfer cookie is domain-wide, so it reaches every tenant
				// subdomain. We do NOT promote it to a durable host-only auth cookie here:
				// that only happens later, and only once we have confirmed the token's user
				// actually belongs to the tenant selected by the current host.
				token = webutil.GetSignUpAuthCookie(c)
				fromSignUpCookie = token != ""
			}

			if token != "" {
				// Decoded as FiderClaims; the Origin claim is used below to
				// reject mobile-API credentials when they are presented as an
				// auth cookie instead of a bearer token.
				claims, err := jwt.DecodeFiderClaims(token)
				if err != nil {
					c.RemoveCookie(web.CookieAuthName)
					return next(c)
				}

				// A widget/mobile JWT (Origin=api) is a bearer-only credential
				// for the /widget/* and /api/v1/* API surface, never a session
				// cookie. Without this check a token minted by /widget/signin
				// (embedded on arbitrary customer sites) could be replayed as the
				// auth cookie and open a full browser UI session for its user for
				// the token's whole 365-day lifetime. UI sessions are always
				// minted with Origin=ui.
				if claims.Origin == jwt.FiderClaimsOriginAPI {
					// Remove the cookie, but do not stop here: the same request
					// may also carry a valid Authorization header (e.g. a client
					// with shared webview storage), which must still be able to
					// authenticate through the bearer path below. The cookie
					// token's own claims are never used to resolve a user.
					c.RemoveCookie(web.CookieAuthName)
					token = ""
					fromSignUpCookie = false
				} else {
					user, err = findUserByClaims(c, claims)
					if err != nil {
						return err
					}
					if user == nil {
						c.RemoveCookie(web.CookieAuthName)
						return next(c)
					}

					// Security stamp check: if the JWT contains a stamp (new tokens only),
					// validate it against the current DB stamp. A mismatch means the user's
					// security-relevant data has changed (e.g. role changed, account blocked,
					// or OAuth allowed-roles updated) and they must re-authenticate so that
					// access controls are re-evaluated.
					if claims.SecurityStamp != "" && claims.SecurityStamp != user.SecurityStamp {
						c.RemoveCookie(web.CookieAuthName)
						if c.IsAjax() {
							return c.JSON(401, web.Map{})
						}
						redirectTarget := c.Request.URL.RequestURI()
						if redirectTarget != "" &&
							redirectTarget != "/" &&
							!strings.HasPrefix(redirectTarget, "/signin") &&
							!strings.HasPrefix(redirectTarget, "/signout") {
							return c.Redirect("/signin?redirect=" + url.QueryEscape(redirectTarget))
						}
						return c.Redirect("/signin")
					}
				}
			}

			// The bearer path runs when there is no usable session cookie —
			// including after an API-origin cookie was just discarded above — so
			// a request presenting both a stale widget cookie and a valid
			// Authorization header still authenticates.
			if token == "" && c.Request.IsAPI() {
				if bearer, err := web.BearerToken(c.Request.GetHeader("Authorization")); err == nil {
					resolved, mobileJWT, handled, err := resolveBearerUser(c, bearer)
					if handled {
						return err
					}
					user = resolved
					isMobileJWT = mobileJWT
				}
			}

			if user != nil && c.Tenant() != nil && user.Tenant.ID == c.Tenant().ID {
				// blocked users are unable to sign in
				if user.Status == enum.UserBlocked {
					c.RemoveCookie(web.CookieAuthName)
					return c.Unauthorized()
				}

				// Mark requests authenticated through the mobile API channel
				// (an API-origin JWT issued by /widget/signin). Middleware that
				// runs later (e.g. CORS) uses this to permit cross-origin
				// clients without widening the same-origin-only posture of
				// ordinary UI-cookie sessions. Only set once the user is
				// confirmed to belong to the current tenant, and never for
				// API-key credentials.
				if isMobileJWT {
					c.Set(app.MobileApiCtxKey, true)
				}

				// Only now that the user is confirmed to belong to the current tenant do we
				// promote a signup-transfer cookie into a durable host-only auth cookie.
				// This is deliberately skipped on any other tenant, so the domain-wide
				// signup token cannot become a normal session on an unrelated subdomain.
				if fromSignUpCookie {
					webutil.AddAuthTokenCookie(c, token)
				}

				c.SetUser(user)
			}

			return next(c)
		}
	}
}

// findUserByClaims loads the user referenced by Fider claims, scoped to the tenant
// selected by the request host. A user ID that belongs to a different tenant must
// resolve to "no user" so a token cannot be replayed across tenant boundaries.
// Returns nil, nil when there is no such user.
func findUserByClaims(c *web.Context, claims *jwt.FiderClaims) (*entity.User, error) {
	tenantID := 0
	if c.Tenant() != nil {
		tenantID = c.Tenant().ID
	}

	byID := &query.GetUserByID{UserID: claims.UserID, TenantID: tenantID}
	if err := bus.Dispatch(c, byID); err != nil {
		if errors.Cause(err) == app.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	return byID.Result, nil
}

// resolveBearerUser authenticates an API request's bearer token, accepting
// either a mobile JWT (an API-origin JWT issued by /widget/signin) or a
// collaborator API key (optionally impersonating another user via
// X-Fider-UserID). mobileJWT reports whether the caller was authenticated
// through the JWT path (API-key credentials are not mobile sessions).
// handled reports whether the caller must stop and return err immediately
// without calling next() — err may be nil in that case, since a response can
// already have been written successfully (c.JSON/c.HandleValidation return
// nil on success).
func resolveBearerUser(c *web.Context, bearer string) (*entity.User, bool, bool, error) {
	if claims, err := jwt.DecodeFiderClaims(bearer); err == nil && claims.Origin == jwt.FiderClaimsOriginAPI {
		user, ok := resolveAPIClaimsUser(c, claims)
		if !ok {
			return nil, false, true, c.JSON(401, web.Map{})
		}
		return user, true, false, nil
	}
	user, handled, err := resolveAPIKeyUser(c, bearer)
	return user, false, handled, err
}

func resolveAPIKeyUser(c *web.Context, apiKey string) (*entity.User, bool, error) {
	getUserByAPIKey := &query.GetUserByAPIKey{APIKey: apiKey}
	if err := bus.Dispatch(c, getUserByAPIKey); err != nil {
		if errors.Cause(err) == app.ErrNotFound {
			return nil, true, c.HandleValidation(validate.Failed("API Key is invalid"))
		}
		return nil, true, err
	}
	user := getUserByAPIKey.Result

	if !user.IsCollaborator() {
		return nil, true, c.HandleValidation(validate.Failed("API Key is invalid"))
	}

	impersonateUserIDStr := c.Request.GetHeader("X-Fider-UserID")
	if impersonateUserIDStr == "" {
		return user, false, nil
	}
	return resolveImpersonatedUser(c, user, impersonateUserIDStr)
}

func resolveImpersonatedUser(c *web.Context, user *entity.User, impersonateUserIDStr string) (*entity.User, bool, error) {
	if !user.IsAdministrator() {
		return nil, true, c.HandleValidation(validate.Failed("Only Administrators are allowed to impersonate another user"))
	}
	impersonateUserID, err := strconv.Atoi(impersonateUserIDStr)
	if err != nil {
		return nil, true, c.HandleValidation(validate.Failed(fmt.Sprintf("User not found for given impersonate UserID '%s'", impersonateUserIDStr)))
	}
	userByImpersonateID := &query.GetUserByID{UserID: impersonateUserID, TenantID: user.Tenant.ID}
	if err := bus.Dispatch(c, userByImpersonateID); err != nil {
		if errors.Cause(err) == app.ErrNotFound {
			return nil, true, c.HandleValidation(validate.Failed(fmt.Sprintf("User not found for given impersonate UserID '%s'", impersonateUserIDStr)))
		}
		return nil, true, err
	}
	return userByImpersonateID.Result, false, nil
}

// resolveAPIClaimsUser validates a Fider JWT issued through the mobile API
// against the current tenant: the user must exist in the tenant, its security
// stamp must match, and it must not be blocked. Returns the tenant-scoped user,
// or (nil, false) when the token is no longer usable.
func resolveAPIClaimsUser(c *web.Context, claims *jwt.FiderClaims) (*entity.User, bool) {
	user, err := findUserByClaims(c, claims)
	if err != nil || user == nil {
		return nil, false
	}
	if claims.SecurityStamp != "" && user.SecurityStamp != claims.SecurityStamp {
		return nil, false
	}
	if user.Status == enum.UserBlocked {
		return nil, false
	}
	return user, true
}
