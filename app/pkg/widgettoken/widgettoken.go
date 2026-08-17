package widgettoken

import (
	"regexp"

	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/crypto"
	"github.com/getfider/fider/app/pkg/jwt"
	"github.com/getfider/fider/app/pkg/web"
)

// DeviceHash returns the deterministic digest of a raw device identifier. The
// digest is persisted and queried instead of the identifier itself, so a
// database leak does not expose stable device identifiers.
func DeviceHash(udid string) string {
	return crypto.SHA256(udid)
}

// udidPattern matches a well-formed RFC 4122 UUID (any version).
var udidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

// ValidUDID reports whether udid is a well-formed UUID for X-Widget-UDID /
// the sign-in udid field. The device-secret protection on first registration
// (see registerDeviceUser) only works because a real UUID v4 carries ~122
// bits of entropy, making it infeasible to pre-register/squat a meaningful
// share of the identifier space ahead of a legitimate device. A bare length
// check (previously: any 8-128 char string) doesn't guarantee that — a
// client using short, sequential, or otherwise predictable identifiers would
// leave that assumption false, and an attacker holding only the tenant-wide
// widget token could cheaply pre-claim device_hash values a real device
// might later use, permanently locking it out (see
// docs/MOBILE_FEEDBACK_API.md §4.4).
func ValidUDID(udid string) bool {
	return udidPattern.MatchString(udid)
}

// Validate checks that rawToken matches an active widget token of the current
// tenant and marks it as recently used in the same round trip (an UPDATE ...
// RETURNING), returning app.ErrNotFound when no active token matches the hash.
func Validate(c *web.Context, rawToken string) error {
	hash := entity.HashWidgetToken(rawToken)
	return bus.Dispatch(c, &cmd.UpdateWidgetTokenLastUsed{Hash: hash})
}

// ValidateSession checks that the widget token a device-user JWT was issued
// from is still active. This makes widget-token revocation retroactively
// invalidate already-issued device JWTs. Returns nil when the claims carry no
// widget token (real-user sessions are unaffected).
func ValidateSession(c *web.Context, claims *jwt.WidgetClaims) error {
	if claims.WidgetTokenHash == "" {
		return nil
	}
	return bus.Dispatch(c, &query.GetWidgetTokenByHash{Hash: claims.WidgetTokenHash})
}
