package widgettoken

import (
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
