package widgettoken

import (
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/crypto"
	"github.com/getfider/fider/app/pkg/web"
)

// DeviceHash returns the deterministic digest of a raw device identifier. The
// digest is persisted and queried instead of the identifier itself, so a
// database leak does not expose stable device identifiers.
func DeviceHash(udid string) string {
	return crypto.SHA256(udid)
}

// Validate checks that rawToken matches an active widget token of the current
// tenant and marks it as recently used. It returns an error when the token is
// not valid or the usage update fails. In case the last usage bookkeeping
// starts failing, tokens are still validated but last_used_at may go stale.
func Validate(c *web.Context, rawToken string) error {
	hash := entity.HashWidgetToken(rawToken)

	if err := bus.Dispatch(c, &query.GetWidgetTokenByHash{Hash: hash}); err != nil {
		return err
	}

	return bus.Dispatch(c, &cmd.UpdateWidgetTokenLastUsed{Hash: hash})
}