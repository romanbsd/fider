package widgettoken

import (
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/web"
)

// Validate checks that rawToken matches an active widget token of the current
// tenant and marks it as recently used. It returns an error when the token is
// not valid.
func Validate(c *web.Context, rawToken string) error {
	hash := entity.HashWidgetToken(rawToken)

	if err := bus.Dispatch(c, &query.GetWidgetTokenByHash{Hash: hash}); err != nil {
		return err
	}

	_ = bus.Dispatch(c, &cmd.UpdateWidgetTokenLastUsed{Hash: hash})
	return nil
}