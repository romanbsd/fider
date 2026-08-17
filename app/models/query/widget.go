package query

import (
	"github.com/getfider/fider/app/models/entity"
)

// ListWidgetTokens lists all non-revoked widget tokens of current tenant
type ListWidgetTokens struct {
	Result []*entity.WidgetToken
}

// GetWidgetTokenByHash finds an active (non-revoked) widget token by its hash
type GetWidgetTokenByHash struct {
	Hash   string
	Result *entity.WidgetToken
}

// GetUserByDeviceHash finds a device user by its device hash within current tenant
type GetUserByDeviceHash struct {
	DeviceHash string
	Result     *entity.User
}