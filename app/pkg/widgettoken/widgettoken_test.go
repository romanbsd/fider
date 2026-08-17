package widgettoken_test

import (
	"context"
	"testing"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/query"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/mock"
	"github.com/getfider/fider/app/pkg/web"
	"github.com/getfider/fider/app/pkg/widgettoken"
)

func TestValidateToken_Valid(t *testing.T) {
	RegisterT(t)

	touched := false
	bus.AddHandler(func(ctx context.Context, q *query.GetWidgetTokenByHash) error {
		Expect(q.Hash).Equals(entity.HashWidgetToken("raw-token"))
		q.Result = &entity.WidgetToken{ID: 1, Hash: q.Hash}
		return nil
	})
	bus.AddHandler(func(ctx context.Context, c *cmd.UpdateWidgetTokenLastUsed) error {
		touched = true
		return nil
	})

	server := mock.NewServer()
	server.OnTenant(mock.DemoTenant)
	var validateErr error
	_, _ = server.Execute(func(c *web.Context) error {
		validateErr = widgettoken.Validate(c, "raw-token")
		return nil
	})

	Expect(validateErr).IsNil()
	Expect(touched).IsTrue()
}

func TestValidateToken_Invalid(t *testing.T) {
	RegisterT(t)

	bus.AddHandler(func(ctx context.Context, q *query.GetWidgetTokenByHash) error {
		return app.ErrNotFound
	})

	server := mock.NewServer()
	server.OnTenant(mock.DemoTenant)
	var validateErr error
	_, _ = server.Execute(func(c *web.Context) error {
		validateErr = widgettoken.Validate(c, "bad-token")
		return nil
	})

	Expect(validateErr).IsNotNil()
}